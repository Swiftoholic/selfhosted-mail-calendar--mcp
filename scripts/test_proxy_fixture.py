"""Private namespace proxy fixture; never opens a host port or a provider."""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import resource
import ssl
import time


def limits():
    os.sched_setaffinity(0, {max(os.sched_getaffinity(0))})
    resource.setrlimit(resource.RLIMIT_AS, (64 * 1024**2, 64 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))


class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        headers = {key.lower(): value for key, value in self.headers.items()}
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        raw = json.dumps({'synthetic_backend_reached': True, 'method': self.command,
                          'path': self.path, 'headers': headers,
                          'body_matches': body in (b'', b'{}')}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_POST = do_GET

    def log_message(self, *_):
        pass


def request(context, host, path, method='GET', body=None):
    # Connect to loopback while verifying the configured TLS server name.
    connection = http.client.HTTPConnection('127.0.0.1', 8443, timeout=3)
    connection.connect()
    try:
        connection.sock = context.wrap_socket(connection.sock, server_hostname='mcp.example.test')
        connection.request(method, path, body=body, headers={
            'Host': host, 'Authorization': 'synthetic-auth', 'Cookie': 'synthetic-cookie',
            'Origin': 'https://mcp.example.test', 'X-Forwarded-Proto': 'http',
            'X-Forwarded-Host': 'untrusted.example.test', 'X-Forwarded-For': '192.0.2.1',
            'X-Real-IP': '192.0.2.2', 'Forwarded': 'for=192.0.2.3',
            'X-Synthetic-Consent': 'untrusted',
        })
        response = connection.getresponse()
        return response.status, response.read(32769)
    finally:
        connection.close()


def probe(host):
    context = ssl.create_default_context(cafile='/run/tls/fullchain.pem')
    for _ in range(100):
        try:
            if request(context, host, '/fixture-not-allowed')[0] == 404:
                break
        except (OSError, http.client.HTTPException):
            time.sleep(0.1)
    else:
        raise RuntimeError('synthetic_proxy_startup_timeout')
    positive = [
        ('POST', '/accounts/manage/check'), ('POST', '/accounts/manage/save'),
        ('POST', '/accounts/manage/retest'), ('POST', '/accounts/manage/remove'),
        ('POST', '/accounts/calendars/list'), ('POST', '/accounts/contacts/list'),
        ('GET', '/accounts/status'), ('POST', '/accounts/check'), ('POST', '/accounts/save'),
        ('POST', '/accounts/calendars/inspect'), ('POST', '/accounts/contacts/save'),
        ('GET', '/auth/status'), ('POST', '/mcp'), ('GET', '/login'),
        ('GET', '/static/accounts.js'), ('POST', '/oauth/token'),
        ('GET', '/.well-known/oauth-authorization-server'),
        ('GET', '/.well-known/oauth-protected-resource/mcp'),
    ]
    for method, path in positive:
        status, raw = request(context, host, path, method, b'{}' if method == 'POST' else None)
        if status != 200:
            raise RuntimeError('synthetic_allowed_route_rejected: ' + path)
        result = json.loads(raw)
        headers = result['headers']
        if not (result['synthetic_backend_reached'] and result['method'] == method
                and result['path'] == path and result['body_matches']
                and headers.get('host') == host and headers.get('x-forwarded-proto') == 'https'
                and headers.get('authorization') == 'synthetic-auth'
                and headers.get('cookie') == 'synthetic-cookie'
                and headers.get('origin') == 'https://mcp.example.test'):
            raise RuntimeError('synthetic_proxy_forwarding_changed')
        for key in ('x-forwarded-host', 'x-forwarded-for', 'x-real-ip', 'forwarded', 'x-synthetic-consent'):
            if key in headers:
                raise RuntimeError('synthetic_untrusted_header_forwarded')
    negative = [
        ('GET', '/accounts/manage/unknown', 404), ('POST', '/accounts/manage/save/extra', 404),
        ('GET', '/accounts/calendars/list/', 404), ('GET', '/accounts/contacts/list/extra', 404),
        ('GET', '/Accounts/status', 404), ('GET', '/admin', 404),
        ('DELETE', '/accounts/manage/remove', 405),
    ]
    for method, path, expected in negative:
        status, raw = request(context, host, path, method)
        if status != expected or b'synthetic_backend_reached' in raw:
            raise RuntimeError('synthetic_forbidden_route_accepted')
    # An unmatched Host selects nginx's default server (404), whereas a wrong
    # port on the matching server name reaches its explicit Host guard (421).
    for path in ('/accounts/status', '/'):
        status, raw = request(context, 'wrong.example.test', path)
        if status not in (404, 421) or b'synthetic_backend_reached' in raw:
            raise RuntimeError('synthetic_wrong_host_accepted')
    wrong_port_host = 'mcp.example.test:8443' if host == 'mcp.example.test' else 'mcp.example.test'
    status, raw = request(context, wrong_port_host, '/accounts/status')
    if status != 421 or b'synthetic_backend_reached' in raw:
        raise RuntimeError('synthetic_wrong_host_port_accepted')
    connection = http.client.HTTPConnection('127.0.0.1', 8443, timeout=3)
    connection.connect()
    try:
        # Keep CA validation; suppress only the fixture client's hostname error
        # so a server accepting wrong SNI cannot masquerade as server rejection.
        rejection_context = ssl.create_default_context(cafile='/run/tls/fullchain.pem')
        rejection_context.check_hostname = False
        try:
            connection.sock = rejection_context.wrap_socket(connection.sock, server_hostname='wrong.example.test')
        except ssl.SSLError:
            pass
        else:
            raise RuntimeError('synthetic_wrong_sni_accepted')
    finally:
        connection.close()
    print(json.dumps({'proxy_http_probes': len(positive) + len(negative) + 4,
                      'allowed_routes': len(positive), 'negative_boundaries': len(negative) + 4,
                      'host_variant': host, 'failures': 0, 'tls_verified': True,
                      'network_namespace': 'none', 'published_ports': False}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('serve', 'probe'))
    parser.add_argument('--host', default='mcp.example.test')
    args = parser.parse_args()
    limits()
    if args.action == 'serve':
        HTTPServer(('127.0.0.1', 8082), Backend).serve_forever()
    else:
        probe(args.host)


if __name__ == '__main__':
    main()
