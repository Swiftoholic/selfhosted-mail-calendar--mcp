"""Fresh no-provider startup probe. Run only with disposable private tmpfs mounts."""
import http.client
import json
import os
import subprocess
import sys
import time


def main():
    command = [sys.executable, '-m', 'mcp_bridge.main']
    for category, env in (
        ('missing_origin', {key: value for key, value in os.environ.items() if key != 'MCP_PUBLIC_ORIGIN'}),
        ('insecure_oauth_mode', dict(os.environ, AUTHLIB_INSECURE_TRANSPORT='1')),
    ):
        result = subprocess.run(command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        if result.returncode == 0:
            raise SystemExit('Runtime failed closed-startup probe: ' + category)
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise SystemExit('Fresh configured runtime did not start')
            try:
                connection = http.client.HTTPConnection('127.0.0.1', 8082, timeout=1)
                connection.connect()
                connection.close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise SystemExit('Runtime startup timeout')
        from mcp_bridge.config import HOST, ORIGIN
        cases = [
            ('/.well-known/oauth-authorization-server', {'Host': HOST, 'X-Forwarded-Proto': 'https'}, 200),
            ('/.well-known/oauth-protected-resource/mcp', {'Host': HOST, 'X-Forwarded-Proto': 'https'}, 200),
            ('/mcp', {'Host': HOST, 'X-Forwarded-Proto': 'https'}, 401),
            ('/accounts/status', {'Host': HOST, 'X-Forwarded-Proto': 'https'}, 401),
            ('/auth/status', {'Host': 'wrong.example.test', 'X-Forwarded-Proto': 'https'}, 403),
        ]
        statuses = []
        for route, headers, expected in cases:
            connection = http.client.HTTPConnection('127.0.0.1', 8082, timeout=3)
            try:
                connection.request('GET', route, headers=headers)
                response = connection.getresponse()
                raw = response.read(32769)
                if response.status != expected or len(raw) > 32768:
                    print(json.dumps({'failed_http_probe': route, 'expected_status': expected,
                                      'actual_status': response.status, 'body_within_bound': len(raw) <= 32768}))
                    raise SystemExit('Runtime HTTP boundary probe failed')
                if route.endswith('oauth-authorization-server') and json.loads(raw).get('issuer') != ORIGIN:
                    raise SystemExit('Runtime issuer binding probe failed')
                statuses.append({'route': route, 'status': response.status})
            finally:
                connection.close()
        print(json.dumps({'runtime_probes': 7, 'failures': 0, 'fresh_disposable_identity': True,
                          'provider_accounts_mounted': False, 'external_requests': False,
                          'http_statuses': statuses}))
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


if __name__ == '__main__':
    main()
