"""TLS transports which resolve once and connect only to validated public IPs.

Configuration selects DNS names; requests cannot select hosts, disable TLS, or
use an HTTP proxy. DNS answers are checked again for every new connection.
"""
import concurrent.futures
import http.client
import imaplib
import ipaddress
import re
import smtplib
import socket
import ssl
import threading
import time


class NetworkError(OSError):
    def __init__(self):
        super().__init__('provider_network_unavailable')


def hostname(value):
    if (not isinstance(value, str) or not 4 <= len(value) <= 253 or
            value != value.lower() or value.endswith('.') or
            not re.fullmatch(r'[a-z0-9.-]+', value)):
        raise ValueError('invalid_provider_host')
    labels = value.split('.')
    if (len(labels) < 2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in labels) or
            labels[-1].isdigit() or labels[-1] in ('local', 'localhost', 'internal', 'home', 'lan', 'invalid')):
        raise ValueError('invalid_provider_host')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('invalid_provider_host')


def tls_context():
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def public_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise NetworkError() from None
    if (not address.is_global or address.is_multicast or address.is_reserved or
            address.is_loopback or address.is_link_local or address.is_unspecified or
            address == ipaddress.ip_address('168.63.129.16')):
        raise NetworkError()
    if isinstance(address, ipaddress.IPv6Address):
        if (address.ipv4_mapped is not None or address.sixtofour is not None or address.teredo is not None or
                address in ipaddress.ip_network('64:ff9b::/96') or
                address in ipaddress.ip_network('64:ff9b:1::/48')):
            raise NetworkError()
    return address


_resolver = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix='provider-dns')
_resolver_slots = threading.BoundedSemaphore(4)


def public_addresses(host, port, timeout=4):
    """Reject the entire answer if it contains any forbidden or malformed IP."""
    try:
        hostname(host)
        if type(port) is not int or port not in (443, 465, 587, 993, 8443):
            raise ValueError()
        if not _resolver_slots.acquire(blocking=False):
            raise NetworkError()
        try:
            pending = _resolver.submit(socket.getaddrinfo, host, port, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        except Exception:
            _resolver_slots.release()
            raise
        pending.add_done_callback(lambda unused: _resolver_slots.release())
        answers = pending.result(timeout=min(4, timeout))
        if not answers or len(answers) > 16:
            raise NetworkError()
        result = []
        for family, kind, protocol, unused, target in answers:
            if family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM or protocol != socket.IPPROTO_TCP:
                raise NetworkError()
            if len(target) != (2 if family == socket.AF_INET else 4) or target[1] != port:
                raise NetworkError()
            address = public_ip(target[0])
            if (address.version != (4 if family == socket.AF_INET else 6) or
                    family == socket.AF_INET6 and (target[2] != 0 or target[3] != 0)):
                raise NetworkError()
            item = (family, str(address), (str(address), port) if family == socket.AF_INET else (str(address), port, 0, 0))
            if item not in result:
                result.append(item)
        return result
    except Exception:
        raise NetworkError() from None


def public_socket(host, port, timeout=8):
    """Use numeric socket.connect, never a second hostname lookup (DNS rebinding)."""
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 8:
        raise NetworkError()
    deadline = time.monotonic() + timeout
    targets = public_addresses(host, port, timeout)
    for family, address, target in targets:
        client = None
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            client = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            client.settimeout(remaining)
            client.connect(target)
            peer = client.getpeername()
            if str(public_ip(peer[0])) != address or peer[1] != port:
                raise NetworkError()
            return client
        except Exception:
            if client is not None:
                client.close()
    raise NetworkError()


def wrap_tls(client, context, host):
    try:
        if (not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED or
                context.minimum_version < ssl.TLSVersion.TLSv1_2):
            raise NetworkError()
        return context.wrap_socket(client, server_hostname=host)
    except Exception:
        client.close()
        raise NetworkError() from None


class TLSIMAP(imaplib.IMAP4_SSL):
    def _create_socket(self, timeout):
        if self.port != 993:
            raise NetworkError()
        return wrap_tls(public_socket(self.host, self.port, timeout), self.ssl_context, self.host)

    def _log(self, *unused):
        # imaplib otherwise retains its last commands, including LOGIN, for diagnostics.
        pass


class TLSSMTP(smtplib.SMTP_SSL):
    def _get_socket(self, host, port, timeout):
        if port != 465 or self.source_address:
            raise NetworkError()
        return wrap_tls(public_socket(host, port, timeout), self.context, host)


class STARTTLSSMTP(smtplib.SMTP):
    def __init__(self, host, port=587, *, context=None, timeout=8, local_hostname='mcp-bridge.invalid'):
        context = context or tls_context()
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED or context.minimum_version < ssl.TLSVersion.TLSv1_2:
            raise NetworkError()
        super().__init__(host, port, local_hostname=local_hostname, timeout=timeout)
        try:
            if self.ehlo()[0] != 250 or not self.has_extn('starttls'):
                raise NetworkError()
            if self.starttls(context=context)[0] != 220 or self.ehlo()[0] != 250:
                raise NetworkError()
        except Exception:
            self.close()
            raise NetworkError() from None

    def _get_socket(self, host, port, timeout):
        if port != 587 or self.source_address:
            raise NetworkError()
        return public_socket(host, port, timeout)


def smtp_connection(host, port, *, context, timeout=8):
    if port == 465:
        return TLSSMTP(host, port, context=context, timeout=timeout, local_hostname='mcp-bridge.invalid')
    if port == 587:
        return STARTTLSSMTP(host, port, context=context, timeout=timeout)
    raise NetworkError()


class TLSHTTPS(http.client.HTTPSConnection):
    def connect(self):
        if self._tunnel_host or self.source_address or self.port not in (443, 8443):
            raise NetworkError()
        self.sock = wrap_tls(public_socket(self.host, self.port, self.timeout), self._context, self.host)
