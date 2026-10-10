"""ChatGPT-only CIMD, verified public IPs, pinned DNS result, no redirects."""
import concurrent.futures
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time

STABLE = "https://chatgpt.com/oauth/client.json"
STABLE_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
CALLBACK = re.compile(r"^https://chatgpt\.com/oauth/([A-Za-z0-9_-]{1,128})/client\.json$")
MAX_DOCUMENT = 32768
DNS_TIMEOUT_SECONDS = 5
TOTAL_TIMEOUT_SECONDS = 10


def expected_redirect(client_id):
    if client_id == STABLE:
        return STABLE_REDIRECT
    match = CALLBACK.fullmatch(client_id or "")
    if match:
        return "https://chatgpt.com/connector/oauth/" + match[1]
    raise ValueError("untrusted_client")


def validate(client_id, document):
    redirect = expected_redirect(client_id)
    if not isinstance(document, dict) or len(json.dumps(document).encode()) > MAX_DOCUMENT:
        raise ValueError("invalid_cimd")
    if document.get("client_id") != client_id or document.get("redirect_uris") != [redirect]:
        raise ValueError("invalid_cimd_identity_or_redirect")
    if not isinstance(document.get("client_name"), str) or len(document["client_name"]) > 200:
        raise ValueError("invalid_cimd")
    methods = document.get("token_endpoint_auth_methods_supported")
    if methods is None:
        methods = [document.get("token_endpoint_auth_method")]
    if not isinstance(methods, list) or not all(isinstance(v, str) for v in methods) or "none" not in methods:
        raise ValueError("unsupported_client_auth")
    grants = document.get("grant_types", ["authorization_code"])
    if not isinstance(grants, list) or not all(isinstance(v,str) for v in grants) or "authorization_code" not in grants:
        raise ValueError("unsupported_grant")
    if document.get("response_types", ["code"]) != ["code"]:
        raise ValueError("unsupported_response")
    return {"client_id": client_id, "redirect_uri": redirect, "auth_method": "none",
            "grant_types": [grant for grant in ("authorization_code","refresh_token") if grant in grants]}


def public_addresses(rows):
    addresses = []
    for family, _, _, _, address in rows:
        ip = ipaddress.ip_address(address[0])
        if not ip.is_global or ip.is_multicast:
            raise ValueError("nonpublic_cimd_address")
        if family in (socket.AF_INET, socket.AF_INET6) and (family, address[0]) not in addresses:
            addresses.append((family, address[0]))
    if not addresses:
        raise ValueError("cimd_dns_failed")
    return sorted(addresses, key=lambda entry: entry[0] != socket.AF_INET)


def read_document(response):
    if response.status != 200 or response.getheader("Content-Encoding") not in (None, "identity"):
        raise ValueError("cimd_http_rejected")
    mime = response.getheader("Content-Type", "").split(";")[0].strip().lower()
    if mime not in {"application/json", "application/jrd+json"}:
        raise ValueError("cimd_content_type")
    length = response.getheader("Content-Length")
    if length is not None and (not length.isdigit() or int(length) > MAX_DOCUMENT):
        raise ValueError("cimd_too_large")
    raw = response.read(MAX_DOCUMENT + 1)
    if len(raw) > MAX_DOCUMENT:
        raise ValueError("cimd_too_large")
    return json.loads(raw)


class CIMD:
    def __init__(self):
        self.cache, self.lock = {}, threading.RLock()
        self.dns = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="cimd-dns")
        self.dns_slots = threading.BoundedSemaphore(2)

    def cached(self, client_id):
        with self.lock:
            row = self.cache.get(client_id)
            return row[1] if row and row[0] > time.monotonic() else None

    def prepare(self, client_id):
        expected_redirect(client_id)  # Reject arbitrary URLs BEFORE DNS/network.
        with self.lock:
            existing = self.cached(client_id)
            if existing:
                return existing
            self.cache = {key: value for key, value in self.cache.items() if value[0] > time.monotonic()}
            if len(self.cache) >= 16:
                raise ValueError("cimd_capacity")
            if not self.dns_slots.acquire(blocking=False):
                raise ValueError("cimd_dns_busy")
            deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
            task = self.dns.submit(socket.getaddrinfo, "chatgpt.com", 443, 0, socket.SOCK_STREAM)
            task.add_done_callback(lambda _: self.dns_slots.release())
            try:
                rows = task.result(timeout=min(DNS_TIMEOUT_SECONDS,max(0,deadline-time.monotonic())))
            except TimeoutError:
                # Do not create another resolver job on timeout. Running DNS
                # work keeps its slot until completion; at most two can exist.
                task.cancel()
                raise ValueError('cimd_dns_timeout') from None
            except OSError:
                raise ValueError('cimd_dns_failed') from None
            choices = public_addresses(rows)
            context = ssl.create_default_context()
            path = client_id[len("https://chatgpt.com"):]
            document = None
            for family, address in choices[:2]:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                connection = http.client.HTTPSConnection("chatgpt.com", timeout=3, context=context)
                sock = None
                transport = []
                def expire():
                    # Retain the TLS socket even when HTTPResponse detaches it
                    # for a Connection: close body read.
                    target = transport[-1] if transport else None
                    if target is not None:
                        try:
                            target.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                timer = threading.Timer(remaining, expire)
                timer.daemon = True
                timer.start()
                try:
                    # Connect to the validated address itself, no second DNS lookup.
                    sock = socket.socket(family, socket.SOCK_STREAM)
                    transport.append(sock)
                    sock.settimeout(3)
                    sock.connect((address, 443))
                    connection.sock = context.wrap_socket(sock, server_hostname="chatgpt.com", do_handshake_on_connect=False)
                    transport.append(connection.sock)
                    connection.sock.do_handshake()
                    connection.request("GET", path, headers={"Host": "chatgpt.com", "Accept": "application/json",
                                                              "User-Agent": "SelfHostedMailCalendarMCP/0.1",
                                                              "Connection": "close"})
                    document = read_document(connection.getresponse())
                    break
                except (OSError, ssl.SSLError):
                    continue
                finally:
                    timer.cancel()
                    connection.close()
                    if sock is not None:
                        sock.close()
            if document is None:
                raise ValueError("cimd_fetch_failed")
            item = validate(client_id, document)
            self.cache[client_id] = (time.monotonic() + 300, item)
            return item

    def close(self):
        self.dns.shutdown(wait=False, cancel_futures=True)
