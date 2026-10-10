"""Bounded read operations. No SMTP, mutations, shell calls, or credential logging."""
import base64
import datetime as dt
import email
import email.policy
import hashlib
import hmac
import http.client
import imaplib
import json
import os
import pathlib
import re
import ssl
import threading
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
from .providers import ICLOUD_CALDAV, profiles_for
from .network import TLSHTTPS, TLSIMAP, tls_context

MAX_REQUEST = 8192
MAX_RESPONSE = 262144
MAX_MAIL_BYTES = 65536
MAX_HEADER_BYTES = 4096
SEARCH_WINDOW = 200
MAX_UPSTREAM_BYTES = 2097152
DAV = "DAV:"
CAL = "urn:ietf:params:xml:ns:caldav"


class ApiError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code
        super().__init__(code)


def bounded_int(value, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ApiError(400, "invalid_request")
    return value


def fields(data, allowed):
    if not isinstance(data, dict) or set(data) - set(allowed):
        raise ApiError(400, "invalid_request")


def text(value, limit=1000):
    value = str(value or "")
    return "".join(c for c in value if c in "\n\t" or ord(c) >= 32)[:limit]


class Secrets:
    """Only fixed runtime secret names. Never values in environment variables."""
    def __init__(self, directory="/run/secrets"):
        self.directory = pathlib.Path(directory)

    def get(self, name):
        try:
            path = self.directory / name
            if path.is_symlink():
                return None
            with path.open("rb") as f:
                raw = f.read(4097)
            if len(raw) > 4096:
                return None
            value = raw.decode("utf-8").rstrip("\r\n")
            if not value or "\r" in value or "\n" in value or "\x00" in value:
                return None
            return value
        except (OSError, UnicodeError):
            return None

    def pair(self, provider):
        username = self.get(provider + "_username")
        password = self.get(provider + "_app_password")
        if not username or not password:
            raise ApiError(503, "provider_not_configured")
        return username, password


class PlainHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {"script", "style"}:
            self.skip += 1

    def handle_endtag(self, tag):
        if tag.lower() in {"script", "style"} and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def plain_message(message, limit):
    html_fallback = None
    for index, part in enumerate(message.walk()):
        if index >= 40:
            break
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        raw = part.get_payload(decode=True) or b""
        try:
            decoded = raw.decode(part.get_content_charset() or "utf-8", errors="replace")
        except LookupError:
            decoded = raw.decode("utf-8", errors="replace")
        if part.get_content_type() == "text/plain":
            return text(decoded, limit)
        if html_fallback is None:
            parser = PlainHTML()
            parser.feed(decoded)
            html_fallback = " ".join(parser.parts)
    return text(html_fallback, limit)


class Mail:
    def __init__(self, secrets, factory=TLSIMAP):
        self.secrets, self.factory = secrets, factory

    @property
    def provider(self):
        return profiles_for(self.secrets).mail

    @contextmanager
    def opened(self):
        username, password = self.secrets.pair("mail")
        client = self.factory(self.provider.imap_host, self.provider.imap_port, ssl_context=tls_context(), timeout=8)
        try:
            if client.login(username, password)[0] != "OK":
                raise ApiError(502, "upstream_unavailable")
            # readonly=True issues EXAMINE, never SELECT in read/write mode.
            if client.select("INBOX", readonly=True)[0] != "OK":
                raise ApiError(502, "upstream_unavailable")
            yield client
        finally:
            # CLOSE can expunge in writable sessions. Never call it.
            try:
                client.logout()
            except Exception:
                pass

    @staticmethod
    def response_number(client, name):
        _, values = client.response(name)
        if not values or not isinstance(values[0], bytes) or not values[0].isdigit():
            raise ApiError(502, "upstream_unavailable")
        return int(values[0])

    @staticmethod
    def literals(response, maximum):
        status, rows = response
        if status != "OK":
            raise ApiError(502, "upstream_unavailable")
        result = []
        for row in rows or []:
            if isinstance(row, tuple) and len(row) == 2:
                meta, raw = row
                match = re.search(rb"\bUID (\d+)\b", meta)
                if not match or not isinstance(raw, bytes) or len(raw) > maximum:
                    raise ApiError(502, "upstream_unavailable")
                result.append((int(match.group(1)), meta, raw))
        return result

    @staticmethod
    def headers(raw):
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        return {"subject": text(msg.get("Subject"), 500), "from": text(msg.get("From"), 500),
                "to": text(msg.get("To"), 500), "date": text(msg.get("Date"), 100)}

    def search(self, data):
        fields(data, {"query", "limit"})
        query = data.get("query", "")
        if not isinstance(query, str) or len(query) > 200:
            raise ApiError(400, "invalid_request")
        limit = bounded_int(data.get("limit", 10), 1, 25)
        with self.opened() as client:
            validity = self.response_number(client, "UIDVALIDITY")
            highest = max(1, self.response_number(client, "UIDNEXT") - 1)
            lowest = max(1, highest - SEARCH_WINDOW + 1)
            status, result = client.uid("SEARCH", None, "UID", f"{lowest}:{highest}")
            if status != "OK" or not result:
                raise ApiError(502, "upstream_unavailable")
            tokens = (result[0] or b"").split()
            if len(tokens) > SEARCH_WINDOW or any(not x.isdigit() for x in tokens):
                raise ApiError(502, "upstream_unavailable")
            ids = sorted(set(int(x) for x in tokens), reverse=True)
            if any(not lowest <= x <= highest for x in ids):
                raise ApiError(502, "upstream_unavailable")
            matches, deadline = [], time.monotonic() + 20
            for start in range(0, len(ids), 25):
                if time.monotonic() > deadline:
                    raise ApiError(504, "upstream_timeout")
                batch = ids[start:start + 25]
                command = "(UID FLAGS BODY.PEEK[HEADER.FIELDS (DATE FROM TO SUBJECT)]<0.4096>)"
                rows = self.literals(client.uid("FETCH", ",".join(map(str, batch)), command), MAX_HEADER_BYTES)
                if len(rows) > len(batch) or any(uid not in batch for uid, _, _ in rows):
                    raise ApiError(502, "upstream_unavailable")
                for uid, meta, raw in sorted(rows, reverse=True):
                    item = self.headers(raw)
                    if query.casefold() in " ".join(item.values()).casefold():
                        item.update(uid=uid, uidvalidity=validity, mailbox="INBOX",
                                    unread=b"\\Seen" not in meta, data_trust="untrusted")
                        matches.append(item)
                if len(matches) >= limit:
                    break
            return {"items": matches[:limit], "limit": limit, "scan_window_uids": SEARCH_WINDOW,
                    "bounded_window": True, "data_trust": "untrusted"}

    def read(self, data):
        fields(data, {"uid", "uidvalidity", "max_chars"})
        uid = bounded_int(data.get("uid"), 1, 4294967295)
        validity = bounded_int(data.get("uidvalidity"), 1, 4294967295)
        maximum = bounded_int(data.get("max_chars", 8000), 1, 16000)
        with self.opened() as client:
            if self.response_number(client, "UIDVALIDITY") != validity:
                raise ApiError(409, "stale_message_id")
            rows = self.literals(client.uid("FETCH", str(uid),
                "(UID FLAGS RFC822.SIZE BODY.PEEK[]<0.65536>)"), MAX_MAIL_BYTES)
            if not rows:
                raise ApiError(404, "not_found")
            if len(rows) != 1 or rows[0][0] != uid:
                raise ApiError(502, "upstream_unavailable")
            _, meta, raw = rows[0]
            msg = email.message_from_bytes(raw, policy=email.policy.default)
            size = re.search(rb"RFC822.SIZE (\d+)", meta)
            item = self.headers(raw)
            item.update(uid=uid, uidvalidity=validity, mailbox="INBOX", body=plain_message(msg, maximum),
                        unread=b"\\Seen" not in meta, data_trust="untrusted",
                        truncated=(not size or int(size.group(1)) > len(raw)
                                   or len(plain_message(msg, maximum + 1)) > maximum))
            return item


def icloud_url(value):
    try:return ICLOUD_CALDAV.validate_url(value)
    except ValueError:raise ApiError(502,'upstream_unavailable') from None


class CalDAV:
    def __init__(self, credentials, connection=TLSHTTPS, *, provider=ICLOUD_CALDAV, url_validator=None):
        self.credentials, self.connection, self.calls = credentials, connection, 0
        self.provider, self.origin = provider, provider.origin
        self.url_validator = url_validator or self.validate_url

    def validate_url(self, value):
        try:
            return self.provider.validate_url(value)
        except ValueError:
            raise ApiError(502, 'upstream_unavailable') from None

    def request(self, method, url, payload, depth="0"):
        if method not in {"PROPFIND", "REPORT"}:
            raise ApiError(405, "read_only")
        for redirect in range(4):
            parsed = self.url_validator(url)
            self.calls += 1
            if self.calls > 16:
                raise ApiError(502, "upstream_unavailable")
            auth = base64.b64encode(":".join(self.credentials).encode("utf-8")).decode("ascii")
            headers = {"Authorization": "Basic " + auth, "Content-Type": "application/xml; charset=utf-8",
                       "Depth": depth, "User-Agent": "SelfHostedReadAdapter/0.1"}
            client = self.connection(parsed.hostname, 443 if parsed.port is None else parsed.port, context=tls_context(), timeout=8)
            try:
                client.request(method, parsed.path or "/", body=payload, headers=headers)
                response = client.getresponse()
                status, location = response.status, response.getheader("Location")
                raw = response.read(MAX_UPSTREAM_BYTES + 1)
            finally:
                client.close()
            if len(raw) > MAX_UPSTREAM_BYTES:
                raise ApiError(502, "upstream_unavailable")
            if status in {301, 302, 307, 308} and location and redirect < 3:
                url = urljoin(url, location)
                self.url_validator(url)  # Check BEFORE forwarding Authorization.
                continue
            if status != 207 or b'\x00' in raw or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                raise ApiError(502, "upstream_unavailable")
            try:
                return ET.fromstring(raw.decode('utf-8')), url
            except (ET.ParseError,UnicodeError):
                raise ApiError(502, "upstream_unavailable") from None
        raise ApiError(502, "upstream_unavailable")


def propfind(*names):
    root = ET.Element("{" + DAV + "}propfind")
    prop = ET.SubElement(root, "{" + DAV + "}prop")
    for namespace, name in names:
        ET.SubElement(prop, "{" + namespace + "}" + name)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def successful_props(xml):
    for response in xml.findall("{" + DAV + "}response"):
        for state in response.findall("{" + DAV + "}propstat"):
            status = state.findtext("{" + DAV + "}status", "")
            if re.search(r"\s200(?:\s|$)", status):
                prop = state.find("{" + DAV + "}prop")
                if prop is not None:
                    yield response, prop


def calendar_id(url):
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]


def ical_events(content, maximum):
    if not content.startswith("BEGIN:VCALENDAR"):
        raise ApiError(502, "upstream_unavailable")
    lines = re.sub(r"\r?\n[ \t]", "", content).splitlines()
    result, current, depth = [], None, 0
    for line in lines:
        if line == "BEGIN:VEVENT":
            current, depth = {}, 1
        elif current is not None and line.startswith("BEGIN:"):
            depth += 1
        elif line == "END:VEVENT" and current is not None:
            if "RRULE" in current:
                # Expanded REPORT must resolve recurrences; don't silently omit instances.
                raise ApiError(502, "upstream_unavailable")
            if "UID" in current and "DTSTART" in current:
                start_value, start_options = current["DTSTART"]
                item = {"id": text(current["UID"][0], 300), "starts_at": text(start_value, 80),
                        "timezone": text(start_options.get("TZID", "UTC" if start_value.endswith("Z") else "floating"), 100),
                        "all_day": start_options.get("VALUE") == "DATE", "data_trust": "untrusted"}
                for source, key, size in [("SUMMARY", "summary", 500), ("DESCRIPTION", "description", 1000),
                                          ("LOCATION", "location", 500), ("DTEND", "ends_at", 80)]:
                    value = current.get(source, ("", {}))[0]
                    value = re.sub(r"\\([nN,;\\])", lambda m: "\n" if m[1].lower() == "n" else m[1], value)
                    item[key] = text(value, size)
                result.append(item)
            current, depth = None, 0
            if len(result) >= maximum:
                break
        elif current is not None and line.startswith("END:"):
            depth -= 1
        elif current is not None and depth == 1 and ":" in line:
            header, value = line.split(":", 1)
            parts = header.split(";")
            if parts[0] in {"UID", "SUMMARY", "LOCATION", "DESCRIPTION", "DTSTART", "DTEND", "RRULE"}:
                options = dict(p.split("=", 1) for p in parts[1:] if "=" in p)
                current[parts[0]] = value, options
    return result


class Calendar:
    def __init__(self, secrets, factory=None):
        self.secrets, self.factory = secrets, factory

    @property
    def provider(self):
        return profiles_for(self.secrets).caldav

    def validate_url(self, value):
        try:
            return self.provider.validate_url(value)
        except ValueError:
            raise ApiError(502, 'upstream_unavailable') from None

    def discover(self):
        client = self.factory(self.secrets.pair("caldav")) if self.factory else CalDAV(self.secrets.pair("caldav"), provider=self.provider)
        # Trusted test transports use the same profile for metadata validation.
        client.origin, client.url_validator = self.provider.origin, self.validate_url
        xml, base = client.request("PROPFIND", self.provider.origin,
                                   propfind((DAV, "current-user-principal")))
        href = next((p.findtext("{" + DAV + "}current-user-principal/{" + DAV + "}href")
                     for _, p in successful_props(xml)), None)
        if not href:
            raise ApiError(502, "upstream_unavailable")
        principal = urljoin(base, href)
        self.validate_url(principal)
        xml, base = client.request("PROPFIND", principal, propfind((CAL, "calendar-home-set")))
        href = next((p.findtext("{" + CAL + "}calendar-home-set/{" + DAV + "}href")
                     for _, p in successful_props(xml)), None)
        if not href:
            raise ApiError(502, "upstream_unavailable")
        home = urljoin(base, href)
        self.validate_url(home)
        xml, base = client.request("PROPFIND", home,
            propfind((DAV, "displayname"), (DAV, "resourcetype")), depth="1")
        calendars = []
        for response, prop in successful_props(xml):
            if prop.find("{" + DAV + "}resourcetype/{" + CAL + "}calendar") is None:
                continue
            href = response.findtext("{" + DAV + "}href")
            if not href:
                continue
            url = urljoin(base, href)
            self.validate_url(url)
            calendars.append({"id": calendar_id(url), "name": text(prop.findtext("{" + DAV + "}displayname"), 300), "url": url})
            if len(calendars) >= 25:
                break
        return client, calendars

    def list(self, data):
        fields(data, {"limit"})
        maximum = bounded_int(data.get("limit", 25), 1, 25)
        _, calendars = self.discover()
        return {"items": [{"id": c["id"], "name": c["name"], "data_trust": "untrusted"}
                          for c in calendars[:maximum]], "limit": maximum, "data_trust": "untrusted"}

    def events(self, data):
        fields(data, {"calendar_id", "start", "end", "limit"})
        maximum = bounded_int(data.get("limit", 25), 1, 50)
        identifier = data.get("calendar_id", "")
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{24}", identifier):
            raise ApiError(400, "invalid_request")
        try:
            start = dt.datetime.fromisoformat(data["start"].replace("Z", "+00:00"))
            end = dt.datetime.fromisoformat(data["end"].replace("Z", "+00:00"))
            if not start.utcoffset() == dt.timedelta(0) or not end.utcoffset() == dt.timedelta(0):
                raise ValueError()
            if not dt.timedelta(0) < end - start <= dt.timedelta(days=31):
                raise ValueError()
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ApiError(400, "invalid_request") from None
        client, calendars = self.discover()
        selected = next((c for c in calendars if c["id"] == identifier), None)
        if not selected:
            raise ApiError(404, "not_found")
        timerange = {"start": start.strftime("%Y%m%dT%H%M%SZ"), "end": end.strftime("%Y%m%dT%H%M%SZ")}
        root = ET.Element("{" + CAL + "}calendar-query")
        prop = ET.SubElement(root, "{" + DAV + "}prop")
        ET.SubElement(prop, "{" + DAV + "}getetag")
        value = ET.SubElement(prop, "{" + CAL + "}calendar-data")
        ET.SubElement(value, "{" + CAL + "}expand", timerange)
        filters = ET.SubElement(root, "{" + CAL + "}filter")
        vc = ET.SubElement(filters, "{" + CAL + "}comp-filter", {"name": "VCALENDAR"})
        ve = ET.SubElement(vc, "{" + CAL + "}comp-filter", {"name": "VEVENT"})
        ET.SubElement(ve, "{" + CAL + "}time-range", timerange)
        xml, _ = client.request("REPORT", selected["url"], ET.tostring(root, encoding="utf-8"), depth="1")
        events = []
        for response, prop in successful_props(xml):
            content = prop.findtext("{" + CAL + "}calendar-data")
            if content:
                href=response.findtext("{" + DAV + "}href", "")
                object_url=urljoin(selected["url"],href)
                parsed=self.validate_url(object_url)
                parent=self.validate_url(selected["url"])
                if not href or (parsed.hostname, 443 if parsed.port is None else parsed.port)!=(parent.hostname, 443 if parent.port is None else parent.port) or not parsed.path.startswith(parent.path.rstrip('/')+'/'):
                    raise ApiError(502,"upstream_unavailable")
                rows=ical_events(content, maximum + 1 - len(events))
                for item in rows:
                    item.update(object_id=calendar_id(object_url),etag=text(prop.findtext("{" + DAV + "}getetag"),200))
                events.extend(rows)
            if len(events) > maximum:
                break
        events.sort(key=lambda e: (e["starts_at"], e["id"]))
        return {"items": events[:maximum], "limit": maximum, "truncated": len(events) > maximum,
                "data_trust": "untrusted"}


class App:
    def __init__(self, secrets=None, mail=None, calendar=None):
        self.secrets = secrets or Secrets()
        self.mail = mail or Mail(self.secrets)
        self.calendar = calendar or Calendar(self.secrets)

    def authorized(self, supplied):
        token = self.secrets.get("bridge_auth_token")
        if not token or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", token):
            return False
        return isinstance(supplied, str) and hmac.compare_digest(supplied.encode("utf-8"), ("Bearer " + token).encode("ascii"))

    def call(self, method, path, data):
        if method == "GET" and path == "/v1/status":
            return {"mode": "read_only_prototype", "providers_connected": False}
        routes = {"/v1/mail/search": self.mail.search, "/v1/mail/read": self.mail.read,
                  "/v1/calendars/list": self.calendar.list, "/v1/calendars/events": self.calendar.events}
        if path not in routes:
            raise ApiError(404, "not_found")
        if method != "POST":
            raise ApiError(405, "read_only")
        return routes[path](data)

