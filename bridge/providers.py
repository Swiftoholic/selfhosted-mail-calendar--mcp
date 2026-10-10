"""Pinned presets/operator profiles and validated, owner-only account endpoints."""
from dataclasses import dataclass
import hashlib
import json
import os
import re
import stat
from typing import Protocol
from urllib.parse import unquote, urlsplit

from .network import hostname


@dataclass(frozen=True)
class MailProvider:
    identifier: str
    imap_host: str
    imap_port: int
    smtp_host: str
    smtp_port: int

    @property
    def fingerprint(self):
        return fingerprint([self.identifier, self.imap_host, self.imap_port, self.smtp_host, self.smtp_port])

    def public(self):
        return {'provider': self.identifier, 'experimental': self.identifier == 'custom',
                'imap_host': self.imap_host, 'imap_port': self.imap_port,
                'smtp_host': self.smtp_host, 'smtp_port': self.smtp_port,
                'smtp_tls': 'implicit' if self.smtp_port == 465 else 'starttls_required'}


@dataclass(frozen=True)
class DAVProvider:
    identifier: str
    protocol: str
    origin: str
    hostname_pattern: str
    port: int = 443

    def validate_url(self,value):
        if not isinstance(value,str) or not value or len(value)>2048 or any(ord(c)<33 or ord(c)>126 for c in value):
            raise ValueError('invalid_provider_url')
        try:parsed=urlsplit(value);port=parsed.port
        except ValueError:raise ValueError('invalid_provider_url') from None
        path = unquote(parsed.path)
        if (parsed.scheme!='https' or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or
            (443 if port is None else port) != self.port or not re.fullmatch(self.hostname_pattern,parsed.hostname or '') or
            not parsed.path.startswith('/') or re.search(r'%(?![0-9a-fA-F]{2})', value) or
            re.search(r'%2f|%5c|%25', parsed.path, re.IGNORECASE) or '?' in value or '#' in value or
            any(ord(c) < 32 or ord(c) == 127 for c in path) or '\\' in path or
            any(part in ('.', '..') for part in path.split('/'))):
            raise ValueError('invalid_provider_url')
        return parsed

    @property
    def fingerprint(self):
        return fingerprint([self.identifier, self.protocol, self.origin, self.hostname_pattern, self.port])

    def public(self):
        return {'provider': self.identifier, 'experimental': self.identifier == 'custom',
                'origin': self.origin, 'port': self.port}


class DAVTransport(Protocol):
    def request(self,method: str,url: str,payload: bytes,depth: str='0'): ...


class TransportFactory(Protocol):
    def __call__(self,credentials: tuple[str,str]) -> DAVTransport: ...


class MailTransportFactory(Protocol):
    def __call__(self,host: str,port: int,*,ssl_context,timeout: int): ...


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode('ascii')).hexdigest()


GMX=MailProvider('gmx','imap.gmx.net',993,'mail.gmx.net',465)
ICLOUD_CALDAV=DAVProvider('icloud','caldav','https://caldav.icloud.com/',r'(?:caldav|p\d{2,3}-caldav)\.icloud\.com')
ICLOUD_CARDDAV=DAVProvider('icloud','carddav','https://contacts.icloud.com/',r'(?:contacts|p\d{2,3}-contacts)\.icloud\.com')
MAIL_PROVIDERS={'gmx':GMX}
DAV_PROVIDERS={('icloud','caldav'):ICLOUD_CALDAV,('icloud','carddav'):ICLOUD_CARDDAV}


def mail_provider(identifier):
    if identifier not in MAIL_PROVIDERS:raise ValueError('unsupported_mail_provider')
    return MAIL_PROVIDERS[identifier]


def dav_provider(identifier,protocol):
    if (identifier,protocol) not in DAV_PROVIDERS:raise ValueError('unsupported_dav_provider')
    return DAV_PROVIDERS[(identifier,protocol)]


@dataclass(frozen=True)
class ProviderProfiles:
    mail: MailProvider = GMX
    caldav: DAVProvider = ICLOUD_CALDAV
    carddav: DAVProvider = ICLOUD_CARDDAV

    def get(self, account):
        if account not in ('mail', 'caldav', 'carddav'):
            raise ValueError('unsupported_protocol_account')
        return getattr(self, account)

    def public(self):
        return {name: self.get(name).public() for name in ('mail', 'caldav', 'carddav')}


DEFAULT_PROFILES = ProviderProfiles()


def profiles_for(source):
    return getattr(source, 'profiles', DEFAULT_PROFILES)


PROFILE_ID = re.compile(r'[a-z][a-z0-9_-]{0,47}\Z')
# ':' was never permitted in V2 operator IDs, so manual accounts cannot collide
# with a formerly valid operator profile or silently reinterpret its records.
MANUAL_IDS = {protocol: 'manual:' + protocol for protocol in ('mail', 'caldav', 'carddav')}


def manual_profile(protocol, config):
    """Reuse the strict operator protocol schema; no network or mutable registry.

    A manual DAV URL authorizes exactly its own DNS host. Each eventual transport
    still rejects nonpublic/mixed DNS, pins the checked IP and verifies TLS/SNI.
    The returned fresh canonical configuration is bound into the account proof.
    """
    if protocol not in MANUAL_IDS or not isinstance(config, dict):
        raise ValueError('invalid_manual_server_config')
    try:
        defaults = {'version': 1, 'mail': {'preset': 'gmx'}, 'caldav': {'preset': 'icloud'}, 'carddav': {'preset': 'icloud'}}
        defaults[protocol] = config
        profile = parse_profiles(defaults).get(protocol)
        if profile.identifier != 'custom':
            raise ValueError()
        if protocol == 'mail':
            hosts = [profile.imap_host, profile.smtp_host]
            canonical = {'preset': 'custom', 'imap': {'host': profile.imap_host, 'port': profile.imap_port, 'tls': 'implicit'},
                         'smtp': {'host': profile.smtp_host, 'port': profile.smtp_port,
                                  'tls': 'implicit' if profile.smtp_port == 465 else 'starttls_required'}}
        else:
            host = profile.validate_url(profile.origin).hostname
            if config['allowed_hosts'] != [host]:
                raise ValueError()
            hosts = [host]
            canonical = {'preset': 'custom', 'origin': profile.origin, 'allowed_hosts': [host]}
        if any(host.endswith('.home.arpa') for host in hosts):
            raise ValueError()
        return profile, canonical
    except (KeyError, ValueError, TypeError, AttributeError):
        raise ValueError('invalid_manual_server_config') from None


class ProviderCatalog:
    """Named profiles are immutable; manual endpoints belong to an account only."""
    def __init__(self, profiles=DEFAULT_PROFILES, extra=None, defaults=None):
        from .provider_presets import bundle
        self.entries, self.choice_info, self.unavailable_choices = bundle()
        self.defaults = {'mail': 'gmx-mail', 'caldav': 'icloud-caldav', 'carddav': 'icloud-carddav'}
        for protocol in self.defaults:
            selected = profiles.get(protocol)
            if selected.identifier == 'custom':
                key = 'operator-' + protocol
                self.entries[key] = (protocol, 'Eigener Anbieter', selected)
                self.defaults[protocol] = key
        # Existing V2 IDs take precedence over newly introduced template names.
        # Their immutable transport/fingerprint and operator guidance survive.
        for key, entry in (extra or {}).items():
            self.entries[key] = entry
            self.choice_info[key] = {'info_key': 'provider.operator', 'auth_mode': 'provider_password', 'source_urls': []}
        if defaults is not None:
            self.defaults = defaults
        if set(self.defaults) != {'mail', 'caldav', 'carddav'} or any(
                key not in self.entries or self.entries[key][0] != protocol for protocol, key in self.defaults.items()):
            raise ValueError('invalid_provider_configuration')

    @classmethod
    def from_profiles(cls, profiles):
        return profiles if isinstance(profiles, cls) else cls(profiles)

    def selected(self, identifier, protocol):
        if not isinstance(identifier, str) or identifier not in self.entries or self.entries[identifier][0] != protocol:
            raise ValueError('unsupported_provider_profile')
        return self.entries[identifier][2]

    def get(self, protocol):
        return self.selected(self.defaults[protocol], protocol)

    @property
    def mail(self): return self.get('mail')

    @property
    def caldav(self): return self.get('caldav')

    @property
    def carddav(self): return self.get('carddav')

    def public(self):
        return {protocol: self.get(protocol).public() for protocol in self.defaults}

    def choices(self):
        return [{'id': key, 'protocol': protocol, 'name': name, 'supported': True, **profile.public(),
                 **self.choice_info.get(key, {'info_key': 'provider.operator', 'auth_mode': 'provider_password', 'source_urls': []})}
                for key, (protocol, name, profile) in self.entries.items()] + [
                    {'id': key, 'protocol': protocol, 'name': 'Other provider / Manual', 'manual': True,
                     'supported': True, 'auth_mode': 'provider_password', 'info_key': 'provider.manual', 'source_urls': []}
                    for protocol, key in MANUAL_IDS.items()] + [dict(choice) for choice in self.unavailable_choices
                                                               if choice['id'] not in self.entries]

    def oauth_only(self, identifier):
        return (isinstance(identifier, str) and identifier not in self.entries and
                any(choice['id'] == identifier and choice['auth_mode'] == 'oauth_required' for choice in self.unavailable_choices))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('invalid_provider_configuration')
        result[key] = value
    return result


def parse_profiles(value):
    """Strict schema, narrow port choices, explicit per-protocol server allowlists."""
    try:
        if isinstance(value, dict) and type(value.get('version')) is int and value['version'] == 2:
            if set(value) != {'version', 'profiles', 'defaults'} or not isinstance(value['profiles'], dict) or not 1 <= len(value['profiles']) <= 16:
                raise ValueError()
            entries = {}
            # Preserve the original V2 schema: newer template names were legal
            # operator IDs before this feature and must keep their meaning.
            reserved = {'gmx-mail', 'icloud-caldav', 'icloud-carddav'}
            for key, item in value['profiles'].items():
                if (not isinstance(key, str) or not PROFILE_ID.fullmatch(key) or key in reserved or
                        not isinstance(item, dict) or set(item) != {'protocol', 'name', 'config'} or
                        item['protocol'] not in ('mail', 'caldav', 'carddav') or not isinstance(item['name'], str) or
                        not 1 <= len(item['name']) <= 80 or any(ord(c) < 32 or ord(c) == 127 for c in item['name'])):
                    raise ValueError()
                protocol = item['protocol']
                old = {'version': 1, 'mail': {'preset': 'gmx'}, 'caldav': {'preset': 'icloud'}, 'carddav': {'preset': 'icloud'}}
                old[protocol] = item['config']
                entries[key] = (protocol, item['name'], parse_profiles(old).get(protocol))
            return ProviderCatalog(extra=entries, defaults=value['defaults'])
        if not isinstance(value, dict) or set(value) != {'version', 'mail', 'caldav', 'carddav'} or type(value['version']) is not int or value['version'] != 1:
            raise ValueError()
        mail = value['mail']
        if mail == {'preset': 'gmx'}:
            mail = GMX
        else:
            if not isinstance(mail, dict) or set(mail) != {'preset', 'imap', 'smtp'} or mail['preset'] != 'custom':
                raise ValueError()
            imap, smtp = mail['imap'], mail['smtp']
            if (not isinstance(imap, dict) or set(imap) != {'host', 'port', 'tls'} or
                    not isinstance(smtp, dict) or set(smtp) != {'host', 'port', 'tls'} or
                    type(imap['port']) is not int or imap['port'] != 993 or imap['tls'] != 'implicit' or
                    type(smtp['port']) is not int or (smtp['port'], smtp['tls']) not in ((465, 'implicit'), (587, 'starttls_required'))):
                raise ValueError()
            mail = MailProvider('custom', hostname(imap['host']), imap['port'], hostname(smtp['host']), smtp['port'])
        dav = {}
        for protocol in ('caldav', 'carddav'):
            item = value[protocol]
            if item == {'preset': 'icloud'}:
                dav[protocol] = dav_provider('icloud', protocol)
                continue
            if (not isinstance(item, dict) or set(item) != {'preset', 'origin', 'allowed_hosts'} or
                    item['preset'] != 'custom' or not isinstance(item['origin'], str) or
                    not isinstance(item['allowed_hosts'], list) or not 1 <= len(item['allowed_hosts']) <= 8):
                raise ValueError()
            hosts = tuple(hostname(host) for host in item['allowed_hosts'])
            if len(set(hosts)) != len(hosts):
                raise ValueError()
            parsed = urlsplit(item['origin'])
            if parsed.hostname not in hosts or (443 if parsed.port is None else parsed.port) not in (443, 8443):
                raise ValueError()
            provider = DAVProvider('custom', protocol, item['origin'], '(?:' + '|'.join(re.escape(host) for host in hosts) + ')', 443 if parsed.port is None else parsed.port)
            provider.validate_url(provider.origin)
            dav[protocol] = provider
        return ProviderProfiles(mail, dav['caldav'], dav['carddav'])
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError('invalid_provider_configuration') from None


def load_profiles(path='/run/config/providers.json'):
    """The fixed read-only operator file contains endpoints, never credentials."""
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in (0, os.getuid()) or
                stat.S_IMODE(info.st_mode) & 0o022 or not 1 <= info.st_size <= 16384):
            raise ValueError()
        with os.fdopen(descriptor, 'rb') as stream:
            descriptor = None
            raw = stream.read(16385)
        if len(raw) > 16384:
            raise ValueError()
        return parse_profiles(json.loads(raw, object_pairs_hook=unique_object))
    except FileNotFoundError:
        return DEFAULT_PROFILES
    except (OSError, ValueError, TypeError, UnicodeError):
        raise ValueError('invalid_provider_configuration') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
