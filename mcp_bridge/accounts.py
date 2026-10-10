"""Owner-only account storage; isolated protocols, atomic snapshots, no secret output."""
import hashlib
import imaplib
import re
import smtplib

from bridge.app import ApiError, Calendar, tls_context
from bridge.providers import DEFAULT_PROFILES
from bridge.network import TLSIMAP, smtp_connection
from .config import ORIGIN
from .account_storage import PROVIDERS, MAX_CONFIG, SingleAccountSecrets, Snapshot, credentials, provider_name, sender_address


def current_account_id(source, provider):
    method = getattr(source, 'account_id', None)
    return method(provider) if callable(method) else None


def current_revision(source, provider):
    method = getattr(source, 'revision', None)
    return method(provider) if callable(method) else None


def bind_id(value, revision, purpose):
    """Reversible opaque mapping; stale account IDs no longer match discovery.

    This is a revision binding, never an authorization boundary. Provider IDs
    are still validated against bounded discovery before any mutation.
    """
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{24}', value):
        raise ApiError(400, 'invalid_stable_id')
    mask = hashlib.sha256((revision + ':' + purpose).encode('ascii')).digest()[:12]
    return bytes(a ^ b for a, b in zip(bytes.fromhex(value), mask)).hex()


class MemorySecrets:
    def __init__(self, username, password, profiles=DEFAULT_PROFILES):
        self.values = (username, password)
        self.profiles = profiles

    def pair(self, provider):
        return self.values


class ConnectionChecks:
    def __init__(self, imap=TLSIMAP, smtp=smtp_connection, calendar=None, contacts=None, *, profiles=DEFAULT_PROFILES):
        self.imap, self.smtp, self.calendar, self.contacts = imap, smtp, calendar, contacts
        self.profiles = profiles

    def check(self, provider, username, password, *, profiles=None):
        provider_name(provider)
        credentials(username, password)
        profiles = profiles if profiles is not None else self.profiles
        try:
            if provider == 'mail':
                mail = profiles.mail
                client = self.imap(mail.imap_host, mail.imap_port, ssl_context=tls_context(), timeout=8)
                try:
                    if client.login(username, password)[0] != 'OK':
                        raise ValueError()
                finally:
                    try:
                        client.logout()
                    except Exception:
                        pass
                client = self.smtp(mail.smtp_host, mail.smtp_port, context=tls_context(), timeout=8)
                try:
                    if client.ehlo()[0] != 250 or client.login(username, password)[0] not in (235, 503):
                        raise ValueError()
                finally:
                    try:
                        client.quit()
                    except Exception:
                        try:
                            client.close()
                        except Exception:
                            pass
            elif provider == 'caldav':
                Calendar(MemorySecrets(username, password, profiles), **({'factory': self.calendar} if self.calendar else {})).discover()
            else:
                from bridge.carddav import Contacts
                Contacts(MemorySecrets(username, password, profiles), **({'factory': self.contacts} if self.contacts else {})).discover()
            return {'connected': True, 'mail_sent': False, 'provider_data_changed': False, 'credentials_saved': False}
        except Exception:
            raise ApiError(502, 'connection_check_failed') from None


def connection_status(source):
    result = {'accounts': source.status(), 'setup_url': ORIGIN + '/accounts', 'live_provider_access_verified': False,
            'requires_personal_passkey': True, 'credential_input_in_tools_supported': False,
            'protocols': source.profiles.public()}
    if callable(getattr(source, 'inventory', None)):
        result['configured_accounts'] = source.inventory()
        result['account_selection_required_when_ambiguous'] = True
    return result


# The catalog imports the shared storage module directly; either import order works.
from .multi_accounts import MultiAccountSecrets as AccountSecrets
