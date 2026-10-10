"""Private single-account storage and validation shared by the catalog reader."""
import contextlib
import hashlib
import json
import os
import pathlib
import re
import secrets
import stat
import threading
from dataclasses import dataclass
from email.headerregistry import Address

from bridge.app import ApiError, Secrets
from bridge.providers import load_profiles

PROVIDERS = ('mail', 'caldav', 'carddav')
MAX_CONFIG = 2048


def provider_name(value):
    if value not in PROVIDERS:
        raise ApiError(400, 'unsupported_provider')
    return value

def credentials(username, password):
    if not isinstance(username, str) or not 1 <= len(username) <= 254 or ':' in username or any(ord(c) < 33 or ord(c) > 126 for c in username):
        raise ApiError(400, 'invalid_account_input')
    if not isinstance(password, str) or not 8 <= len(password) <= 256 or any(ord(c) < 33 or ord(c) > 126 for c in password):
        raise ApiError(400, 'invalid_account_input')
    return username, password

def sender_address(value):
    try:
        if not isinstance(value, str) or not 3 <= len(value) <= 254 or any(ord(c) < 33 or ord(c) > 126 for c in value):
            raise ValueError()
        address = Address(addr_spec=value)
        if not address.username or not address.domain or address.addr_spec != value or any(c in value for c in '<>"\\,;:'):
            raise ValueError()
    except Exception:
        raise ApiError(400, 'invalid_account_input') from None
    return value

@dataclass(frozen=True, repr=False)
class Snapshot:
    revision: str
    username: str
    password: str
    sender: str | None = None
    profile_matches: bool = True
    account_id: str | None = None
    profile_id: str | None = None
    capabilities: tuple[str, ...] | None = None
    profile: object | None = None

class SingleAccountSecrets(Secrets):
    managed_accounts = True

    def __init__(self, directory='/run/secrets', *, profiles=None):
        super().__init__(directory)
        self.profiles = profiles if profiles is not None else load_profiles()
        self.locks = {provider: threading.RLock() for provider in PROVIDERS}
        self.local = threading.local()

    @contextlib.contextmanager
    def directory_fd(self):
        descriptor = None
        try:
            descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            info = os.fstat(descriptor)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ApiError(503, 'account_storage_not_private')
            yield descriptor
        except OSError:
            raise ApiError(503, 'account_storage_unavailable') from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def load(self, provider):
        provider_name(provider)
        with self.directory_fd() as directory:
            descriptor = None
            try:
                descriptor = os.open(provider + '.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > MAX_CONFIG:
                    raise ApiError(503, 'account_storage_not_private')
                with os.fdopen(descriptor, 'rb') as stream:
                    descriptor = None
                    raw = stream.read(MAX_CONFIG + 1)
                value = json.loads(raw)
                if (len(raw) > MAX_CONFIG or not isinstance(value, dict) or set(value) != {'version', 'revision', 'username', 'app_password', 'sender_email', 'profile_fingerprint'} or
                        type(value['version']) is not int or value['version'] != 2 or not isinstance(value['revision'], str) or not re.fullmatch(r'[0-9a-f]{24}', value['revision']) or
                        not isinstance(value['profile_fingerprint'], str) or not re.fullmatch(r'[0-9a-f]{64}', value['profile_fingerprint'])):
                    raise ValueError()
                username, password = credentials(value['username'], value['app_password'])
                sender = sender_address(value['sender_email']) if provider == 'mail' else None
                if provider != 'mail' and value['sender_email'] is not None:
                    raise ValueError()
                profile = self.profiles.get(provider).fingerprint
                revision = hashlib.sha256((value['revision'] + ':' + profile).encode('ascii')).hexdigest()[:24]
                return Snapshot(revision, username, password, sender, value['profile_fingerprint'] == profile)
            except FileNotFoundError:
                return None
            except ApiError as error:
                if error.code == 'invalid_account_input':
                    raise ApiError(503, 'account_configuration_invalid') from None
                raise
            except (OSError, ValueError, TypeError, UnicodeError):
                raise ApiError(503, 'account_configuration_invalid') from None
            finally:
                if descriptor is not None:
                    os.close(descriptor)

    @contextlib.contextmanager
    def guarded(self, provider):
        provider_name(provider)
        lock = self.locks[provider]
        if not lock.acquire(blocking=False):
            raise ApiError(409, 'provider_busy_try_again')
        try:
            yield
        finally:
            lock.release()

    @contextlib.contextmanager
    def operation(self, provider):
        with self.guarded(provider):
            snapshot = self.load(provider)
            if snapshot is None:
                raise ApiError(503, 'provider_not_configured')
            if not snapshot.profile_matches:
                raise ApiError(503, 'provider_profile_changed_reenter_credentials')
            old = getattr(self.local, provider, None)
            setattr(self.local, provider, snapshot)
            try:
                yield snapshot
            finally:
                setattr(self.local, provider, old)

    def pair(self, provider):
        provider_name(provider)
        snapshot = getattr(self.local, provider, None) or self.load(provider)
        if snapshot is None:
            raise ApiError(503, 'provider_not_configured')
        if not snapshot.profile_matches:
            raise ApiError(503, 'provider_profile_changed_reenter_credentials')
        return snapshot.username, snapshot.password

    def sender(self):
        snapshot = getattr(self.local, 'mail', None) or self.load('mail')
        if snapshot is None or not snapshot.profile_matches:
            raise ApiError(503, 'provider_not_configured')
        return snapshot.sender

    def revision(self, provider):
        snapshot = getattr(self.local, provider, None) or self.load(provider)
        return snapshot.revision if snapshot else None

    def status(self, revisions=False):
        result = {}
        for provider in PROVIDERS:
            try:
                snapshot = self.load(provider)
                item = {'configured': snapshot is not None and snapshot.profile_matches,
                        'error': 'provider_profile_changed_reenter_credentials' if snapshot and not snapshot.profile_matches else None}
                if revisions:
                    item['revision'] = snapshot.revision if snapshot else None
            except ApiError:
                item = {'configured': False, 'error': 'account_storage_unavailable'}
                if revisions:
                    item['revision'] = None
            result[provider] = item
        return result

    def persist(self, provider, username, password, expected_revision, sender_email=None):
        provider_name(provider)
        username, password = credentials(username, password)
        sender = sender_address(sender_email if sender_email is not None else username) if provider == 'mail' else None
        if provider != 'mail' and sender_email is not None:
            raise ApiError(400, 'invalid_account_input')
        if expected_revision is not None and (not isinstance(expected_revision, str) or not re.fullmatch(r'[0-9a-f]{24}', expected_revision)):
            raise ApiError(400, 'invalid_account_input')
        with self.guarded(provider):
            old = self.load(provider)
            if (old.revision if old else None) != expected_revision:
                raise ApiError(409, 'account_changed_reload_form')
            value = {'version': 2, 'revision': secrets.token_hex(12), 'username': username, 'app_password': password,
                     'sender_email': sender, 'profile_fingerprint': self.profiles.get(provider).fingerprint}
            raw = json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode('ascii')
            if len(raw) > MAX_CONFIG:
                raise ApiError(400, 'invalid_account_input')
            with self.directory_fd() as directory:
                temporary = '.' + provider + '-' + secrets.token_hex(16) + '.tmp'
                descriptor = None
                try:
                    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
                    with os.fdopen(descriptor, 'wb') as stream:
                        descriptor = None
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary, provider + '.json', src_dir_fd=directory, dst_dir_fd=directory)
                    os.fsync(directory)
                except OSError:
                    raise ApiError(503, 'account_save_unavailable_check_status') from None
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
                    try:
                        os.unlink(temporary, dir_fd=directory)
                    except FileNotFoundError:
                        pass
                    except OSError:
                        pass
            return {'saved': True, 'configured': True, 'revision': self.load(provider).revision, 'connection_verified': False}
