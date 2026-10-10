"""Private bounded multiaccount catalog and immutable per-operation routing.

Existing single-account files remain read-only compatible. Explicit offline
migration imports them without changing their effective revisions or identity.
"""
import contextlib
import ctypes
import hashlib
import json
import os
import re
import secrets
import stat
import threading
import time

from bridge.app import ApiError
from bridge.providers import ProviderCatalog, ProviderProfiles, unique_object
from .account_storage import SingleAccountSecrets, Snapshot, credentials, provider_name, sender_address

CATALOG = 'accounts.json'
MAX_CATALOG = 65536
MAX_ACCOUNTS = 32
HEX = re.compile(r'[a-f0-9]{24}\Z')
CAPABILITIES = {'mail': {'mail:read', 'mail:write', 'mail:send'},
                'caldav': {'calendars:read', 'calendars:write'}, 'carddav': {'contacts:read'}}
RECORD_FIELDS = {'id', 'protocol', 'profile_id', 'profile_fingerprint', 'revision', 'username',
                 'app_password', 'sender_email', 'label', 'capabilities', 'connection'}


def identifier(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ApiError(400, 'invalid_account_id')
    return value


def label(value):
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= 80 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ApiError(400, 'invalid_account_label')
    return value.strip()


def capabilities(protocol, value):
    if (not isinstance(value, list) or any(not isinstance(x, str) for x in value) or
            len(value) != len(set(value)) or not set(value) <= CAPABILITIES[protocol]):
        raise ApiError(400, 'invalid_account_capabilities')
    return sorted(value)


class MultiAccountSecrets(SingleAccountSecrets):
    def __init__(self, directory='/run/secrets', *, profiles=None, clock=time.time):
        super().__init__(directory, profiles=profiles)
        self.catalog_lock = threading.RLock()
        self.account_locks = {}
        self.clock = clock

    @property
    def profiles(self):
        local = getattr(self, 'local', None)
        values = {protocol: self.catalog.get(protocol) for protocol in CAPABILITIES}
        for protocol in values:
            snapshot = getattr(local, protocol, None)
            if snapshot and snapshot.profile_id:
                values[protocol] = self.catalog.selected(snapshot.profile_id, protocol)
        return ProviderProfiles(**values)

    @profiles.setter
    def profiles(self, profiles):
        self.catalog = ProviderCatalog.from_profiles(profiles)

    def _read_file(self, name, maximum=MAX_CATALOG):
        with self.directory_fd() as directory:
            fd = None
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or
                        stat.S_IMODE(info.st_mode) != 0o600 or not 1 <= info.st_size <= maximum):
                    raise ApiError(503, 'account_storage_not_private')
                with os.fdopen(fd, 'rb') as stream:
                    fd = None
                    raw = stream.read(maximum + 1)
                if len(raw) > maximum:
                    raise ValueError()
                return json.loads(raw, object_pairs_hook=unique_object)
            except FileNotFoundError:
                return None
            except ApiError:
                raise
            except (ValueError, OSError, UnicodeError):
                raise ApiError(503, 'account_configuration_invalid') from None
            finally:
                if fd is not None:
                    os.close(fd)

    def _validate_catalog(self, value):
        try:
            if (not isinstance(value, dict) or set(value) != {'version', 'generation', 'accounts'} or
                    type(value['version']) is not int or value['version'] != 3 or
                    not isinstance(value['accounts'], list) or len(value['accounts']) > MAX_ACCOUNTS):
                raise ValueError()
            identifier(value['generation'])
            ids, revisions = set(), set()
            for item in value['accounts']:
                if not isinstance(item, dict) or set(item) != RECORD_FIELDS:
                    raise ValueError()
                key, revision = identifier(item['id']), identifier(item['revision'])
                if key in ids or revision in revisions:
                    raise ValueError()
                ids.add(key); revisions.add(revision)
                protocol = provider_name(item['protocol'])
                if not isinstance(item['profile_id'], str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,47}', item['profile_id']):
                    raise ValueError()
                # Removed operator profiles must produce an honest unavailable status.
                if not isinstance(item['profile_fingerprint'], str) or not re.fullmatch(r'[a-f0-9]{64}', item['profile_fingerprint']):
                    raise ValueError()
                credentials(item['username'], item['app_password'])
                if protocol == 'mail': sender_address(item['sender_email'])
                elif item['sender_email'] is not None: raise ValueError()
                label(item['label']); capabilities(protocol, item['capabilities'])
                check = item['connection']
                if (not isinstance(check, dict) or set(check) != {'state', 'checked_at'} or
                        check['state'] not in ('never_checked', 'connected', 'failed') or
                        check['checked_at'] is not None and (type(check['checked_at']) not in (int, float) or
                        not 0 <= check['checked_at'] < 1e12)):
                    raise ValueError()
            return value
        except (ValueError, KeyError, TypeError, ApiError):
            raise ApiError(503, 'account_configuration_invalid') from None

    def _legacy_records(self):
        result = []
        for protocol in CAPABILITIES:
            snapshot = SingleAccountSecrets.load(self, protocol)
            if snapshot:
                profile_id = self.catalog.defaults[protocol]
                profile = self.catalog.selected(profile_id, protocol)
                result.append({'id': hashlib.sha256(('single-v2:' + protocol).encode()).hexdigest()[:24],
                               'protocol': protocol, 'profile_id': profile_id,
                               'profile_fingerprint': profile.fingerprint if snapshot.profile_matches else '0' * 64,
                               'revision': snapshot.revision, 'username': snapshot.username, 'app_password': snapshot.password,
                               'sender_email': snapshot.sender, 'label': self.catalog.entries[profile_id][1],
                               'capabilities': sorted(CAPABILITIES[protocol]),
                               'connection': {'state': 'never_checked', 'checked_at': None}})
        return result

    def _state(self):
        value = self._read_file(CATALOG)
        return self._validate_catalog(value) if value is not None else None

    def _records(self):
        value = self._state()
        return value['accounts'] if value is not None else self._legacy_records()

    def _mutable_state(self):
        value = self._state()
        if value is None:
            if self._legacy_records():
                raise ApiError(409, 'account_migration_required')
            value = {'version': 3, 'generation': None, 'accounts': []}
        return value

    def _write_state(self, value, expected_generation):
        current = self._state()
        if (current['generation'] if current is not None else None) != expected_generation:
            raise ApiError(409, 'account_catalog_changed_reload')
        value = {**value, 'generation': secrets.token_hex(12)}
        self._validate_catalog(value)
        raw = json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode('ascii')
        if len(raw) > MAX_CATALOG:
            raise ApiError(400, 'account_capacity_reached')
        with self.directory_fd() as directory:
            temporary = '.accounts-' + secrets.token_hex(16) + '.tmp'
            fd = None
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
                with os.fdopen(fd, 'wb') as stream:
                    fd = None
                    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                if expected_generation is None:
                    # No overwrite when importing the old layout or creating a fresh catalog.
                    libc = ctypes.CDLL(None, use_errno=True)
                    rename = libc.renameat2
                    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
                    rename.restype = ctypes.c_int
                    if rename(directory, temporary.encode(), directory, CATALOG.encode(), 1) != 0:
                        raise OSError()
                else:
                    os.replace(temporary, CATALOG, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            except (OSError, AttributeError):
                raise ApiError(503, 'account_save_unavailable_check_status') from None
            finally:
                if fd is not None: os.close(fd)
                with contextlib.suppress(OSError): os.unlink(temporary, dir_fd=directory)

    def _choose(self, protocol, account_id=None):
        provider_name(protocol)
        active = getattr(self.local, protocol, None)
        if account_id is None and active is not None:
            account_id = active.account_id
        with self.catalog_lock:
            records = [x for x in self._records() if x['protocol'] == protocol]
            if account_id is not None:
                identifier(account_id)
                records = [x for x in records if x['id'] == account_id]
            elif len(records) > 1:
                raise ApiError(400, 'account_selection_required')
            if not records:
                raise ApiError(404 if account_id else 503, 'account_not_found' if account_id else 'provider_not_configured')
            return records[0]

    def load(self, provider, account_id=None):
        try:
            item = self._choose(provider, account_id)
        except ApiError as error:
            if account_id is None and error.code == 'provider_not_configured': return None
            raise
        try: profile = self.catalog.selected(item['profile_id'], provider)
        except ValueError: profile = None
        return Snapshot(item['revision'], item['username'], item['app_password'], item['sender_email'],
                        profile is not None and profile.fingerprint == item['profile_fingerprint'],
                        item['id'], item['profile_id'], tuple(item['capabilities']))

    @contextlib.contextmanager
    def guarded(self, provider, account_id=None):
        provider_name(provider)
        if account_id is None:
            active = getattr(self.local, provider, None)
            account_id = active.account_id if active else None
        with self.catalog_lock:
            if account_id is None and self._state() is None:
                # Legacy saves and reads must share the same virtual-account lock,
                # including the first save before a protocol file exists.
                account_id = hashlib.sha256(('single-v2:' + provider).encode()).hexdigest()[:24]
            key = account_id or provider
            lock = self.account_locks.setdefault(key, threading.RLock())
        if not lock.acquire(blocking=False):
            raise ApiError(409, 'provider_busy_try_again')
        try: yield
        finally: lock.release()

    @contextlib.contextmanager
    def operation(self, provider, account_id=None):
        selected = self._choose(provider, account_id)
        with self.guarded(provider, selected['id']):
            snapshot = self.load(provider, selected['id'])
            if not snapshot.profile_matches:
                raise ApiError(503, 'provider_profile_changed_reenter_credentials')
            old = getattr(self.local, provider, None)
            setattr(self.local, provider, snapshot)
            try: yield snapshot
            finally: setattr(self.local, provider, old)

    def pair(self, provider):
        snapshot = getattr(self.local, provider, None) or self.load(provider)
        if snapshot is None or not snapshot.profile_matches:
            raise ApiError(503, 'provider_not_configured')
        return snapshot.username, snapshot.password

    def revision(self, provider):
        snapshot = getattr(self.local, provider, None) or self.load(provider)
        return snapshot.revision if snapshot else None

    def account_id(self, provider):
        snapshot = getattr(self.local, provider, None) or self.load(provider)
        return snapshot.account_id if snapshot else None

    def status(self, revisions=False):
        result = {}
        for protocol in CAPABILITIES:
            try:
                with self.catalog_lock: records = [x for x in self._records() if x['protocol'] == protocol]
                states = [self.load(protocol, x['id']) for x in records]
                item = {'configured': any(x.profile_matches for x in states), 'error': None}
                if any(not x.profile_matches for x in states): item['error'] = 'provider_profile_changed_reenter_credentials'
                if revisions: item['revision'] = states[0].revision if len(states) == 1 else None
            except ApiError:
                item = {'configured': False, 'error': 'account_storage_unavailable'}
                if revisions: item['revision'] = None
            result[protocol] = item
        return result

    def inventory(self, owner=False):
        with self.catalog_lock:
            result = []
            for item in self._records():
                protocol, profile_id = item['protocol'], item['profile_id']
                snapshot = self.load(protocol, item['id'])
                row = {'id': item['id'], 'protocol': protocol, 'profile_id': profile_id, 'label': item['label'],
                       'provider': self.catalog.entries[profile_id][1] if profile_id in self.catalog.entries else 'Profil nicht verfügbar',
                       'capabilities': list(snapshot.capabilities), 'configured': snapshot.profile_matches,
                       'connection': item['connection'] if snapshot.profile_matches else {'state': 'profile_changed', 'checked_at': None},
                       'data_trust': 'untrusted'}
                if owner: row.update(revision=item['revision'], username=item['username'], sender_email=item['sender_email'])
                result.append(row)
            return result

    def persist(self, *args, **kwargs):
        protocol = args[0] if args else kwargs.get('provider')
        with self.guarded(protocol):
            with self.catalog_lock:
                if self._state() is not None:
                    raise ApiError(409, 'multi_account_ui_required')
                return super().persist(*args, **kwargs)

    def migration_required(self):
        with self.catalog_lock:
            return self._state() is None and bool(self._legacy_records())

    def candidate(self, data):
        protocol = provider_name(data.get('provider'))
        key = data.get('account_id')
        old = self._choose(protocol, identifier(key)) if key is not None else None
        if data.get('expected_revision') != (old['revision'] if old else None):
            raise ApiError(409, 'account_changed_reload_form')
        try: profile = self.catalog.selected(data.get('profile_id'), protocol)
        except ValueError: raise ApiError(400, 'unsupported_provider_profile') from None
        password = data.get('app_password')
        if password is None and old:
            if old['profile_id'] != data['profile_id'] or old['profile_fingerprint'] != profile.fingerprint:
                raise ApiError(400, 'profile_change_requires_password')
            password = old['app_password']
        username, password = credentials(data.get('username'), password)
        sender = sender_address(data.get('sender_email')) if protocol == 'mail' else None
        if protocol != 'mail' and data.get('sender_email') is not None:
            raise ApiError(400, 'invalid_account_input')
        return {'id': old['id'] if old else None, 'protocol': protocol, 'profile_id': data['profile_id'],
                'profile_fingerprint': profile.fingerprint, 'revision': old['revision'] if old else None,
                'username': username, 'app_password': password, 'sender_email': sender,
                'label': label(data.get('label')), 'capabilities': capabilities(protocol, data.get('capabilities'))}

    def save_candidate(self, candidate, new_id, expected_revision, checked_at):
        with self.catalog_lock:
            state = self._mutable_state()
            old = next((x for x in state['accounts'] if x['id'] == candidate['id']), None) if candidate['id'] else None
            if (old['revision'] if old else None) != expected_revision or candidate['id'] is not None and old is None:
                raise ApiError(409, 'account_changed_reload_form')
            if old is None and len(state['accounts']) >= MAX_ACCOUNTS:
                raise ApiError(400, 'account_capacity_reached')
            key = old['id'] if old else identifier(new_id)
            if old is None and any(x['id'] == key for x in state['accounts']):
                raise ApiError(409, 'account_changed_reload_form')
            revision = hashlib.sha256((key + ':' + secrets.token_hex(12) + ':' + candidate['profile_fingerprint']).encode()).hexdigest()[:24]
            saved = {**candidate, 'id': key, 'revision': revision, 'connection': {'state': 'connected', 'checked_at': checked_at}}
            state['accounts'] = [x for x in state['accounts'] if x['id'] != key] + [saved]
            self._write_state(state, state['generation'])
            return {'saved': True, 'account_id': key, 'revision': revision, 'connection_verified': True}, expected_revision

    def remove(self, protocol, key, expected_revision):
        with self.catalog_lock:
            state = self._mutable_state()
            old = next((x for x in state['accounts'] if x['id'] == identifier(key) and x['protocol'] == protocol), None)
            if not old or old['revision'] != expected_revision:
                raise ApiError(409, 'account_changed_reload_form')
            state['accounts'] = [x for x in state['accounts'] if x['id'] != key]
            self._write_state(state, state['generation'])
            return old['revision']

    def record_check(self, protocol, key, expected_revision, connected):
        with self.catalog_lock:
            state = self._mutable_state()
            row = next((x for x in state['accounts'] if x['id'] == key and x['protocol'] == protocol), None)
            if not row or row['revision'] != expected_revision:
                raise ApiError(409, 'account_changed_reload_form')
            row['connection'] = {'state': 'connected' if connected else 'failed', 'checked_at': self.clock()}
            self._write_state(state, state['generation'])

    def migrate_single_accounts(self):
        with self.catalog_lock:
            existing = self._state()
            if existing is not None: return {'migrated': False, 'already_current': True, 'accounts': len(existing['accounts'])}
            records = self._legacy_records()
            if any(not self.load(x['protocol'], x['id']).profile_matches for x in records):
                raise ApiError(409, 'provider_profile_changed_reenter_credentials')
            self._write_state({'version': 3, 'generation': None, 'accounts': records}, None)
            return {'migrated': True, 'accounts': len(records), 'identity_changed': False,
                    'consent_revisions_preserved': True, 'scopes_changed': False}
