"""Synthetic-only local test storage; never a runtime storage/auth bypass."""
import copy
import os
from pathlib import Path
import secrets
import stat
import tempfile
from unittest.mock import patch

from bridge.app import ApiError
from bridge.providers import DEFAULT_PROFILES
from mcp_bridge.multi_accounts import MultiAccountSecrets
from mcp_bridge.store import Store


class MemoryAccounts(MultiAccountSecrets):
    def __init__(self, profiles=DEFAULT_PROFILES, clock=lambda: 1000, legacy=None):
        super().__init__('synthetic-not-a-runtime-directory', profiles=profiles, clock=clock)
        self.memory = None if legacy is not None else {'version': 3, 'generation': secrets.token_hex(12), 'accounts': []}
        self.legacy = copy.deepcopy(legacy or [])
        self.fail_before_write = False
        self.fail_after_write = False

    def _read_file(self, name, maximum=65536):
        return copy.deepcopy(self.memory)

    def _legacy_records(self):
        return copy.deepcopy(self.legacy)

    def _write_state(self, value, expected_generation):
        if (self.memory['generation'] if self.memory else None) != expected_generation:
            raise ApiError(409, 'account_catalog_changed_reload')
        saved = copy.deepcopy({**value, 'generation': secrets.token_hex(12)})
        self._validate_catalog(saved)
        if self.fail_before_write:
            raise ApiError(503, 'account_save_unavailable_check_status')
        self.memory = saved
        if self.fail_after_write:
            raise ApiError(503, 'account_save_unavailable_check_status')

    def seed(self, protocol, username='synthetic@example.invalid', rights=None, profile_id=None, sender=None):
        data = {'provider': protocol, 'account_id': None, 'expected_revision': None,
                'profile_id': profile_id or self.catalog.defaults[protocol], 'label': 'Synthetic account',
                'username': username, 'app_password': 'SYNTHETIC_ONLY_NOT_A_PASSWORD',
                'sender_email': sender or username if protocol == 'mail' else None,
                'capabilities': list(rights or [])}
        candidate = self.candidate(data)
        saved, _ = self.save_candidate(candidate, secrets.token_hex(12), None, self.clock())
        return next(row for row in self.inventory(owner=True) if row['id'] == saved['account_id'])


def synthetic_store(clock=lambda: 1000):
    """Actual SQLite/Store logic, disposable fixture only. Runtime remains Linux.

    Windows cannot implement the POSIX UID/mode guard. Only Store construction
    in this fixture gets equivalent synthetic metadata; no application network
    code or private account file protection is overridden.
    """
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name)
    if os.name == 'posix':
        return Store(root / 'identity.sqlite3', clock=clock), temporary
    original = Path.stat
    def fixture_stat(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == root:
            result = os.stat_result((stat.S_IFDIR | 0o700, *result[1:]))
        return result
    with patch.object(os, 'getuid', create=True, return_value=root.stat().st_uid), patch.object(Path, 'stat', new=fixture_stat):
        store = Store(root / 'identity.sqlite3', clock=clock)
    return store, temporary


class SyntheticChecks:
    def __init__(self):
        self.calls = []
        self.fail = False
        self.callback = None

    def check(self, protocol, username, password, *, profiles=None):
        self.calls.append((protocol, username, password, profiles.get(protocol)))
        if self.callback: self.callback()
        if self.fail: raise ApiError(502, 'connection_check_failed')
        return {'connected': True, 'provider_data_changed': False, 'credentials_saved': False}
