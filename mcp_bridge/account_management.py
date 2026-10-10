"""Recent-owner account administration; tests are bound to input and session."""
import hashlib
import hmac
import json
import secrets

from bridge.app import ApiError
from bridge.providers import ProviderProfiles
from .accounts import provider_name
from .multi_accounts import identifier

INPUT_FIELDS = {'provider', 'account_id', 'expected_revision', 'profile_id', 'label',
                'username', 'app_password', 'sender_email', 'capabilities'}


class AccountManagement:
    def __init__(self, accounts, store, checks):
        self.accounts, self.store, self.checks = accounts, store, checks

    def fingerprint(self, candidate):
        raw = json.dumps(candidate, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
        # A keyed digest of credentials is never returned or logged.
        return hmac.new(self.store.owner.encode('ascii'), raw, hashlib.sha256).hexdigest()

    def profiles(self, candidate):
        values = {protocol: self.accounts.catalog.get(protocol) for protocol in ('mail', 'caldav', 'carddav')}
        values[candidate['protocol']] = self.accounts.profile_for(candidate)
        return ProviderProfiles(**values)

    def retire(self, protocol, revision):
        if revision is None: return
        if protocol == 'caldav': self.store.clear_calendar_consents(revision)
        elif protocol == 'carddav': self.store.clear_contacts_consents(revision)
        else: self.store.invalidate_mail_previews(revision)

    def action(self, action, data, authorize, csrf):
        if action not in {'check', 'save', 'retest', 'remove'}:
            raise ApiError(404, 'account_action_not_found')
        expected = (INPUT_FIELDS | ({'check_id', 'persistent_storage_confirmed'} if action == 'save' else set())
                    if action in {'check', 'save'} else {'provider', 'account_id', 'expected_revision'} |
                    ({'integration_removal_confirmed'} if action == 'remove' else set()))
        # Existing preset clients remain compatible; only the recent owner can
        # supply the optional endpoint field. It is never accepted by MCP tools.
        if set(data) != expected and not (action in {'check', 'save'} and set(data) == expected | {'server_config'}):
            raise ApiError(400, 'invalid_account_request')
        protocol = provider_name(data['provider'])
        key = data['account_id']
        if key is not None: identifier(key)
        if action in {'retest', 'remove'} and key is None:
            raise ApiError(400, 'invalid_account_id')
        candidate = None
        with self.accounts.guarded(protocol, key):
            with self.store.lock: authorize()
            try:
                if action in {'check', 'save'}:
                    candidate = self.accounts.candidate(data)
                    fingerprint = self.fingerprint(candidate)
                    session = hashlib.sha256(csrf.encode('ascii')).hexdigest()
                    if action == 'check':
                        self.checks.check(protocol, candidate['username'], candidate['app_password'], profiles=self.profiles(candidate))
                        with self.accounts.catalog_lock, self.store.transaction():
                            authorize()
                            # CAS after network I/O: a stale tested form cannot become saveable.
                            current = self.accounts.candidate(data)
                            try:
                                if self.fingerprint(current) != fingerprint:
                                    raise ApiError(409, 'account_changed_reload_form')
                            finally:
                                current.clear()
                            proof = secrets.token_hex(12)
                            self.store.put('account_check', proof, {'fingerprint': fingerprint, 'session': session,
                                           'new_id': secrets.token_hex(12), 'checked_at': self.store.clock()}, 300, maximum=32)
                        return {'connected': True, 'check_id': proof, 'expires_in': 300,
                                'credentials_saved': False, 'provider_data_changed': False, 'mail_sent': False}
                    if data['persistent_storage_confirmed'] is not True:
                        raise ApiError(400, 'persistent_storage_confirmation_required')
                    with self.accounts.catalog_lock, self.store.transaction():
                        authorize()
                        proof_key = identifier(data['check_id'])
                        proof = self.store.get('account_check', proof_key)
                        if (not proof or proof['session'] != session or
                                not hmac.compare_digest(proof['fingerprint'], fingerprint)):
                            raise ApiError(409, 'connection_check_required_or_changed')
                        result, old_revision = self.accounts.save_candidate(candidate, proof['new_id'], data['expected_revision'], proof['checked_at'])
                        self.retire(protocol, old_revision)
                        self.store.delete('account_check', proof_key)
                        return {**result, 'provider_data_changed': False, 'stale_previews_invalidated': True}
                if action == 'remove':
                    if data['integration_removal_confirmed'] is not True:
                        raise ApiError(400, 'integration_removal_confirmation_required')
                    with self.accounts.catalog_lock, self.store.transaction():
                        authorize()
                        revision = self.accounts.remove(protocol, key, data['expected_revision'])
                        self.retire(protocol, revision)
                    return {'removed': True, 'account_id': key, 'provider_data_changed': False,
                            'stale_previews_invalidated': True}
                with self.accounts.operation(protocol, key) as snapshot:
                    if snapshot.revision != data['expected_revision']:
                        raise ApiError(409, 'account_changed_reload_form')
                    connected = True
                    try: self.checks.check(protocol, snapshot.username, snapshot.password, profiles=self.accounts.profiles)
                    except ApiError as error:
                        if error.code != 'connection_check_failed': raise
                        connected = False
                    with self.accounts.catalog_lock, self.store.lock:
                        authorize()
                        self.accounts.record_check(protocol, key, snapshot.revision, connected)
                    return {'connected': connected, 'account_id': key, 'credentials_saved': False,
                            'provider_data_changed': False, 'mail_sent': False}
            finally:
                if candidate is not None: candidate.clear()
