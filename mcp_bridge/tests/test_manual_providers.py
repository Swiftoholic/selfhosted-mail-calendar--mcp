"""Manual owner endpoints: exact proofs, isolated routing and network rejection."""
import copy
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from bridge.app import ApiError
from bridge.providers import DEFAULT_PROFILES, MANUAL_IDS, ProviderCatalog, manual_profile, parse_profiles
from mcp_bridge.accounts import AccountSecrets, ConnectionChecks
from mcp_bridge.tests import test_multi_accounts as account_tests
from mcp_bridge.tests import test_multi_protocols as protocol_tests
from mcp_bridge.tests.multi_fixtures import MemoryAccounts, SyntheticChecks
from mcp_bridge.account_management import AccountManagement
from mcp_bridge.operations import Operations
from mcp_bridge.tests.multi_fixtures import synthetic_store

form = account_tests.form


def config(protocol='mail', suffix=''):
    if protocol == 'mail':
        return {'preset': 'custom', 'imap': {'host': 'imap' + suffix + '.example.test', 'port': 993, 'tls': 'implicit'},
                'smtp': {'host': 'smtp' + suffix + '.example.test', 'port': 587, 'tls': 'starttls_required'}}
    host = ('calendar' if protocol == 'caldav' else 'contacts') + suffix + '.example.test'
    return {'preset': 'custom', 'origin': 'https://' + host + '/dav/', 'allowed_hosts': [host]}


def manual_form(protocol='mail', suffix='', row=None):
    return {**form(protocol, row), 'profile_id': MANUAL_IDS[protocol], 'server_config': config(protocol, suffix)}


class ManualProfiles(unittest.TestCase):
    def test_each_protocol_has_immutable_profile_and_fresh_canonical_config(self):
        for protocol in MANUAL_IDS:
            value = config(protocol)
            profile, canonical = manual_profile(protocol, value)
            self.assertEqual(canonical, value); self.assertIsNot(canonical, value)
            value.clear()
            self.assertTrue(profile.fingerprint)
            self.assertEqual(canonical['preset'], 'custom')

    def test_ip_literals_local_names_proxy_auth_and_unsafe_tls_rejected(self):
        for host in ('localhost', '127.0.0.1', '10.0.0.7', '[::1]', 'server.local', 'server.internal',
                     'router.home.arpa', '0177.0.0.1', '2130706433', '*.example.test', 'user@public.example.test'):
            value = config(); value['imap']['host'] = host
            with self.subTest(kind='host'), self.assertRaises(ValueError): manual_profile('mail', value)
        for slot, key, value in [('imap', 'port', 143), ('imap', 'tls', 'starttls'), ('smtp', 'port', 25),
                                  ('smtp', 'tls', 'optional'), ('smtp', 'port', True)]:
            bad = config(); bad[slot][key] = value
            with self.subTest(kind='tls_port'), self.assertRaises(ValueError): manual_profile('mail', bad)
        for key in ('skip_tls', 'ca_file', 'password', 'proxy', 'access_token'):
            bad = config('caldav'); bad[key] = 'SYNTHETIC_ONLY'
            with self.assertRaises(ValueError): manual_profile('caldav', bad)

    def test_dav_url_exact_host_scope_and_safe_ports(self):
        for origin in ['http://calendar.example.test/dav/', 'https://calendar.example.test:80/dav/',
                       'https://user:password@calendar.example.test/dav/', 'https://calendar.example.test/dav/?x=1',
                       'https://calendar.example.test/dav/#x', 'https://calendar.example.test/dav/%2e%2e/',
                       'https://calendar.example.test/dav/%252f/', 'https://calendar.example.test/dav/../',
                       'https://127.0.0.1/dav/', 'https://calendar.example.test/dav/%2felse/']:
            bad = config('caldav'); bad['origin'] = origin
            with self.subTest(kind='url'), self.assertRaises(ValueError): manual_profile('caldav', bad)
        bad = config('carddav'); bad['allowed_hosts'].append('other.example.test')
        with self.assertRaises(ValueError): manual_profile('carddav', bad)
        good = config('caldav'); good['origin'] = 'https://calendar.example.test:8443/dav/'
        profile, _ = manual_profile('caldav', good)
        self.assertEqual(profile.port, 8443)
        with self.assertRaises(ValueError): profile.validate_url('https://other.example.test:8443/dav/')
        with self.assertRaises(ValueError): profile.validate_url('https://calendar.example.test/dav/')

    def test_templates_keep_legacy_fingerprints_and_protocol_auth_boundaries(self):
        catalog = ProviderCatalog()
        for protocol in MANUAL_IDS: self.assertEqual(catalog.get(protocol), DEFAULT_PROFILES.get(protocol))
        choices = {x['id']: x for x in catalog.choices()}
        for protocol in MANUAL_IDS: self.assertTrue(choices[MANUAL_IDS[protocol]]['manual'])
        self.assertFalse(choices['microsoft-mail']['supported'])
        self.assertFalse(choices['google-caldav']['supported'])
        self.assertFalse(choices['google-carddav']['supported'])
        self.assertEqual(choices['google-mail']['auth_mode'], 'conditional_app_password')
        self.assertFalse(choices['posteo-mail']['supported'])
        self.assertNotIn('yahoo-carddav', choices)
        self.assertNotIn('gmx-com-caldav', choices)
        for key in ('manual:mail', 'gmx-mail', 'icloud-caldav', 'icloud-carddav'):
            with self.assertRaises(ValueError):
                parse_profiles({'version': 2, 'profiles': {key: {'protocol': 'mail', 'name': 'Reserved', 'config': config()}},
                                'defaults': {'mail': key, 'caldav': 'icloud-caldav', 'carddav': 'icloud-carddav'}})

    def test_formerly_valid_operator_ids_keep_transport_metadata_and_unique_choices(self):
        for key, protocol in [('fastmail-mail', 'mail'), ('microsoft-mail', 'mail'), ('manual-mail', 'mail'),
                              ('google-mail', 'mail'), ('posteo-mail', 'mail'), ('google-caldav', 'caldav')]:
            defaults = {'mail': 'gmx-mail', 'caldav': 'icloud-caldav', 'carddav': 'icloud-carddav'}
            defaults[protocol] = key
            catalog = parse_profiles({'version': 2, 'profiles': {key: {'protocol': protocol, 'name': 'Existing operator', 'config': config(protocol)}},
                                      'defaults': defaults})
            self.assertEqual(catalog.get(protocol), manual_profile(protocol, config(protocol))[0])
            self.assertFalse(catalog.oauth_only(key))
            choices = [choice for choice in catalog.choices() if choice['id'] == key]
            self.assertEqual(len(choices), 1)
            self.assertEqual(choices[0]['info_key'], 'provider.operator')
            self.assertEqual(choices[0]['source_urls'], [])
            self.assertTrue(choices[0]['supported']); self.assertNotIn('verification', choices[0])
            self.assertTrue(any(choice['id'] == MANUAL_IDS['mail'] and choice['manual'] for choice in catalog.choices()))


class ManualAccounts(unittest.TestCase):
    setUp = account_tests.CatalogTests.setUp
    tearDown = account_tests.CatalogTests.tearDown
    check = account_tests.CatalogTests.check
    save = account_tests.CatalogTests.save
    def test_manual_two_accounts_route_separately_without_global_catalog_mutation(self):
        rows = []
        for suffix in ('', '2'):
            data = manual_form(suffix=suffix)
            rows.append(self.save(data, self.check(data)))
        self.assertEqual(self.accounts.catalog.get('mail'), DEFAULT_PROFILES.mail)
        for suffix, row in zip(('', '2'), rows):
            with self.accounts.operation('mail', row['account_id']) as snapshot:
                self.assertEqual(self.accounts.profiles.mail.imap_host, 'imap' + suffix + '.example.test')
                self.assertEqual(snapshot.profile_id, MANUAL_IDS['mail'])
        self.assertNotEqual(rows[0]['revision'], rows[1]['revision'])
        public = self.accounts.inventory()
        self.assertTrue(all('server_config' not in row and 'username' not in row for row in public))
        self.assertNotIn('SYNTHETIC_ONLY', json.dumps(public))

    def test_existing_operator_catalog_records_with_new_template_names_are_not_reinterpreted(self):
        for key, protocol in [('fastmail-mail', 'mail'), ('microsoft-mail', 'mail'), ('manual-mail', 'mail'), ('google-caldav', 'caldav')]:
            defaults = {'mail': 'gmx-mail', 'caldav': 'icloud-caldav', 'carddav': 'icloud-carddav'}
            defaults[protocol] = key
            self.accounts = MemoryAccounts(profiles=parse_profiles({'version': 2,
                'profiles': {key: {'protocol': protocol, 'name': 'Existing', 'config': config(protocol)}}, 'defaults': defaults}))
            self.manager = AccountManagement(self.accounts, self.store, self.checks)
            data = form(protocol); data['profile_id'] = key
            result = self.save(data, self.check(data))
            self.assertNotIn('server_config', self.accounts.inventory(owner=True)[0])
            with self.accounts.operation(protocol, result['account_id']) as snapshot:
                self.assertTrue(snapshot.profile_matches)
                self.assertEqual(self.accounts.profiles.get(protocol), manual_profile(protocol, config(protocol))[0])

    def test_endpoint_change_invalidates_proof_even_with_same_profile_id(self):
        for protocol in MANUAL_IDS:
            data = manual_form(protocol); proof = self.check(data)
            changed = {**data, 'server_config': config(protocol, '2')}
            with self.assertRaises(ApiError) as caught: self.save(changed, proof)
            self.assertEqual(caught.exception.code, 'connection_check_required_or_changed')
        self.assertEqual(self.accounts.inventory(), [])

    def test_smtp_host_tls_pair_or_dav_port_change_invalidates_check_proof(self):
        mutations = []
        smtp_host = config(); smtp_host['smtp']['host'] = 'outgoing.example.test'
        mutations.append(('mail', smtp_host))
        smtp_tls = config(); smtp_tls['smtp'].update(port=465, tls='implicit')
        mutations.append(('mail', smtp_tls))
        dav_port = config('caldav'); dav_port['origin'] = 'https://calendar.example.test:8443/dav/'
        mutations.append(('caldav', dav_port))
        for protocol, value in mutations:
            data = manual_form(protocol); proof = self.check(data)
            with self.assertRaises(ApiError) as caught: self.save({**data, 'server_config': value}, proof)
            self.assertEqual(caught.exception.code, 'connection_check_required_or_changed')

    def test_endpoint_edit_retires_calendar_and_addressbook_consents(self):
        for protocol in ('caldav', 'carddav'):
            data = manual_form(protocol); result = self.save(data, self.check(data))
            row = next(x for x in self.accounts.inventory(owner=True) if x['id'] == result['account_id'])
            if protocol == 'caldav': self.store.set_calendar_consent(row['revision'], 'a' * 24, True)
            else: self.store.set_contacts_consent(row['revision'], 'a' * 24)
            edit = manual_form(protocol, '2', row)
            edit['app_password'] = 'SYNTHETIC_CHANGED_PASSWORD'
            self.save(edit, self.check(edit))
            consent = (self.store.calendar_consent if protocol == 'caldav' else self.store.contacts_consent)
            self.assertIsNone(consent(row['revision'], 'a' * 24))


    def test_edit_same_endpoint_retains_secret_changed_endpoint_requires_reentry(self):
        for protocol in MANUAL_IDS:
            data = manual_form(protocol); result = self.save(data, self.check(data))
            row = next(x for x in self.accounts.inventory(owner=True) if x['id'] == result['account_id'])
            edit = manual_form(protocol, row=row)
            candidate = self.accounts.candidate(edit)
            self.assertEqual(candidate['app_password'], 'SYNTHETIC_ONLY_NOT_A_PASSWORD')
            candidate.clear()
            edit['server_config'] = config(protocol, '2')
            with self.assertRaises(ApiError) as caught: self.check(edit)
            self.assertEqual(caught.exception.code, 'profile_change_requires_password')
            edit['app_password'] = 'SYNTHETIC_CHANGED_PASSWORD'
            new = self.save(edit, self.check(edit))
            self.assertEqual(new['account_id'], row['id']); self.assertNotEqual(new['revision'], row['revision'])
            with self.assertRaises(ApiError): self.check(manual_form(protocol, row=row))

    def test_saved_manual_catalog_rejects_malformed_or_cross_protocol_config(self):
        data = manual_form(); self.save(data, self.check(data))
        saved = copy.deepcopy(self.accounts.memory)
        for mutation in ('host', 'protocol', 'missing'):
            invalid = copy.deepcopy(saved)
            record = invalid['accounts'][0]
            if mutation == 'host': record['server_config']['imap']['host'] = '127.0.0.1'
            elif mutation == 'protocol': record['profile_id'] = MANUAL_IDS['caldav']
            else: record.pop('server_config')
            with self.assertRaises(ApiError): self.accounts._validate_catalog(invalid)

    def test_oauth_only_and_unverified_templates_never_attempt_password_auth(self):
        for protocol, key, code in [('mail', 'microsoft-mail', 'provider_oauth_not_supported'),
                                    ('caldav', 'google-caldav', 'provider_oauth_not_supported'),
                                    ('carddav', 'google-carddav', 'provider_oauth_not_supported'),
                                    ('mail', 'posteo-mail', 'unsupported_provider_profile')]:
            data = form(protocol); data['profile_id'] = key
            with self.assertRaises(ApiError) as caught: self.check(data)
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(self.checks.calls, [])

    def test_manual_real_transport_rejects_private_or_mixed_dns_before_socket_auth_or_save(self):
        self.manager.checks = ConnectionChecks()
        for protocol in MANUAL_IDS:
            port = 993 if protocol == 'mail' else 443
            private = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('127.0.0.1', port))
            public = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('8.8.8.8', port))
            for answers in ([private], [public, private]):
                with patch('bridge.network.socket.getaddrinfo', return_value=answers), patch('bridge.network.socket.socket') as dial:
                    with self.assertRaises(ApiError) as caught: self.check(manual_form(protocol))
                    self.assertEqual(caught.exception.code, 'connection_check_failed'); dial.assert_not_called()
        self.assertEqual(self.accounts.inventory(), [])


class ManualProtocolTests(protocol_tests.MultiProtocolTests):
    """Existing adapter TLS/read/preview/commit tests with manual account profiles."""
    def setUp(self):
        super().setUp()
        self.accounts = MemoryAccounts()
        self.backend = Operations(self.store, self.accounts)
        self.rows = {}
        manager = AccountManagement(self.accounts, self.store, SyntheticChecks())
        rights = {'mail': ['mail:read', 'mail:send'], 'caldav': ['calendars:read', 'calendars:write'], 'carddav': ['contacts:read']}
        for protocol in MANUAL_IDS:
            for suffix in ('', '2'):
                data = manual_form(protocol, suffix)
                data.update(username=protocol + suffix + '@example.invalid', capabilities=rights[protocol])
                if protocol == 'mail': data['sender_email'] = 'sender' + suffix + '@example.invalid'
                else: data['server_config']['origin'] = data['server_config']['origin'].replace('/dav/', '/')
                proof = manager.action('check', data, lambda: None, 'synthetic-csrf')
                saved = manager.action('save', {**data, 'check_id': proof['check_id'], 'persistent_storage_confirmed': True}, lambda: None, 'synthetic-csrf')
                self.rows[protocol + suffix] = next(row for row in self.accounts.inventory(owner=True) if row['id'] == saved['account_id'])


class ManualHTTPTests(account_tests.HTTPTests):
    def test_manual_owner_http_requires_recent_passkey_csrf_exact_origin_and_json(self):
        data = manual_form()
        self.assertEqual(self.post_manage('check', data).status_code, 401)
        self.enroll()
        request = {**data, 'csrf': self.status()['csrf']}
        self.assertEqual(self.client.post('/accounts/manage/check', json={**request, 'csrf': 'bad'}).status_code, 403)
        self.assertEqual(self.client.post('/accounts/manage/check', json=request, headers={'Origin': 'https://attacker.invalid'}).status_code, 403)
        self.assertEqual(self.client.post('/accounts/manage/check', content=json.dumps(request), headers={'Content-Type': 'text/plain'}).status_code, 403)
        self.assertEqual(self.post_manage('check', {**data, 'skip_tls': True}).status_code, 400)
        self.assertEqual(self.post_manage('check', {**form(), 'server_config': config()}).status_code, 400)
        self.offset += 301
        self.assertEqual(self.post_manage('check', data).status_code, 401)
        self.assertEqual(self.checks.calls, [])

    def test_long_manual_url_fits_bounded_http_request_and_owner_only_inventory(self):
        self.enroll()
        data = manual_form('caldav')
        data['server_config']['origin'] = 'https://calendar.example.test/' + 'a' * 2010
        checked = self.post_manage('check', data)
        self.assertEqual(checked.status_code, 200)
        changed = {**data, 'server_config': config('caldav', '2')}
        self.assertEqual(self.post_manage('save', {**changed, 'check_id': checked.json()['check_id'], 'persistent_storage_confirmed': True}).status_code, 409)
        self.assertEqual(self.post_manage('save', {**data, 'check_id': checked.json()['check_id'], 'persistent_storage_confirmed': True}).status_code, 200)
        owner = self.client.get('/accounts/status').json()
        self.assertEqual(owner['items'][0]['server_config'], data['server_config'])
        self.assertNotIn('SYNTHETIC_ONLY', json.dumps(owner))
        self.assertNotIn('server_config', self.accounts.inventory()[0])
        self.assertEqual(self.client.post('/accounts/manage/check', content=' ' * 8193, headers={'Content-Type': 'application/json'}).status_code, 413)

    def test_mcp_cannot_supply_manual_endpoints_or_mutate_saved_configuration(self):
        self.accounts.seed('mail'); self.enroll()
        token = self.token(scope='bridge:read mail:read')
        before = copy.deepcopy(self.accounts.memory)
        with patch('bridge.network.public_socket') as dial:
            response = self.rpc(token, 'tools/call', {'name': 'mail_folders', 'arguments': {'server_config': config()}})
            result = response.json()['result']
        self.assertTrue(result.get('isError')); dial.assert_not_called()
        self.assertEqual(self.accounts.memory, before)


@unittest.skipUnless(os.name == 'posix', 'Private manual catalog UID/mode/atomic checks require Linux.')
class ManualLinuxStorage(unittest.TestCase):
    def test_manual_records_survive_private_atomic_catalog_reload(self):
        with tempfile.TemporaryDirectory() as folder:
            accounts = AccountSecrets(folder)
            accounts.migrate_single_accounts()
            store, temporary = synthetic_store(lambda: 1000)
            try:
                manager = AccountManagement(accounts, store, SyntheticChecks())
                for protocol in MANUAL_IDS:
                    data = manual_form(protocol)
                    proof = manager.action('check', data, lambda: None, 'synthetic-csrf')
                    manager.action('save', {**data, 'check_id': proof['check_id'], 'persistent_storage_confirmed': True}, lambda: None, 'synthetic-csrf')
                path = Path(folder) / 'accounts.json'
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.stat().st_uid, os.getuid())
                fresh = AccountSecrets(folder)
                self.assertEqual(len(fresh.inventory()), 3)
                for protocol in MANUAL_IDS:
                    with fresh.operation(protocol) as snapshot:
                        self.assertTrue(snapshot.profile_matches)
                        self.assertEqual(fresh.profiles.get(protocol), manual_profile(protocol, config(protocol))[0])
            finally:
                store.close(); temporary.cleanup()


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for kind in (ManualProfiles, ManualAccounts, ManualProtocolTests, ManualLinuxStorage):
        suite.addTests(loader.loadTestsFromTestCase(kind))
    # Reuse HTTP fixture helpers without repeating unrelated inherited suites.
    for name in ManualHTTPTests.__dict__:
        if name.startswith('test_'): suite.addTest(ManualHTTPTests(name))
    return suite
