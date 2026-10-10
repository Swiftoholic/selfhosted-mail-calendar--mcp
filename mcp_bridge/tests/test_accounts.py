"""Synthetic credentials only, ephemeral private directories, no network."""
import contextlib
import json
import os
import ssl
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from starlette.testclient import TestClient
from bridge.app import ApiError, calendar_id
from mcp_bridge.accounts import AccountSecrets, ConnectionChecks, bind_id, connection_status, credentials
from mcp_bridge.calendar_ops import CalendarOperations
from mcp_bridge.config import ORIGIN
from mcp_bridge.mail_ops import MailOperations, folder_id
from mcp_bridge.operations import Operations
from mcp_bridge.server import create_app
from mcp_bridge.store import Store
from mcp_bridge.tests.test_security import FixtureCIMD, SecurityTests
from mcp_bridge.tests.test_writes import IMAPFixture, SMTPFixture, DAVFixture, CALENDAR, OBJECT

USER = 'synthetic-owner@example.invalid'
PASSWORD = 'SYNTHETIC_ONLY_NO_ACCESS_0001'
NEW_PASSWORD = 'SYNTHETIC_ONLY_NO_ACCESS_0002'


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.secrets = AccountSecrets(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def saved(self, provider='mail'):
        return self.secrets.persist(provider, USER, PASSWORD, None)

    def test_status_empty_has_no_secret_or_file_creation(self):
        status = connection_status(self.secrets)
        self.assertFalse(status['accounts']['mail']['configured'])
        self.assertNotIn('revision', status['accounts']['mail'])
        self.assertEqual(list(self.root.iterdir()), [])
        with self.assertRaises(ApiError): self.secrets.pair('mail')

    def test_atomic_pair_modes_and_fresh_read_without_restart(self):
        first = self.saved()
        self.assertEqual(self.secrets.pair('mail'), (USER, PASSWORD))
        self.assertEqual((self.root/'mail.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.root/'mail.json').stat().st_uid, os.getuid())
        second = self.secrets.persist('mail', USER, NEW_PASSWORD, first['revision'])
        self.assertNotEqual(first['revision'], second['revision'])
        self.assertEqual(self.secrets.pair('mail'), (USER, NEW_PASSWORD))
        self.assertEqual(len(list(self.root.iterdir())), 1)
        self.assertNotIn(PASSWORD, json.dumps(second))
        self.assertNotIn(USER, json.dumps(second))

    def test_stale_revision_cannot_overwrite_account(self):
        self.saved()
        with self.assertRaises(ApiError): self.secrets.persist('mail', USER, NEW_PASSWORD, None)
        self.assertEqual(self.secrets.pair('mail'), (USER, PASSWORD))

    def test_failed_replace_keeps_old_complete_pair_and_cleans_temp(self):
        first = self.saved()
        with patch('mcp_bridge.account_storage.os.replace', side_effect=OSError('synthetic failure')):
            with self.assertRaises(ApiError): self.secrets.persist('mail', USER, NEW_PASSWORD, first['revision'])
        self.assertEqual(self.secrets.pair('mail'), (USER, PASSWORD))
        self.assertEqual([path.name for path in self.root.iterdir()], ['mail.json'])

    def test_failed_file_fsync_cannot_replace_original(self):
        first = self.saved()
        with patch('mcp_bridge.account_storage.os.fsync', side_effect=OSError('synthetic failure')):
            with self.assertRaises(ApiError): self.secrets.persist('mail', USER, NEW_PASSWORD, first['revision'])
        self.assertEqual(self.secrets.pair('mail'), (USER, PASSWORD))

    def test_failed_directory_fsync_is_reported_uncertain_not_retried(self):
        first = self.saved(); original = os.fsync; calls = []
        def fsync(descriptor):
            calls.append(descriptor)
            if len(calls) == 2: raise OSError('synthetic directory failure')
            return original(descriptor)
        with patch('mcp_bridge.account_storage.os.fsync', side_effect=fsync):
            with self.assertRaises(ApiError) as caught: self.secrets.persist('mail', USER, NEW_PASSWORD, first['revision'])
        self.assertEqual(caught.exception.code, 'account_save_unavailable_check_status')
        self.assertTrue(self.secrets.status()['mail']['configured'])
        self.assertEqual(self.secrets.pair('mail'), (USER, NEW_PASSWORD))

    def test_symlink_secret_rejected_without_touching_target(self):
        target = self.root/'outside.txt'; target.write_text('synthetic sentinel')
        (self.root/'mail.json').symlink_to(target)
        with self.assertRaises(ApiError): self.saved()
        self.assertEqual(target.read_text(), 'synthetic sentinel')

    def test_symlink_directory_rejected(self):
        link = self.root/'linked'; link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ApiError): AccountSecrets(link).persist('mail', USER, PASSWORD, None)

    def test_world_readable_directory_or_file_rejected(self):
        self.root.chmod(0o755)
        with self.assertRaises(ApiError): self.saved()
        self.root.chmod(0o700); self.saved(); (self.root/'mail.json').chmod(0o644)
        with self.assertRaises(ApiError): self.secrets.pair('mail')

    def test_hardlink_or_malformed_file_rejected(self):
        self.saved(); os.link(self.root/'mail.json', self.root/'copy.json')
        with self.assertRaises(ApiError): self.secrets.pair('mail')
        (self.root/'copy.json').unlink(); (self.root/'mail.json').write_text('{malformed')
        with self.assertRaises(ApiError): self.secrets.pair('mail')

    def test_invalid_inputs_never_create_configuration(self):
        for username, password in ((USER, PASSWORD+'\n'), ('Display <'+USER+'>', PASSWORD), (USER, 'short'), ('a\r\nb@example.invalid', PASSWORD), (USER, 'x'*257)):
            with self.assertRaises(ApiError): credentials(username, password)
        for provider in ('smtp', '../gmx', 'https://attacker.invalid'):
            with self.assertRaises(ApiError): self.secrets.persist(provider, USER, PASSWORD, None)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_active_operation_blocks_account_change_but_other_provider_independent(self):
        first = self.saved()
        with self.secrets.operation('mail'):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self.secrets.persist, 'mail', USER, NEW_PASSWORD, first['revision'])
                with self.assertRaises(ApiError) as caught: future.result()
            self.assertEqual(caught.exception.code, 'provider_busy_try_again')
            self.assertEqual(self.secrets.pair('mail'), (USER, PASSWORD))
            self.secrets.persist('caldav', USER, PASSWORD, None)
        self.secrets.persist('mail', USER, NEW_PASSWORD, first['revision'])
        self.assertEqual(self.secrets.pair('mail'), (USER, NEW_PASSWORD))

    def test_concurrent_readers_only_see_complete_atomic_snapshots(self):
        self.saved()
        def update():
            for number in range(15):
                previous = self.secrets.load('mail')
                self.secrets.persist('mail', 'fixture'+str(number)+'@example.invalid', 'SYNTHETIC_ONLY_'+str(number), previous.revision)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(update)
            completed = 0
            for _ in range(70):
                try:
                    snapshot = self.secrets.load('mail')
                except ApiError as error:
                    # An atomic replacement may unlink an opened old inode
                    # before fstat. The existing privacy check rejects nlink=0;
                    # a raw reader can fail closed rather than return a pair.
                    self.assertEqual(error.status,503)
                    self.assertEqual(error.code,'account_storage_not_private')
                    continue
                completed += 1
                if snapshot.username != USER:
                    number = snapshot.username.split('@')[0].removeprefix('fixture')
                    self.assertEqual(snapshot.password, 'SYNTHETIC_ONLY_'+number)
            future.result()
        self.assertGreater(completed,0)
        final = self.secrets.load('mail')
        self.assertEqual((final.username,final.password),('fixture14@example.invalid','SYNTHETIC_ONLY_14'))

    def test_status_only_booleans_errors_and_fixed_setup_link(self):
        self.saved()
        value = connection_status(self.secrets)
        self.assertEqual(value['setup_url'], ORIGIN+'/accounts')
        self.assertEqual(value['accounts']['mail'], {'configured':True,'error':None})
        serialized = json.dumps(value)
        self.assertNotIn(USER, serialized); self.assertNotIn(PASSWORD, serialized); self.assertNotIn('revision', serialized)


class RevisionTests(StorageTests):
    def setUp(self):
        super().setUp()
        identity = self.root/'identity'; identity.mkdir(mode=0o700)
        directory = self.root/'accounts'; directory.mkdir(mode=0o700)
        self.secrets = AccountSecrets(directory); self.store = Store(identity/'identity.sqlite3')
        self.saved(); self.saved('caldav')
        self.store.set_calendar_consent(self.secrets.revision('caldav'), calendar_id(CALENDAR), False)
        self.imap, self.smtp, self.dav = IMAPFixture(), SMTPFixture(), DAVFixture()
        self.backend = Operations(self.store, self.secrets, MailOperations(self.secrets,self.store,self.imap.factory,self.smtp.factory), CalendarOperations(self.secrets,self.store,self.dav.factory,self.dav.connection))

    def tearDown(self):
        self.store.close(); super().tearDown()

    def rotate(self, provider):
        self.secrets.persist(provider, USER, NEW_PASSWORD, self.secrets.revision(provider))

    def call(self, path, **data):
        return self.backend.call('POST', path, data)

    def test_mail_folder_ids_bound_and_old_ids_cannot_mutate_new_account(self):
        old = self.call('/mcp/mail/folders')['items'][0]['id']
        self.assertNotEqual(old, folder_id('INBOX'))
        self.assertEqual(bind_id(old,self.secrets.revision('mail'),'mailbox'), folder_id('INBOX'))
        self.rotate('mail')
        with self.assertRaises(ApiError): self.call('/mcp/mail/flags', mailbox_id=old,uid=7,uidvalidity=111,confirmed=True,read=True,idempotency_key='fixture-stale-folder-0001')
        self.assertFalse(any(row[0]=='STORE' for row in self.imap.commands))
        fresh = self.call('/mcp/mail/folders')['items'][0]['id']
        self.assertNotEqual(old,fresh)
        self.call('/mcp/mail/flags',mailbox_id=fresh,uid=7,uidvalidity=111,confirmed=True,read=True,idempotency_key='fixture-fresh-folder-0001')
        self.assertIn('\\Seen',self.imap.messages['INBOX'][7])

    def test_calendar_and_object_ids_cannot_cross_revision(self):
        old = self.call('/v1/calendars/list')['items'][0]['id']
        event = self.call('/v1/calendars/events',calendar_id=old,start='2026-10-10T00:00:00Z',end='2026-10-11T00:00:00Z')['items'][0]
        self.rotate('caldav')
        with self.assertRaises(ApiError): self.call('/mcp/calendar/prepare-delete',calendar_id=old,object_id=event['object_id'],etag=event['etag'])
        fresh = self.call('/v1/calendars/list')['items'][0]['id']
        with self.assertRaises(ApiError): self.call('/mcp/calendar/prepare-delete',calendar_id=fresh,object_id=event['object_id'],etag=event['etag'])
        self.assertEqual(self.dav.writes,[])

    def test_mail_preview_rejected_after_password_rotation_even_same_username(self):
        preview = self.call('/mcp/mail/prepare-send',to=['recipient@example.invalid'],subject='Synthetic',body='Synthetic only')
        self.rotate('mail')
        with self.assertRaises(ApiError): self.call('/mcp/mail/send',preview_id=preview['preview_id'],preview_hash=preview['preview_hash'],idempotency_key='fixture-stale-send-0001',confirmed=True)
        self.assertEqual(self.smtp.data_count,0)

    def test_calendar_preview_rejected_after_account_rotation(self):
        identifier = self.call('/v1/calendars/list')['items'][0]['id']
        preview = self.call('/mcp/calendar/prepare-create',calendar_id=identifier,summary='Synthetic',start='2026-10-10T12:00:00Z',end='2026-10-10T13:00:00Z')
        self.rotate('caldav')
        with self.assertRaises(ApiError): self.call('/mcp/calendar/commit',preview_id=preview['preview_id'],preview_hash=preview['preview_hash'],idempotency_key='fixture-stale-calendar-0001',confirmed=True)
        self.assertEqual(self.dav.writes,[])

    def test_config_change_preserves_receipts_and_prevents_reusing_key(self):
        identifier = self.call('/mcp/mail/folders')['items'][0]['id']
        args=dict(mailbox_id=identifier,uid=7,uidvalidity=111,confirmed=True,read=True,idempotency_key='fixture-preserved-receipt-0001')
        self.call('/mcp/mail/flags',**args)
        before=self.store.db.execute('SELECT count(*) FROM operations').fetchone()[0]
        self.rotate('mail'); args['mailbox_id']=self.call('/mcp/mail/folders')['items'][0]['id']
        with self.assertRaises(ValueError): self.call('/mcp/mail/flags',**args)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM operations').fetchone()[0],before)
        self.assertEqual(sum(row[0]=='STORE' for row in self.imap.commands),1)


class ChecksTests(unittest.TestCase):
    def test_gmx_checks_only_fixed_tls_authentication_no_mail(self):
        imap, smtp = IMAPFixture(), SMTPFixture(); endpoints=[]
        def imap_factory(host,port,ssl_context,timeout):
            endpoints.append((host,port)); self.assertTrue(ssl_context.check_hostname);self.assertEqual(ssl_context.verify_mode,ssl.CERT_REQUIRED);return imap
        def smtp_factory(host,port,context,timeout):
            endpoints.append((host,port));self.assertTrue(context.check_hostname);self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED);return smtp
        result=ConnectionChecks(imap_factory,smtp_factory).check('mail',USER,PASSWORD)
        self.assertEqual(endpoints,[('imap.gmx.net',993),('mail.gmx.net',465)])
        self.assertTrue(result['connected']);self.assertEqual(imap.commands,[]);self.assertEqual(smtp.data_count,0);self.assertEqual(smtp.rcpts,[])

    def test_icloud_check_only_discovery_no_events_or_writes(self):
        fixture=DAVFixture(); methods=[]; original=fixture.request
        def request(method,*args,**kwargs): methods.append(method);return original(method,*args,**kwargs)
        fixture.request=request
        result=ConnectionChecks(calendar=fixture.factory).check('caldav',USER,PASSWORD)
        self.assertTrue(result['connected']);self.assertTrue(methods);self.assertEqual(set(methods),{'PROPFIND'});self.assertEqual(fixture.writes,[])

    def test_provider_errors_are_generic_and_never_return_input(self):
        def rejected(*args,**kwargs):raise RuntimeError(USER+PASSWORD)
        with self.assertRaises(ApiError) as caught:ConnectionChecks(imap=rejected).check('mail',USER,PASSWORD)
        self.assertEqual(caught.exception.code,'connection_check_failed');self.assertNotIn(PASSWORD,str(caught.exception))


class HTTPTests(SecurityTests):
    def setUp(self):
        super().setUp();self.client.__exit__(None,None,None)
        directory=Path(self.temp.name)/'accounts';directory.mkdir(mode=0o700)
        self.accounts=AccountSecrets(directory);self.check_calls=[]
        outer=self
        class Checks:
            def check(self,provider,username,password):
                outer.check_calls.append(provider)
                return {'connected':True,'mail_sent':False,'provider_data_changed':False,'credentials_saved':False}
        self.app,self.identity,self.oauth=create_app(self.store,FixtureCIMD(),accounts=self.accounts,checks=Checks())
        self.client=TestClient(self.app,base_url=ORIGIN,headers={'Origin':ORIGIN},follow_redirects=False);self.client.__enter__()

    def post(self,action='save',**changes):
        data={'provider':'mail','username':USER,'app_password':PASSWORD,'csrf':self.status()['csrf']}
        if action=='save':data.update(expected_revision=None,persistent_storage_confirmed=True)
        data.update(changes)
        return self.client.post('/accounts/'+action,json=data)

    def test_unauthenticated_page_redirects_and_all_account_api_denied(self):
        self.assertEqual(self.client.get('/accounts').status_code,302)
        self.assertEqual(self.client.get('/accounts/status').status_code,401)
        self.assertEqual(self.post().status_code,401);self.assertEqual(self.post('check').status_code,401)
        self.assertEqual(self.check_calls,[])

    def test_oauth_token_without_owner_cookie_cannot_configure(self):
        self.enroll();token=self.token(scope='bridge:read')
        self.client.cookies.clear()
        result=self.client.post('/accounts/save',headers={'Authorization':'Bearer '+token},json={'provider':'mail','username':USER,'app_password':PASSWORD,'csrf':'synthetic','expected_revision':None,'persistent_storage_confirmed':True})
        self.assertEqual(result.status_code,401)
        self.assertFalse(self.accounts.status()['mail']['configured'])

    def test_oauth_header_even_with_owner_cookie_not_a_configuration_route(self):
        self.enroll();token=self.token(scope='bridge:read')
        result=self.client.post('/accounts/save',headers={'Authorization':'Bearer '+token},json={'provider':'mail','username':USER,'app_password':PASSWORD,'csrf':self.status()['csrf'],'expected_revision':None,'persistent_storage_confirmed':True})
        self.assertEqual(result.status_code,401)

    def test_recent_passkey_serves_empty_form_with_secure_headers(self):
        self.enroll();response=self.client.get('/accounts')
        self.assertEqual(response.status_code,200)
        self.assertIn("frame-ancestors 'none'",response.headers['content-security-policy'])
        self.assertEqual(response.headers['cache-control'],'no-store')
        self.assertNotIn('value=',response.text);self.assertNotIn(' checked',response.text)
        self.assertEqual(response.text.count('type="password"'),3)
        self.assertNotIn(USER,response.text);self.assertNotIn(PASSWORD,response.text)

    def test_expired_recent_authentication_cannot_view_or_save(self):
        self.enroll();self.offset+=300
        self.assertEqual(self.client.get('/accounts').status_code,302)
        self.assertEqual(self.post().status_code,401)
        self.assertFalse(self.accounts.status()['mail']['configured'])

    def test_expired_session_cannot_save(self):
        self.enroll();self.offset+=901
        self.assertEqual(self.post().status_code,401)

    def test_logout_cannot_be_used_for_configuration(self):
        self.enroll();self.assertEqual(self.action('logout').status_code,200)
        self.assertEqual(self.post().status_code,401)

    def test_csrf_and_persistence_confirmation_required(self):
        self.enroll();self.assertEqual(self.post(csrf='wrong').status_code,403)
        self.assertEqual(self.post(persistent_storage_confirmed=False).status_code,400)
        self.assertFalse(self.accounts.status()['mail']['configured'])

    def test_wrong_origin_non_json_extra_fields_and_arbitrary_hosts_rejected(self):
        self.enroll()
        self.assertEqual(self.client.post('/accounts/save',json={},headers={'Origin':'https://attacker.invalid'}).status_code,403)
        self.assertEqual(self.client.post('/accounts/save',content='synthetic',headers={'Content-Type':'text/plain'}).status_code,403)
        self.assertEqual(self.post(host='attacker.invalid').status_code,403)
        self.assertEqual(self.post(provider='https://attacker.invalid').status_code,400)
        self.assertEqual(self.check_calls,[])

    def test_account_body_bound_and_query_credentials_rejected(self):
        self.enroll()
        response=self.client.post('/accounts/save',content='x'*2049,headers={'Content-Type':'application/json'})
        self.assertEqual(response.status_code,413)
        self.assertEqual(self.client.get('/accounts?password=synthetic').status_code,400)

    def test_authentication_rechecked_after_worker_dispatch(self):
        self.enroll();original=self.accounts.guarded
        @contextlib.contextmanager
        def guarded(provider):
            with original(provider):
                self.offset+=301
                yield
        with patch.object(self.accounts,'guarded',guarded):self.assertEqual(self.post().status_code,401)
        self.assertFalse(self.accounts.status()['mail']['configured'])

    def test_checks_are_explicit_and_do_not_persist(self):
        self.enroll();self.client.get('/accounts');self.client.get('/accounts/status')
        self.assertEqual(self.check_calls,[])
        result=self.post('check');self.assertEqual(result.status_code,200)
        self.assertEqual(self.check_calls,['mail']);self.assertFalse(self.accounts.status()['mail']['configured'])
        self.assertNotIn(USER,result.text);self.assertNotIn(PASSWORD,result.text)

    def test_save_does_not_test_provider_and_returns_no_credentials(self):
        self.enroll();result=self.post();self.assertEqual(result.status_code,200)
        self.assertEqual(self.check_calls,[])
        self.assertTrue(self.accounts.status()['mail']['configured'])
        self.assertNotIn(USER,result.text);self.assertNotIn(PASSWORD,result.text)
        self.assertEqual(self.post().status_code,409)

    def test_connection_status_mcp_read_scope_fixed_link_no_credential_arguments(self):
        self.enroll();token=self.token(scope='bridge:read')
        result=self.rpc(token,'tools/call',{'name':'connection_status','arguments':{}}).json()['result']
        self.assertFalse(result.get('isError',False));value=json.loads(result['content'][0]['text'])
        self.assertEqual(value['setup_url'],ORIGIN+'/accounts')
        self.assertFalse(value['accounts']['mail']['configured'])
        tools=self.rpc(token,'tools/list').json()['result']['tools'];tool=next(t for t in tools if t['name']=='connection_status')
        self.assertEqual(tool['inputSchema']['properties'],{})
        self.assertEqual(tool['_meta']['securitySchemes'][0]['scopes'],['bridge:read'])


def load_tests(loader,tests,pattern):
    suite=unittest.TestSuite(loader.loadTestsFromTestCase(StorageTests))
    suite.addTests(loader.loadTestsFromTestCase(ChecksTests))
    for kind in (RevisionTests,HTTPTests):
        for name in kind.__dict__:
            if name.startswith('test_'):suite.addTest(kind(name))
    return suite
