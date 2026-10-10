"""Independent account capabilities, routing, checks, migration and browser API."""
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from starlette.testclient import TestClient
from bridge.app import ApiError, calendar_id
from bridge.providers import ProviderCatalog, parse_profiles
from mcp_bridge.account_management import AccountManagement
from mcp_bridge.accounts import AccountSecrets, bind_id, connection_status
from mcp_bridge.calendar_ops import CalendarOperations
from mcp_bridge.contacts_ops import ContactsOperations
from mcp_bridge.mail_ops import MailOperations, folder_id
from mcp_bridge.operations import Operations
from mcp_bridge.server import create_app
from mcp_bridge.config import ORIGIN
from mcp_bridge.tests.multi_fixtures import MemoryAccounts, SyntheticChecks, synthetic_store
from mcp_bridge.tests.test_security import FixtureCIMD, SecurityTests, Key
from mcp_bridge.tests.test_writes import IMAPFixture, SMTPFixture, DAVFixture, CALENDAR
from mcp_bridge.tests.test_carddav import Fixture as ContactsFixture, BOOK


def form(protocol='mail', row=None):
    return {'provider': protocol, 'account_id': row['id'] if row else None,
            'expected_revision': row['revision'] if row else None,
            'profile_id': row['profile_id'] if row else {'mail':'gmx-mail','caldav':'icloud-caldav','carddav':'icloud-carddav'}[protocol],
            'label': 'Synthetic account', 'username': row['username'] if row else 'owner@example.invalid',
            'app_password': None if row else 'SYNTHETIC_ONLY_NOT_A_PASSWORD',
            'sender_email': row['sender_email'] if row else 'sender@example.invalid' if protocol == 'mail' else None,
            'capabilities': list(row['capabilities']) if row else []}


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.now=1000
        self.store,self.temp=synthetic_store(lambda:self.now)
        self.accounts=MemoryAccounts(clock=lambda:self.now)
        self.checks=SyntheticChecks()
        self.manager=AccountManagement(self.accounts,self.store,self.checks)
        self.csrf='synthetic-csrf'

    def tearDown(self):
        self.store.close();self.temp.cleanup()

    def check(self, data):
        return self.manager.action('check', data, lambda:None, self.csrf)

    def save(self, data, proof):
        return self.manager.action('save', {**data, 'check_id':proof['check_id'], 'persistent_storage_confirmed':True}, lambda:None, self.csrf)

    def test_multiple_accounts_per_type_have_distinct_ids_revisions_and_no_implicit_selection(self):
        for protocol in ('mail','caldav','carddav'):
            a=self.accounts.seed(protocol);b=self.accounts.seed(protocol)
            self.assertNotEqual(a['id'],b['id']);self.assertNotEqual(a['revision'],b['revision'])
            with self.assertRaises(ApiError) as caught:self.accounts.pair(protocol)
            self.assertEqual(caught.exception.code,'account_selection_required')
            with self.accounts.operation(protocol,a['id']):self.assertEqual(self.accounts.account_id(protocol),a['id'])
        self.assertEqual(len(self.accounts.inventory()),6)

    def test_check_saves_nothing_and_save_requires_exact_successful_test(self):
        data=form();proof=self.check(data)
        self.assertEqual(self.accounts.inventory(),[])
        result=self.save(data,proof)
        self.assertEqual(len(self.accounts.inventory()),1)
        self.assertNotIn(data['app_password'],json.dumps(result))
        self.assertEqual(self.accounts.inventory()[0]['capabilities'],[])
        with self.assertRaises(ApiError):self.save(data,proof)
        self.assertEqual(len(self.accounts.inventory()),1)

    def test_changed_input_scopes_sender_profile_session_and_expired_proof_rejected(self):
        for field,value in [('label','Changed'),('username','other@example.invalid'),('app_password','SYNTHETIC_CHANGED'),('sender_email','other@example.invalid'),('capabilities',['mail:send'])]:
            data=form();proof=self.check(data)
            with self.subTest(field=field),self.assertRaises(ApiError):self.save({**data,field:value},proof)
        data=form();proof=self.check(data);self.csrf='other-session'
        with self.assertRaises(ApiError):self.save(data,proof)
        self.csrf='synthetic-csrf';self.now+=301
        with self.assertRaises(ApiError):self.save(data,proof)
        self.assertEqual(self.accounts.inventory(),[])

    def test_edit_keeps_password_without_returning_it_but_new_profile_requires_reentry(self):
        row=self.accounts.seed('mail',rights=['mail:read']);data=form(row=row)
        proof=self.check(data);saved=self.save({**data},proof)
        self.assertEqual(saved['account_id'],row['id']);self.assertNotEqual(saved['revision'],row['revision'])
        self.assertEqual(self.checks.calls[-1][2],'SYNTHETIC_ONLY_NOT_A_PASSWORD')
        self.assertNotIn('app_password',json.dumps(self.accounts.inventory(owner=True)))
        profiles=parse_profiles({'version':2,'profiles':{'other-mail':{'protocol':'mail','name':'Other','config':{'preset':'gmx'}}},
                                 'defaults':{'mail':'gmx-mail','caldav':'icloud-caldav','carddav':'icloud-carddav'}})
        self.accounts.catalog=profiles;current=self.accounts.inventory(owner=True)[0]
        with self.assertRaises(ApiError) as caught:self.check({**form(row=current),'profile_id':'other-mail'})
        self.assertEqual(caught.exception.code,'profile_change_requires_password')

    def test_removal_only_retires_selected_revision_and_keeps_tokens_receipts_other_consents(self):
        a=self.accounts.seed('caldav',rights=['calendars:write']);b=self.accounts.seed('caldav',rights=['calendars:write'])
        identifier='a'*24
        ca=self.store.set_calendar_consent(a['revision'],identifier,True)
        cb=self.store.set_calendar_consent(b['revision'],identifier,True)
        self.store.put('token','synthetic-token',{'fixture':True},900)
        op,_=self.store.reserve_operation('mail_send','synthetic-receipt-0001',{'fixture':True});self.store.finish_operation(op,{'smtp_accepted':True})
        self.store.put('calendar_preview','a'*24,{'account_revision':a['revision']},600)
        self.store.put('calendar_preview','b'*24,{'account_revision':b['revision']},600)
        result=self.manager.action('remove',{'provider':'caldav','account_id':a['id'],'expected_revision':a['revision'],'integration_removal_confirmed':True},lambda:None,self.csrf)
        self.assertFalse(result['provider_data_changed']);self.assertIsNone(self.store.calendar_consent(a['revision'],identifier))
        self.assertEqual(self.store.calendar_consent(b['revision'],identifier),cb)
        self.assertIsNone(self.store.get('calendar_preview','a'*24));self.assertIsNotNone(self.store.get('calendar_preview','b'*24))
        self.assertIsNotNone(self.store.get('token','synthetic-token'));self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0],1)

    def test_edit_invalidates_only_its_mail_previews(self):
        a=self.accounts.seed('mail');b=self.accounts.seed('mail')
        for key,row in [('a'*24,a),('b'*24,b)]:self.store.put('mail_preview',key,{'account_revision':row['revision']},600)
        data=form(row=a);self.save(data,self.check(data))
        self.assertIsNone(self.store.get('mail_preview','a'*24));self.assertIsNotNone(self.store.get('mail_preview','b'*24))

    def test_retest_status_is_explicit_and_failure_sanitized(self):
        row=self.accounts.seed('mail');self.checks.fail=True
        result=self.manager.action('retest',{'provider':'mail','account_id':row['id'],'expected_revision':row['revision']},lambda:None,self.csrf)
        self.assertFalse(result['connected']);self.assertEqual(self.accounts.inventory()[0]['connection']['state'],'failed')
        self.assertNotIn('password',json.dumps(result));self.assertEqual(self.accounts.inventory(owner=True)[0]['revision'],row['revision'])

    def test_logout_during_check_or_save_blocks_result_without_configuration_change(self):
        data=form();count=[0]
        def authorize():
            count[0]+=1
            if count[0]>1:raise ValueError('synthetic-session-expired')
        with self.assertRaises(ValueError):self.manager.action('check',data,authorize,self.csrf)
        self.assertEqual(self.accounts.inventory(),[]);self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM records WHERE kind='account_check'").fetchone()[0],0)

    def test_catalog_cas_and_failure_before_or_after_publish_do_not_duplicate_accounts(self):
        for after in (False,True):
            accounts=MemoryAccounts();manager=AccountManagement(accounts,self.store,self.checks)
            proof=manager.action('check',form(),lambda:None,self.csrf)
            accounts.fail_after_write=after;accounts.fail_before_write=not after
            with self.assertRaises(ApiError):manager.action('save',{**form(),'check_id':proof['check_id'],'persistent_storage_confirmed':True},lambda:None,self.csrf)
            accounts.fail_before_write=accounts.fail_after_write=False
            if after:
                with self.assertRaises(ApiError):manager.action('save',{**form(),'check_id':proof['check_id'],'persistent_storage_confirmed':True},lambda:None,self.csrf)
                self.assertEqual(len(accounts.inventory()),1)
            else:self.assertEqual(accounts.inventory(),[])

    def test_parallel_updates_to_different_accounts_do_not_lose_either(self):
        rows=[self.accounts.seed('mail',username=x+'@example.invalid') for x in ('one','two')]
        prepared=[(form(row=row),None) for row in rows]
        prepared=[(data,self.check(data)) for data,_ in prepared]
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda pair:self.save(*pair),prepared))
        self.assertEqual(len(self.accounts.inventory()),2)
        self.assertEqual({r['account_id'] for r in results},{r['id'] for r in rows})

    def test_source_status_reveals_no_credentials_or_revisions_to_mcp(self):
        self.accounts.seed('mail')
        value=json.dumps(connection_status(self.accounts))
        self.assertNotIn('synthetic@example.invalid',value);self.assertNotIn('SYNTHETIC_ONLY',value);self.assertNotIn('revision',value)

    def test_running_account_blocks_edit_remove_retest_but_other_accounts_remain_independent(self):
        a=self.accounts.seed('mail');b=self.accounts.seed('mail')
        proof=self.check(form(row=a))
        with self.accounts.operation('mail',a['id']) as snapshot:
            calls=[('save',{**form(row=a),'check_id':proof['check_id'],'persistent_storage_confirmed':True}),
                   ('remove',{'provider':'mail','account_id':a['id'],'expected_revision':a['revision'],'integration_removal_confirmed':True}),
                   ('retest',{'provider':'mail','account_id':a['id'],'expected_revision':a['revision']})]
            for action,data in calls:
                with ThreadPoolExecutor(max_workers=1) as pool:
                    task=pool.submit(self.manager.action,action,data,lambda:None,self.csrf)
                    with self.assertRaises(ApiError) as caught:task.result()
                self.assertEqual(caught.exception.code,'provider_busy_try_again')
            with ThreadPoolExecutor(max_workers=1) as pool:
                result=pool.submit(self.manager.action,'retest',{'provider':'mail','account_id':b['id'],'expected_revision':b['revision']},lambda:None,self.csrf).result()
            self.assertTrue(result['connected']);self.assertEqual(self.accounts.revision('mail'),snapshot.revision)
        self.assertEqual(len(self.accounts.inventory()),2)

    def test_legacy_save_guard_and_operation_share_virtual_account_lock(self):
        self.accounts.seed('mail');legacy=copy.deepcopy(self.accounts.memory['accounts'])
        legacy[0]['id']=hashlib.sha256(b'single-v2:mail').hexdigest()[:24]
        accounts=MemoryAccounts(legacy=legacy)
        def legacy_save_guard():
            with accounts.guarded('mail'):return True
        with accounts.operation('mail'):
            with ThreadPoolExecutor(max_workers=1) as pool:
                task=pool.submit(legacy_save_guard)
                with self.assertRaises(ApiError) as caught:task.result()
            self.assertEqual(caught.exception.code,'provider_busy_try_again')


class RoutingTests(CatalogTests):
    def setUp(self):
        super().setUp();self.imap_clients=[];self.smtp_clients=[];self.dav_clients={}
        def imap(host,port,**kwargs):
            client=IMAPFixture();client.endpoint=(host,port);client.login=lambda user,password:(setattr(client,'user',user) or ('OK',[]));self.imap_clients.append(client);return client
        def smtp(host,port,**kwargs):
            client=SMTPFixture();client.endpoint=(host,port);client.login=lambda user,password:(setattr(client,'user',user) or (235,b'ok'))
            client.mail=lambda sender:(setattr(client,'sender',sender) or (250,b'ok'));self.smtp_clients.append(client);return client
        def dav(pair):return self.dav_clients.setdefault(pair[0],DAVFixture())
        self.backend=Operations(self.store,self.accounts,MailOperations(self.accounts,self.store,imap,smtp),CalendarOperations(self.accounts,self.store,dav))
        self.a=self.accounts.seed('mail','one@example.invalid',['mail:read','mail:send'],sender='sender-one@example.invalid')
        self.b=self.accounts.seed('mail','two@example.invalid',['mail:read','mail:send'],sender='sender-two@example.invalid')

    def call(self,path,row,**data):return self.backend.call('POST',path,{**data,'account_id':row['id']})

    def test_identical_provider_folder_ids_are_separate_and_cross_account_target_is_rejected(self):
        a=self.call('/mcp/mail/folders',self.a);b=self.call('/mcp/mail/folders',self.b)
        self.assertNotEqual(a['items'][0]['id'],b['items'][0]['id']);self.assertEqual(a['account_id'],self.a['id'])
        with self.accounts.operation('mail',self.b['id']):
            decoded=bind_id(a['items'][0]['id'],self.accounts.revision('mail'),'mailbox')
            with self.assertRaises(ApiError):self.backend.mail.find(self.backend.mail.folders(self.imap_clients[-1]),decoded)

    def test_sender_and_preview_are_bound_to_account_and_edit_invalidates_only_target(self):
        preview=self.call('/mcp/mail/prepare-send',self.a,to=['recipient@example.invalid'],subject='Synthetic',body='Synthetic only')
        self.assertEqual(preview['preview']['from'],'sender-one@example.invalid');self.assertEqual(preview['preview']['account_id'],self.a['id'])
        with self.assertRaises(ApiError):self.call('/mcp/mail/send',self.b,preview_id=preview['preview_id'],preview_hash=preview['preview_hash'],idempotency_key='synthetic-wrong-account-0001',confirmed=True)
        self.assertEqual(self.smtp_clients,[])
        result=self.call('/mcp/mail/send',self.a,preview_id=preview['preview_id'],preview_hash=preview['preview_hash'],idempotency_key='synthetic-right-account-0001',confirmed=True)
        self.assertTrue(result['smtp_accepted']);self.assertEqual(self.smtp_clients[-1].user,'one@example.invalid');self.assertEqual(self.smtp_clients[-1].sender,'sender-one@example.invalid')
        with self.assertRaises((ApiError,ValueError)):self.call('/mcp/mail/send',self.b,preview_id=preview['preview_id'],preview_hash=preview['preview_hash'],idempotency_key='synthetic-right-account-0001',confirmed=True)
        self.assertEqual(sum(c.data_count for c in self.smtp_clients),1)

    def test_missing_account_invalid_account_and_missing_capability_never_contact_provider(self):
        for data in ({},{'account_id':'0'*24}):
            with self.assertRaises(ApiError):self.backend.call('POST','/mcp/mail/folders',data)
        empty=self.accounts.seed('mail','disabled@example.invalid')
        with self.assertRaises(ApiError) as caught:self.call('/mcp/mail/folders',empty)
        self.assertEqual(caught.exception.code,'account_capability_required');self.assertEqual(self.imap_clients,[])

    def test_dynamic_transport_profiles_are_taken_from_frozen_selected_account(self):
        config={'version':2,'profiles':{'custom-mail':{'protocol':'mail','name':'Other', 'config':{'preset':'custom','imap':{'host':'imap.example.test','port':993,'tls':'implicit'},'smtp':{'host':'smtp.example.test','port':587,'tls':'starttls_required'}}}},'defaults':{'mail':'gmx-mail','caldav':'icloud-caldav','carddav':'icloud-carddav'}}
        self.accounts.catalog=parse_profiles(config)
        c=self.accounts.seed('mail','three@example.invalid',['mail:read'],profile_id='custom-mail')
        self.call('/mcp/mail/folders',c);self.call('/mcp/mail/folders',self.a)
        self.assertEqual(self.imap_clients[-2].endpoint,('imap.example.test',993));self.assertEqual(self.imap_clients[-2].user,'three@example.invalid')
        self.assertEqual(self.imap_clients[-1].endpoint,('imap.gmx.net',993));self.assertEqual(self.imap_clients[-1].user,'one@example.invalid')

    def test_same_calendar_url_has_separate_ids_consents_and_preview_commit(self):
        a=self.accounts.seed('caldav','calendar-one@example.invalid',['calendars:read','calendars:write'])
        b=self.accounts.seed('caldav','calendar-two@example.invalid',['calendars:read','calendars:write'])
        first=self.call('/v1/calendars/list',a);second=self.call('/v1/calendars/list',b)
        self.assertNotEqual(first['items'][0]['id'],second['items'][0]['id'])
        self.store.set_calendar_consent(a['revision'],calendar_id(CALENDAR),False)
        self.assertFalse(self.call('/v1/calendars/list',b)['items'][0]['write_consent_enabled'])
        preview=self.call('/mcp/calendar/prepare-create',a,calendar_id=first['items'][0]['id'],summary='Synthetic',start='2026-10-10T12:00:00Z',end='2026-10-10T12:05:00Z')
        self.assertEqual(preview['preview']['account_id'],a['id'])
        with self.assertRaises(ApiError):self.call('/mcp/calendar/commit',b,preview_id=preview['preview_id'],preview_hash=preview['preview_hash'],idempotency_key='synthetic-calendar-wrong-0001',confirmed=True)

    def test_identical_carddav_urls_consents_and_references_are_account_bound_on_removal(self):
        fixture=ContactsFixture();self.backend.contacts=ContactsOperations(self.accounts,self.store,fixture.factory)
        a=self.accounts.seed('carddav','contacts-one@example.invalid',['contacts:read'])
        b=self.accounts.seed('carddav','contacts-two@example.invalid',['contacts:read'])
        for row in (a,b):self.store.set_contacts_consent(row['revision'],calendar_id(BOOK))
        listings=[self.call('/mcp/contacts/books',row) for row in (a,b)]
        self.assertNotEqual(listings[0]['items'][0]['id'],listings[1]['items'][0]['id'])
        results=[self.call('/mcp/contacts/search',row,addressbook_id=listing['items'][0]['id'],query='Example') for row,listing in zip((a,b),listings)]
        self.assertNotEqual(results[0]['items'][0]['id'],results[1]['items'][0]['id'])
        before=len(fixture.methods)
        with self.assertRaises(ApiError):self.call('/mcp/contacts/read',b,contact_id=results[0]['items'][0]['id'])
        self.assertEqual(len(fixture.methods),before)
        self.manager.action('remove',{'provider':'carddav','account_id':a['id'],'expected_revision':a['revision'],'integration_removal_confirmed':True},lambda:None,self.csrf)
        self.assertIsNone(self.store.contacts_consent(a['revision'],calendar_id(BOOK)))
        self.assertIsNotNone(self.store.contacts_consent(b['revision'],calendar_id(BOOK)))
        self.assertEqual(self.call('/mcp/contacts/read',b,contact_id=results[1]['items'][0]['id'])['name'],'Example Person')


class MigrationTests(CatalogTests):
    def test_legacy_import_preserves_exact_revisions_and_identity_without_new_rights(self):
        original=self.accounts.seed('caldav',rights=['calendars:read','calendars:write'])
        legacy=copy.deepcopy(self.accounts.memory['accounts']);self.accounts=MemoryAccounts(legacy=legacy)
        consent=self.store.set_calendar_consent(original['revision'],'a'*24,True)
        before=self.store.db.iterdump();before=list(before)
        result=self.accounts.migrate_single_accounts()
        self.assertTrue(result['consent_revisions_preserved']);self.assertEqual(list(self.store.db.iterdump()),before)
        self.assertEqual(self.accounts.inventory(owner=True)[0]['revision'],original['revision'])
        self.assertEqual(self.store.calendar_consent(original['revision'],'a'*24),consent)
        self.assertFalse(self.accounts.migrate_single_accounts()['migrated'])

    def test_failed_import_is_unpublished_or_complete_and_never_duplicates(self):
        self.accounts.seed('mail');legacy=copy.deepcopy(self.accounts.memory['accounts'])
        for after in (False,True):
            accounts=MemoryAccounts(legacy=legacy);accounts.fail_before_write=not after;accounts.fail_after_write=after
            with self.assertRaises(ApiError):accounts.migrate_single_accounts()
            accounts.fail_before_write=accounts.fail_after_write=False
            accounts.migrate_single_accounts();self.assertEqual(len(accounts.inventory()),1);self.assertEqual(accounts.legacy,legacy)


class HTTPTests(SecurityTests):
    def setUp(self):
        self.offset=0;self.store,self.temp=synthetic_store(lambda:time.time()+self.offset)
        self.accounts=MemoryAccounts(clock=self.store.clock);self.checks=SyntheticChecks()
        self.app,self.identity,self.oauth=create_app(self.store,FixtureCIMD(),accounts=self.accounts,checks=self.checks)
        self.client=TestClient(self.app,base_url=ORIGIN,headers={'Origin':ORIGIN},follow_redirects=False);self.client.__enter__();self.key=Key()

    def post_manage(self,action,data):return self.client.post('/accounts/manage/'+action,json={'csrf':self.status()['csrf'],**data})

    def test_management_requires_recent_passkey_csrf_same_origin_json_and_rejects_browser_endpoints(self):
        self.assertEqual(self.post_manage('check',form()).status_code,401);self.enroll()
        self.assertEqual(self.client.post('/accounts/manage/check',json={**form(),'csrf':'bad'}).status_code,403)
        self.assertEqual(self.client.post('/accounts/manage/check',json={**form(),'csrf':self.status()['csrf']},headers={'Origin':'https://attacker.invalid'}).status_code,403)
        self.assertEqual(self.post_manage('check',{**form(),'host':'attacker.invalid'}).status_code,400)
        self.offset+=301;self.assertEqual(self.post_manage('check',form()).status_code,401);self.assertEqual(self.checks.calls,[])

    def test_owner_overview_after_login_contains_accounts_and_status_but_never_passwords(self):
        self.accounts.seed('mail');self.enroll();result=self.client.get('/accounts/status')
        self.assertEqual(result.status_code,200);self.assertEqual(len(result.json()['items']),1)
        self.assertIn('profile_choices',result.json());self.assertNotIn('app_password',result.text);self.assertNotIn('SYNTHETIC_ONLY',result.text)
        self.assertEqual(self.checks.calls,[])

    def test_add_edit_remove_flow_and_double_save_no_duplicate_account(self):
        self.enroll();data=form();check=self.post_manage('check',data)
        self.assertEqual(check.status_code,200)
        save={**data,'check_id':check.json()['check_id'],'persistent_storage_confirmed':True}
        result=self.post_manage('save',save);self.assertEqual(result.status_code,200)
        self.assertEqual(self.post_manage('save',save).status_code,409);self.assertEqual(len(self.accounts.inventory()),1)
        row=self.accounts.inventory(owner=True)[0];edit=form(row=row);edit['label']='Edited'
        proof=self.post_manage('check',edit);self.assertEqual(proof.status_code,200)
        self.assertEqual(self.post_manage('save',{**edit,'check_id':proof.json()['check_id'],'persistent_storage_confirmed':True}).status_code,200)
        row=self.accounts.inventory(owner=True)[0]
        remove={'provider':'mail','account_id':row['id'],'expected_revision':row['revision'],'integration_removal_confirmed':False}
        self.assertEqual(self.post_manage('remove',remove).status_code,400)
        remove['integration_removal_confirmed']=True
        self.assertEqual(self.post_manage('remove',remove).status_code,200);self.assertEqual(self.accounts.inventory(),[])

    def test_existing_oauth_scope_does_not_authorize_new_account_without_explicit_capability(self):
        row=self.accounts.seed('mail');self.enroll();token=self.token(scope='bridge:read mail:read')
        with patch('bridge.network.public_socket') as dial:
            result=self.rpc(token,'tools/call',{'name':'mail_folders','arguments':{'account_id':row['id']}}).json()['result']
        self.assertTrue(result.get('isError'));self.assertIn('account_capability_required',result['content'][0]['text']);dial.assert_not_called()


@unittest.skipUnless(os.name == 'posix','Real private-file mode/UID/renameat2 checks require Linux; never emulated in runtime.')
class LinuxCatalogTests(unittest.TestCase):
    def test_real_import_modes_atomic_replay_and_original_files_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            accounts=AccountSecrets(folder)
            saved=accounts.persist('mail','synthetic@example.invalid','SYNTHETIC_ONLY_NOT_A_PASSWORD',None)
            path=Path(folder)/'mail.json';original=path.read_bytes()
            result=accounts.migrate_single_accounts()
            self.assertTrue(result['migrated']);self.assertEqual(path.read_bytes(),original)
            self.assertEqual((Path(folder)/'accounts.json').stat().st_mode & 0o777,0o600)
            self.assertEqual(accounts.inventory(owner=True)[0]['revision'],saved['revision'])
            self.assertFalse(accounts.migrate_single_accounts()['migrated'])


def load_tests(loader, tests, pattern):
    suite=unittest.TestSuite(loader.loadTestsFromTestCase(CatalogTests))
    for kind in (RoutingTests,MigrationTests,HTTPTests,LinuxCatalogTests):
        for name in kind.__dict__:
            if name.startswith('test_'):suite.addTest(kind(name))
    return suite
