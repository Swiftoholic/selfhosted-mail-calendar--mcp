"""Exact-calendar consent tests. All identities, metadata and writes are synthetic."""
import contextlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from starlette.testclient import TestClient
from bridge.app import ApiError, DAV, calendar_id
from mcp_bridge.accounts import AccountSecrets, bind_id
from mcp_bridge.calendar_consent import CalendarConsents, metadata
from mcp_bridge.calendar_ops import CalendarOperations
from mcp_bridge.config import ORIGIN
from mcp_bridge.operations import Operations
from mcp_bridge.server import create_app
from mcp_bridge.tests.test_accounts import USER, PASSWORD, NEW_PASSWORD
from mcp_bridge.tests.test_security import SecurityTests, FixtureCIMD
from mcp_bridge.tests.test_writes import AdapterTests, DAVFixture, CALENDAR, OBJECT, ROOT, value


class ConsentAdapterTests(AdapterTests):
    def test_default_off_even_private_verified(self):
        self.store.clear_calendar_consents()
        with self.assertRaises(ApiError) as caught:self.calendar.prepare('create', self.event())
        self.assertEqual(caught.exception.code,'calendar_write_consent_required')
        self.assertFalse(self.calendar.list({})['items'][0]['write_consent_enabled'])
        self.assertEqual(self.dav.writes,[])

    def test_exact_identity_not_calendar_name(self):
        other=ROOT+'/calendars/other/'
        self.store.set_calendar_consent('f'*24,calendar_id(other),True)
        self.store.revoke_calendar_consent('f'*24,calendar_id(CALENDAR))
        with self.assertRaises(ApiError):self.calendar.prepare('create',self.event())
        self.assertEqual(self.dav.writes,[])

    def test_unknown_and_shared_with_ack_have_honest_preview(self):
        self.store.set_calendar_consent('f'*24,calendar_id(CALENDAR),True)
        for shared, expected in ((False,'unknown'),(True,'shared_or_public')):
            self.dav.private=False;self.dav.shared=shared
            preview=self.calendar.prepare('create',self.event())['preview']
            self.assertEqual(preview['calendar_audience'],expected)
            self.assertTrue(preview['other_members_may_see_changes'])
            self.assertTrue(preview['provider_may_notify_members'])
            self.assertTrue(preview['capability_is_not_event_approval'])
            self.assertEqual(preview['write_permission'],'unknown')
            self.assertNotIn('private_calendar_verified',preview)
        self.assertEqual(self.dav.writes,[])

    def test_revoke_then_reenable_never_resurrects_preview(self):
        preview=self.calendar.prepare('create',self.event())
        old=self.store.calendar_consent('f'*24,calendar_id(CALENDAR))['generation']
        self.store.revoke_calendar_consent('f'*24,calendar_id(CALENDAR))
        new=self.store.set_calendar_consent('f'*24,calendar_id(CALENDAR),False)['generation']
        self.assertNotEqual(old,new)
        with self.assertRaises(ApiError):self.calendar.commit(self.commit_args(preview))
        self.assertEqual(self.dav.writes,[])

    def test_generation_also_blocks_restored_stale_preview(self):
        preview=self.calendar.prepare('create',self.event());saved=self.store.get('calendar_preview',preview['preview_id'])
        self.store.set_calendar_consent('f'*24,calendar_id(CALENDAR),False)
        self.store.put('calendar_preview',preview['preview_id'],saved,600)
        with self.assertRaises(ApiError) as caught:self.calendar.commit(self.commit_args(preview))
        self.assertEqual(caught.exception.code,'calendar_consent_changed_or_revoked')
        self.assertEqual(self.dav.writes,[])

    def test_audience_change_requires_fresh_preview(self):
        self.store.set_calendar_consent('f'*24,calendar_id(CALENDAR),True)
        preview=self.calendar.prepare('create',self.event());self.dav.shared=True
        with self.assertRaises(ApiError) as caught:self.calendar.commit(self.commit_args(preview))
        self.assertEqual(caught.exception.code,'calendar_audience_changed_new_preview_required')
        self.assertEqual(self.dav.writes,[])

    def test_known_negative_privileges_block_even_with_consent(self):
        self.dav.privileges=['read']
        with self.assertRaises(ApiError) as caught:self.calendar.prepare('create',self.event())
        self.assertEqual(caught.exception.code,'calendar_write_permission_denied')
        self.assertEqual(self.dav.writes,[])

    def test_action_privileges_and_write_aggregate(self):
        self.dav.privileges=['write-content']
        with self.assertRaises(ApiError):self.calendar.prepare('create',self.event())
        self.calendar.prepare('update',self.event(object_id=calendar_id(OBJECT),etag='"v1"'))
        with self.assertRaises(ApiError):self.calendar.prepare('delete',{'calendar_id':calendar_id(CALENDAR),'object_id':calendar_id(OBJECT),'etag':'"v1"'})
        self.dav.privileges=['write']
        details=metadata(self.dav,{'url':CALENDAR})
        self.assertEqual(details['permitted_actions'],{'create':True,'update':True,'delete':True})
        self.assertEqual(self.dav.writes,[])

    def test_provider_403_is_final_no_retry(self):
        preview=self.calendar.prepare('create',self.event());self.dav.deny_write=True
        args=self.commit_args(preview)
        with self.assertRaises(ApiError) as caught:self.calendar.commit(args)
        self.assertEqual(caught.exception.code,'calendar_provider_write_denied')
        with self.assertRaises(Exception):self.calendar.commit(args)
        self.assertEqual(sum(method=='PUT' for method,_ in self.dav.requests),1)
        self.assertEqual(self.dav.writes,[])

    def test_malformed_acl_never_verified_private(self):
        original=self.dav.request
        def malformed(method,url,*args,**kwargs):
            xml,base=original(method,url,*args,**kwargs)
            for grant in xml.findall('.//{'+DAV+'}grant'):
                for ace in xml.findall('.//{'+DAV+'}ace'):ace.remove(grant)
            return xml,base
        self.dav.request=malformed
        self.assertEqual(metadata(self.dav,{'url':CALENDAR})['calendar_audience'],'unknown')

    def test_recovery_clears_consent_and_previews(self):
        preview=self.calendar.prepare('create',self.event());self.store.recovery_reset()
        self.assertEqual(self.store.calendar_consents('f'*24),[])
        self.assertIsNone(self.store.get('calendar_preview',preview['preview_id']))

    def test_consent_survives_store_reopen(self):
        from mcp_bridge.store import Store
        path=self.store.path;old=self.store.calendar_consent('f'*24,calendar_id(CALENDAR))
        self.store.close();self.store=Store(path)
        self.assertEqual(self.store.calendar_consent('f'*24,calendar_id(CALENDAR)),old)


class ConsentHTTPTests(SecurityTests):
    def setUp(self):
        super().setUp();self.client.__exit__(None,None,None)
        directory=Path(self.temp.name)/'accounts';directory.mkdir(mode=0o700)
        self.accounts=AccountSecrets(directory);self.accounts.persist('caldav',USER,PASSWORD,None)
        self.dav=DAVFixture();self.calendar=CalendarOperations(self.accounts,self.store,self.dav.factory,self.dav.connection)
        self.backend=Operations(self.store,self.accounts,calendar=self.calendar)
        self.app,self.identity,self.oauth=create_app(self.store,FixtureCIMD(),self.backend,accounts=self.accounts)
        self.client=TestClient(self.app,base_url=ORIGIN,headers={'Origin':ORIGIN},follow_redirects=False);self.client.__enter__()
    def request_data(self,**changes):
        revision=self.accounts.revision('caldav')
        consent=self.store.calendar_consent(revision,calendar_id(CALENDAR))
        return {'calendar_id':bind_id(calendar_id(CALENDAR),revision,'calendar'),'expected_revision':revision,
                'expected_generation':consent['generation'] if consent else None,'csrf':self.status()['csrf'],**changes}
    def post_calendar(self,action='save',**changes):
        data=self.request_data(**changes)
        if action=='save':data={'audience_acknowledged':False,'capability_only_acknowledged':True,**data}
        return self.client.post('/accounts/calendars/'+action,json=data)
    def test_anonymous_and_unverified_cannot_grant(self):
        self.status()
        for path in ('/accounts/calendars','/accounts/calendars/inspect','/accounts/calendars/save','/accounts/calendars/revoke'):
            result=self.client.get(path) if path.endswith('calendars') else self.client.post(path,json={})
            self.assertEqual(result.status_code,401)
        self.assertEqual(self.store.calendar_consents(self.accounts.revision('caldav')),[])
    def test_list_default_off_and_inspect_never_grants(self):
        self.enroll();rows=self.client.get('/accounts/calendars').json()
        self.assertFalse(rows['default_write_enabled']);self.assertFalse(rows['items'][0]['write_enabled'])
        result=self.post_calendar('inspect');self.assertEqual(result.status_code,200)
        self.assertEqual(result.json()['calendar_audience'],'private_verified')
        self.assertEqual(self.store.calendar_consents(self.accounts.revision('caldav')),[])
        self.assertEqual(self.dav.writes,[])
    def test_save_exact_bound_calendar_and_revoke(self):
        self.enroll();result=self.post_calendar();self.assertEqual(result.status_code,200)
        self.assertTrue(result.json()['write_enabled'])
        self.assertTrue(self.client.get('/accounts/calendars').json()['items'][0]['write_enabled'])
        self.assertEqual(self.post_calendar('revoke').status_code,200)
        self.assertEqual(self.store.calendar_consents(self.accounts.revision('caldav')),[])
        self.assertEqual(self.dav.writes,[])
    def test_stale_generation_and_revision_cannot_save_or_revoke(self):
        self.enroll();old=self.request_data();self.assertEqual(self.post_calendar().status_code,200)
        self.assertEqual(self.client.post('/accounts/calendars/revoke',json=old).status_code,409)
        self.assertEqual(self.post_calendar(expected_revision='0'*24).status_code,409)
        self.assertTrue(self.store.calendar_consents(self.accounts.revision('caldav')))
    def test_unknown_shared_requires_both_acknowledgments(self):
        self.enroll();self.dav.private=False
        self.assertEqual(self.post_calendar().status_code,400)
        self.assertEqual(self.post_calendar(audience_acknowledged=True,capability_only_acknowledged=False).status_code,400)
        self.assertEqual(self.post_calendar(audience_acknowledged=True).status_code,200)
        self.assertEqual(self.post_calendar('revoke').status_code,200)
        self.dav.shared=True
        self.assertEqual(self.post_calendar().status_code,400)
        self.assertEqual(self.post_calendar(audience_acknowledged=True).status_code,200)
        self.assertEqual(self.dav.writes,[])
    def test_negative_provider_permission_cannot_enable(self):
        self.enroll();self.dav.privileges=['read']
        self.assertEqual(self.post_calendar().status_code,403)
        self.assertEqual(self.store.calendar_consents(self.accounts.revision('caldav')),[])
    def test_csrf_origin_exact_fields_body_bound_and_url_rejected(self):
        self.enroll()
        self.assertEqual(self.post_calendar(csrf='wrong').status_code,403)
        self.assertEqual(self.client.post('/accounts/calendars/save',json=self.request_data(),headers={'Origin':'https://attacker.invalid'}).status_code,403)
        data=self.request_data();del data['csrf']
        self.assertEqual(self.client.post('/accounts/calendars/inspect',json=data).status_code,403)
        self.assertEqual(self.post_calendar(host='https://attacker.invalid').status_code,400)
        self.assertEqual(self.post_calendar(calendar_id='https://attacker.invalid/calendar').status_code,400)
        self.assertEqual(self.client.post('/accounts/calendars/save',content='x'*2049,headers={'Content-Type':'application/json'}).status_code,413)
        self.assertEqual(self.store.calendar_consents(self.accounts.revision('caldav')),[])
    def test_bearer_even_with_owner_cookie_cannot_grant(self):
        self.enroll();token=self.token();data=self.request_data()
        self.assertEqual(self.client.post('/accounts/calendars/inspect',json=data,headers={'Authorization':'Bearer '+token}).status_code,401)
        self.client.cookies.clear()
        self.assertEqual(self.client.get('/accounts/calendars',headers={'Authorization':'Bearer '+token}).status_code,401)
        self.assertEqual(self.store.calendar_consents(self.accounts.revision('caldav')),[])
    def test_recent_passkey_expires(self):
        self.enroll();self.offset+=300
        self.assertEqual(self.post_calendar().status_code,401)
        self.assertEqual(self.client.get('/accounts/calendars').status_code,401)
    def test_session_rechecked_after_metadata(self):
        self.enroll();original=self.dav.request
        def expire(*args,**kwargs):
            result=original(*args,**kwargs);self.offset+=301;return result
        self.dav.request=expire
        self.assertEqual(self.post_calendar().status_code,401)
        self.assertEqual(self.store.calendar_consents(self.accounts.revision('caldav')),[])
    def test_provider_busy_serializes_against_commit_and_revoke(self):
        self.enroll()
        with self.accounts.operation('caldav'):
            with ThreadPoolExecutor(max_workers=1) as pool:
                result=pool.submit(self.post_calendar).result()
                self.assertEqual(result.status_code,409)
        self.assertEqual(self.store.calendar_consents(self.accounts.revision('caldav')),[])
    def test_account_save_invalidates_consents_and_previews(self):
        self.enroll();self.assertEqual(self.post_calendar().status_code,200)
        revision=self.accounts.revision('caldav')
        preview=self.backend.call('POST','/mcp/calendar/prepare-create',{'calendar_id':bind_id(calendar_id(CALENDAR),revision,'calendar'),'summary':'Synthetic','start':'2026-10-10T12:00:00Z','end':'2026-10-10T13:00:00Z'})
        result=self.client.post('/accounts/save',json={'provider':'caldav','username':USER,'app_password':NEW_PASSWORD,'expected_revision':revision,'persistent_storage_confirmed':True,'csrf':self.status()['csrf']})
        self.assertEqual(result.status_code,200)
        self.assertEqual(self.store.calendar_consents(revision),[])
        self.assertIsNone(self.store.get('calendar_preview',preview['preview_id']))
        self.assertEqual(self.dav.writes,[])
    def test_neutral_mcp_descriptions_no_private_claim(self):
        self.enroll();token=self.token();tools=self.rpc(token,'tools/list').json()['result']['tools']
        tool=next(t for t in tools if t['name']=='calendar_prepare_create')
        self.assertIn('owner-enabled',tool['description']);self.assertIn('not event approval',tool['description'])
        self.assertNotIn('private calendar',tool['description'])


def load_tests(loader,tests,pattern):
    suite=unittest.TestSuite()
    for kind in (ConsentAdapterTests,ConsentHTTPTests):
        for name in kind.__dict__:
            if name.startswith('test_'):suite.addTest(kind(name))
    return suite
