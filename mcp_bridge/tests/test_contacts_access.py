"""Synthetic consent, scope, revision, recovery and contact disclosure boundaries."""
import json
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.testclient import TestClient
from bridge.app import ApiError, calendar_id
from bridge.providers import parse_profiles
from mcp_bridge.accounts import AccountSecrets, bind_id
from mcp_bridge.config import DEFAULT_SCOPE, ORIGIN
from mcp_bridge.contacts_ops import ContactsOperations
from mcp_bridge.operations import Operations
from mcp_bridge.server import create_app
from mcp_bridge.tests.test_carddav import Fixture, BOOK
from mcp_bridge.tests.test_provider_network import CUSTOM
from mcp_bridge.tests import test_security as security
from mcp_bridge.tests.test_security import FixtureCIMD


class ContactsAccessTests(unittest.TestCase):
    status=security.SecurityTests.status
    action=security.SecurityTests.action
    prepare=security.SecurityTests.prepare
    enroll=security.SecurityTests.enroll
    authdata=security.SecurityTests.authdata
    code=security.SecurityTests.code
    exchange=security.SecurityTests.exchange
    token=security.SecurityTests.token
    rpc=security.SecurityTests.rpc
    def setUp(self):
        security.SecurityTests.setUp(self);self.client.__exit__(None,None,None)
        directory=Path(self.temp.name)/'accounts';directory.mkdir(mode=0o700)
        self.accounts=AccountSecrets(directory)
        self.accounts.persist('carddav','synthetic-contacts','SYNTHETIC_CARD_ONLY',None)
        self.fixture=Fixture();self.contacts=ContactsOperations(self.accounts,self.store,self.fixture.factory)
        self.backend=Operations(self.store,self.accounts,contacts=self.contacts)
        app,self.identity,self.oauth=create_app(self.store,FixtureCIMD(),self.backend,accounts=self.accounts)
        self.client=TestClient(app,base_url=ORIGIN,headers={'Origin':ORIGIN},follow_redirects=False);self.client.__enter__()
    def tearDown(self):
        security.SecurityTests.tearDown(self)
    def owner_books(self):
        response=self.client.get('/accounts/contacts');self.assertEqual(response.status_code,200);return response.json()
    def enable_book(self):
        listing=self.owner_books();row=listing['items'][0]
        payload={'addressbook_id':row['id'],'expected_revision':listing['account_revision'],'expected_generation':row['generation'],
                 'read_access_acknowledged':True,'csrf':self.status()['csrf']}
        response=self.client.post('/accounts/contacts/save',json=payload);self.assertEqual(response.status_code,200);return payload
    def invoke(self, token, name, **arguments):
        result=self.rpc(token,'tools/call',{'name':name,'arguments':arguments}).json()['result']
        serialized=json.dumps(result)
        if not result.get('isError',False) and 'structuredContent' not in result:
            result['structuredContent']=json.loads(result['content'][0]['text'])
        return result, serialized
    def books_tool(self, token):
        return self.invoke(token,'contacts_addressbooks')[0]['structuredContent']

    def test_contact_scope_is_explicit_and_no_write_tool_or_scope_exists(self):
        self.assertNotIn('contacts:read',DEFAULT_SCOPE.split())
        self.enroll();token=self.token(scope='bridge:read mail:read calendars:read')
        for name,args in (('contacts_addressbooks',{}),('contacts_search',{'addressbook_id':'0'*24,'query':'Example'}),('contacts_read',{'contact_id':'0'*24})):
            result,serialized=self.invoke(token,name,**args);self.assertTrue(result['isError']);self.assertIn('insufficient_scope',serialized)
        self.assertEqual(self.fixture.methods,[])
        tools=self.rpc(token,'tools/list').json()['result']['tools'];contacts=[tool for tool in tools if tool['name'].startswith('contacts_')]
        self.assertEqual(len(contacts),3)
        self.assertTrue(all(tool['annotations']['readOnlyHint'] and not tool['annotations']['destructiveHint'] for tool in contacts))
        self.assertTrue(all(tool['_meta']['securitySchemes'][0]['scopes']==['bridge:read','contacts:read'] for tool in contacts))
        self.assertNotIn('contacts:write',self.client.get('/.well-known/oauth-protected-resource/mcp').json()['scopes_supported'])

    def test_book_capability_defaults_off_and_metadata_is_not_contact_approval(self):
        self.enroll();token=self.token(scope='bridge:read contacts:read')
        self.assertEqual(self.books_tool(token)['items'],[])
        listing=self.owner_books();self.assertFalse(listing['items'][0]['read_enabled']);self.assertFalse(listing['default_read_enabled'])
        result,serialized=self.invoke(token,'contacts_search',addressbook_id=listing['items'][0]['id'],query='Example')
        self.assertTrue(result['isError']);self.assertIn('contacts_addressbook_consent_required',serialized)
        self.assertNotIn('REPORT',self.fixture.methods)

    def test_enabled_search_and_reference_read_minimal_fields_without_urls(self):
        self.enroll();self.enable_book();token=self.token(scope='bridge:read contacts:read')
        book=self.books_tool(token)['items'][0]
        result,serialized=self.invoke(token,'contacts_search',addressbook_id=book['id'],query='Example',limit=2)
        self.assertFalse(result.get('isError',False));contact=result['structuredContent']['items'][0]
        self.assertEqual(contact['name'],'Example Person');self.assertEqual(contact['addressbook_id'],book['id'])
        self.assertNotIn(BOOK,serialized);self.assertNotIn('photo',serialized.lower());self.assertNotIn('note',serialized.lower())
        result,serialized=self.invoke(token,'contacts_read',contact_id=contact['id'])
        self.assertEqual(result['structuredContent']['emails'],['person@example.invalid']);self.assertNotIn('_resource_url',serialized)
        self.assertEqual(set(self.fixture.methods),{'PROPFIND','REPORT'})

    def reference(self):
        token=self.token(scope='bridge:read contacts:read');book=self.books_tool(token)['items'][0]
        result,_=self.invoke(token,'contacts_search',addressbook_id=book['id'],query='Example')
        return token,book,result['structuredContent']['items'][0]['id']

    def test_revoke_regrant_account_rotation_and_expiry_invalidate_refs(self):
        self.enroll();self.enable_book();token,book,reference=self.reference()
        listing=self.owner_books();row=listing['items'][0]
        response=self.client.post('/accounts/contacts/revoke',json={'csrf':self.status()['csrf'],'addressbook_id':row['id'],'expected_revision':listing['account_revision'],'expected_generation':row['generation']})
        self.assertEqual(response.status_code,200);self.assertFalse(response.json()['provider_changed'])
        result,_=self.invoke(token,'contacts_read',contact_id=reference);self.assertTrue(result['isError'])
        self.enable_book();token,book,new=self.reference();self.assertNotEqual(new,reference)
        self.offset+=601;result,_=self.invoke(token,'contacts_read',contact_id=new);self.assertTrue(result['isError'])

    def test_account_replacement_clears_consent_and_never_reuses_other_protocol(self):
        self.enroll();self.enable_book();token,book,reference=self.reference()
        revision=self.accounts.revision('carddav')
        response=self.client.post('/accounts/save',json={'provider':'carddav','username':'new-contacts','app_password':'SYNTHETIC_NEW_ONLY','expected_revision':revision,
                                  'persistent_storage_confirmed':True,'csrf':self.status()['csrf']})
        self.assertEqual(response.status_code,200);self.assertEqual(self.store.contacts_consents(self.accounts.revision('carddav')),[])
        self.assertEqual(self.store.get('contact_ref',bind_id(reference,revision,'contact')),None)
        result,_=self.invoke(token,'contacts_read',contact_id=reference);self.assertTrue(result['isError'])
        self.assertFalse(self.accounts.status()['caldav']['configured']);self.assertFalse(self.accounts.status()['mail']['configured'])

    def test_contact_consent_requires_recent_passkey_csrf_selection_and_confirmation(self):
        self.assertEqual(self.client.get('/accounts/contacts').status_code,401)
        self.enroll();listing=self.owner_books();row=listing['items'][0]
        base={'csrf':self.status()['csrf'],'addressbook_id':row['id'],'expected_revision':listing['account_revision'],'expected_generation':None,'read_access_acknowledged':True}
        for change in ({'csrf':'wrong'},{'read_access_acknowledged':False},{'addressbook_id':'0'*24},{'expected_revision':'0'*24},{'expected_generation':'0'*24},{'url':'https://contacts.example.test/'}):
            self.assertGreaterEqual(self.client.post('/accounts/contacts/save',json={**base,**change}).status_code,400)
        token=self.token(scope='bridge:read contacts:read')
        self.assertEqual(self.client.post('/accounts/contacts/save',headers={'Authorization':'Bearer '+token},json=base).status_code,401)
        self.offset+=300;self.assertEqual(self.client.post('/accounts/contacts/save',json=base).status_code,401)
        self.assertEqual(self.store.contacts_consents(listing['account_revision']),[])

    def test_recovery_or_oauth_revocation_during_network_call_prevents_disclosure(self):
        self.enroll();self.enable_book();token,book,reference=self.reference()
        original=self.contacts.read_resource
        def revoked(*args):
            result=original(*args)
            self.store.db.execute("DELETE FROM records WHERE kind='token'")
            return result
        with patch.object(self.contacts,'read_resource',side_effect=revoked):
            result,serialized=self.invoke(token,'contacts_read',contact_id=reference)
        self.assertTrue(result['isError']);self.assertIn('authorization_revoked',serialized);self.assertNotIn('Example Person',serialized)

    def test_book_revoke_during_report_and_recovery_clear_all_contact_state(self):
        self.enroll();self.enable_book();token,book,reference=self.reference()
        original=self.contacts.read_resource
        def revoked(*args):
            result=original(*args);self.store.revoke_contacts_consent(self.accounts.revision('carddav'),calendar_id(BOOK));return result
        with patch.object(self.contacts,'read_resource',side_effect=revoked):
            result,serialized=self.invoke(token,'contacts_read',contact_id=reference)
        self.assertTrue(result['isError']);self.assertNotIn('Example Person',serialized)
        self.store.set_contacts_consent(self.accounts.revision('carddav'),calendar_id(BOOK));self.store.recovery_reset()
        self.assertEqual(self.store.contacts_consents(self.accounts.revision('carddav')),[])
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM records WHERE kind='contact_ref'").fetchone()[0],0)

    def test_untrusted_resource_paths_and_query_bounds_never_fetch_arbitrary_urls(self):
        self.enroll();self.enable_book();token=self.token(scope='bridge:read contacts:read');book=self.books_tool(token)['items'][0]
        for query in ('','x'*101,'a\nBEGIN:BAD'):
            result,_=self.invoke(token,'contacts_search',addressbook_id=book['id'],query=query);self.assertTrue(result['isError'])
        for href in ('https://attacker.example.test/person.vcf',BOOK+'nested/person.vcf',BOOK+'%2e%2e.vcf'):
            self.fixture.href=href;result,_=self.invoke(token,'contacts_search',addressbook_id=book['id'],query='Example');self.assertTrue(result['isError'])
        result,_=self.invoke(token,'contacts_read',contact_id='https://attacker.example.test/person.vcf');self.assertTrue(result['isError'])
