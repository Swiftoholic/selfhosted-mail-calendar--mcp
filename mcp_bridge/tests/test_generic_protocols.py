"""Four protocol adapters against offline TLS servers with custom logical hosts."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bridge.app import ApiError, Calendar, Mail, calendar_id
from bridge.carddav import Contacts
from bridge.network import smtp_connection
from bridge.providers import parse_profiles
from mcp_bridge.accounts import AccountSecrets, ConnectionChecks
from mcp_bridge.calendar_ops import CalendarOperations
from mcp_bridge.mail_ops import MailOperations
from mcp_bridge.store import Store
from mcp_bridge.tests.protocol_fixtures import certificate, running, fixture_dial, IMAPHandler, SMTPHandler, DAVHandler
from mcp_bridge.tests.test_provider_network import CUSTOM


class GenericProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.server_tls,self.client_tls=certificate(self.root)
        config=copy.deepcopy(CUSTOM);config['caldav']={'preset':'custom','origin':'https://calendar.example.test/','allowed_hosts':['calendar.example.test']}
        config['carddav']={'preset':'custom','origin':'https://contacts.example.test/','allowed_hosts':['contacts.example.test']}
        self.config=config;self.profiles=parse_profiles(config)
        accounts=self.root/'accounts';accounts.mkdir(mode=0o700)
        self.accounts=AccountSecrets(accounts,profiles=self.profiles)
        self.accounts.persist('mail','synthetic-login','SYNTHETIC_ONLY',None,'sender@example.invalid')
        self.accounts.persist('caldav','calendar-login','SYNTHETIC_CAL_ONLY',None)
        self.accounts.persist('carddav','contacts-login','SYNTHETIC_CARD_ONLY',None)
        identity=self.root/'identity';identity.mkdir(mode=0o700);self.store=Store(identity/'identity.sqlite3')
        self.context_patch=patch('bridge.app.tls_context',return_value=self.client_tls);self.context_patch.start()
        self.mail_context_patch=patch('mcp_bridge.mail_ops.tls_context',return_value=self.client_tls);self.mail_context_patch.start()
        self.cal_context_patch=patch('mcp_bridge.calendar_ops.tls_context',return_value=self.client_tls);self.cal_context_patch.start()
        self.check_context_patch=patch('mcp_bridge.accounts.tls_context',return_value=self.client_tls);self.check_context_patch.start()
    def tearDown(self):
        self.context_patch.stop();self.mail_context_patch.stop();self.cal_context_patch.stop();self.check_context_patch.stop();self.store.close();self.temp.cleanup()

    def test_custom_imap_read_only_search_read_and_folder_discovery_over_tls(self):
        with running(IMAPHandler,self.server_tls) as server, patch('bridge.network.public_socket',side_effect=fixture_dial(server,'imap.example.test',993)):
            adapter=MailOperations(self.accounts,self.store)
            self.assertEqual(adapter.list_folders({})['items'][0]['name'],'INBOX')
            self.assertEqual(adapter.read_operation('search',{'query':'Synthetic'})['items'][0]['uid'],7)
            self.assertIn('Synthetic body only',adapter.read_operation('read',{'uid':7,'uidvalidity':111})['body'])
        self.assertTrue(all(event.get('tls') for event in server.events));self.assertFalse(any(event.get('command') in ('CLOSE','EXPUNGE','SELECT','STORE','MOVE') for event in server.events))

    def test_custom_smtp_starttls_happens_before_auth_and_separate_sender_used(self):
        with running(SMTPHandler,self.server_tls,immediate=False) as server, patch('bridge.network.public_socket',side_effect=fixture_dial(server,'smtp.example.test',587)):
            adapter=MailOperations(self.accounts,self.store)
            preview=adapter.prepare_send({'to':['recipient@example.invalid'],'subject':'Synthetic','body':'Synthetic only'})
            self.assertEqual(preview['preview']['from'],'sender@example.invalid')
            result=adapter.send({'preview_id':preview['preview_id'],'preview_hash':preview['preview_hash'],'idempotency_key':'synthetic-send-fixture-0001','confirmed':True})
            self.assertTrue(result['smtp_accepted'])
        auth=[event for event in server.events if event.get('command')=='AUTH'];self.assertTrue(auth);self.assertTrue(all(event['tls'] for event in auth))
        self.assertEqual(sum(event.get('command')=='DATA' for event in server.events),1)

    def test_custom_smtp_implicit_tls_and_no_plaintext_fallback(self):
        with running(SMTPHandler,self.server_tls) as server, patch('bridge.network.public_socket',side_effect=fixture_dial(server,'smtp.example.test',465)):
            client=smtp_connection('smtp.example.test',465,context=self.client_tls);client.ehlo();self.assertEqual(client.login('synthetic','SYNTHETIC_ONLY')[0],235);client.quit()
        self.assertTrue(all(event.get('tls') for event in server.events))
        with running(SMTPHandler,self.server_tls,immediate=False) as server, patch('bridge.network.public_socket',side_effect=fixture_dial(server,'smtp.example.test',587)):
            server.support_starttls=False
            with self.assertRaises(OSError):smtp_connection('smtp.example.test',587,context=self.client_tls)
        self.assertFalse(any(event.get('command')=='AUTH' for event in server.events))

    def test_custom_caldav_discovery_read_privacy_and_conditional_create_commit(self):
        with running(DAVHandler,self.server_tls) as server, patch('bridge.network.public_socket',side_effect=fixture_dial(server,'calendar.example.test',443)):
            adapter=CalendarOperations(self.accounts,self.store)
            identifier=adapter.list({})['items'][0]['id']
            events=adapter.events({'calendar_id':identifier,'start':'2026-10-10T00:00:00Z','end':'2026-10-11T00:00:00Z'})
            self.assertEqual(events['items'][0]['summary'],'Fixture event')
            self.store.set_calendar_consent(self.accounts.revision('caldav'),identifier,False)
            preview=adapter.prepare('create',{'calendar_id':identifier,'summary':'Synthetic','start':'2026-10-10T12:00:00Z','end':'2026-10-10T12:05:00Z'})
            self.assertEqual(preview['preview']['calendar_audience'],'private_verified')
            result=adapter.commit({'preview_id':preview['preview_id'],'preview_hash':preview['preview_hash'],'idempotency_key':'synthetic-create-fixture-0001','confirmed':True})
            self.assertTrue(result['changed'])
            self.assertEqual(sum(event.get('method')=='PUT' for event in server.events),1)
            self.assertEqual(len(server.objects),1)
        self.assertTrue(all(event.get('tls') and event.get('auth_present') for event in server.events))

    def test_custom_carddav_discovery_search_multiget_with_minimal_fields_only(self):
        with running(DAVHandler,self.server_tls) as server, patch('bridge.network.public_socket',side_effect=fixture_dial(server,'contacts.example.test',443)):
            adapter=Contacts(self.accounts)
            client,books=adapter.discover();book=books[0]
            found=adapter.search_book(client,book,'Example',2);self.assertEqual(found['items'][0]['name'],'Example Person')
            item=adapter.read_resource(client,book,found['items'][0]['_resource_url'])
            self.assertEqual(item['emails'],['person@example.invalid']);self.assertNotIn('photo',item);self.assertNotIn('note',item)
            self.assertEqual(set(event.get('method') for event in server.events),{'PROPFIND','REPORT'})
        self.assertTrue(all(event.get('tls') and event.get('auth_present') for event in server.events))

    def test_custom_caldav_unknown_audience_and_denied_privileges_remain_fail_closed(self):
        with running(DAVHandler,self.server_tls) as server, patch('bridge.network.public_socket',side_effect=fixture_dial(server,'calendar.example.test',443)):
            adapter=CalendarOperations(self.accounts,self.store);identifier=adapter.list({})['items'][0]['id']
            self.store.set_calendar_consent(self.accounts.revision('caldav'),identifier,False);server.include_acl=False
            data={'calendar_id':identifier,'summary':'Synthetic','start':'2026-10-10T12:00:00Z','end':'2026-10-10T12:05:00Z'}
            with self.assertRaises(ApiError) as caught:adapter.prepare('create',data)
            self.assertEqual(caught.exception.code,'calendar_audience_acknowledgement_required')
            self.store.set_calendar_consent(self.accounts.revision('caldav'),identifier,True);server.privilege_mode='deny'
            with self.assertRaises(ApiError) as caught:adapter.prepare('create',data)
            self.assertEqual(caught.exception.code,'calendar_write_permission_denied');self.assertFalse(any(event.get('method')=='PUT' for event in server.events))

    def test_custom_caldav_update_delete_keep_etag_and_simple_event_guards(self):
        from mcp_bridge.tests.test_writes import INITIAL
        path='/calendars/example/event.ics'
        with running(DAVHandler,self.server_tls) as server, patch('bridge.network.public_socket',side_effect=fixture_dial(server,'calendar.example.test',443)):
            server.objects[path]=(INITIAL,'"fixture-old"');adapter=CalendarOperations(self.accounts,self.store);identifier=adapter.list({})['items'][0]['id']
            self.store.set_calendar_consent(self.accounts.revision('caldav'),identifier,False)
            preview=adapter.prepare('update',{'calendar_id':identifier,'object_id':calendar_id('https://calendar.example.test'+path),'etag':'"fixture-old"',
                                    'summary':'Synthetic update','start':'2026-10-10T12:00:00Z','end':'2026-10-10T12:05:00Z'})
            adapter.commit({'preview_id':preview['preview_id'],'preview_hash':preview['preview_hash'],'idempotency_key':'synthetic-update-fixture-0001','confirmed':True})
            preview=adapter.prepare('delete',{'calendar_id':identifier,'object_id':calendar_id('https://calendar.example.test'+path),'etag':'"fixture-new"'})
            server.objects[path]=(server.objects[path][0],'"fixture-conflict"')
            with self.assertRaises(ApiError):adapter.commit({'preview_id':preview['preview_id'],'preview_hash':preview['preview_hash'],'idempotency_key':'synthetic-delete-fixture-conflict','confirmed':True})
            self.assertIn(path,server.objects);server.objects[path]=(server.objects[path][0],'"fixture-new"')
            preview=adapter.prepare('delete',{'calendar_id':identifier,'object_id':calendar_id('https://calendar.example.test'+path),'etag':'"fixture-new"'})
            adapter.commit({'preview_id':preview['preview_id'],'preview_hash':preview['preview_hash'],'idempotency_key':'synthetic-delete-fixture-0001','confirmed':True})
            self.assertNotIn(path,server.objects)

    def test_generic_tls_rejects_wrong_certificate_hostname_before_auth(self):
        with running(DAVHandler,self.server_tls) as server, patch('bridge.network.public_socket',side_effect=lambda *args,**kw:fixture_dial(server,'contacts.example.test',443)('contacts.example.test',443)):
            config=copy.deepcopy(self.config);config['carddav']={'preset':'custom','origin':'https://wrong.example.test/','allowed_hosts':['wrong.example.test']}
            accounts=AccountSecrets(self.root/'accounts',profiles=parse_profiles(config));status=accounts.status(True)['carddav'];accounts.persist('carddav','contacts-login','SYNTHETIC_CARD_ONLY',status['revision'])
            with self.assertRaises(OSError):Contacts(accounts).discover()
        self.assertFalse(any(event.get('auth_present') for event in server.events))
