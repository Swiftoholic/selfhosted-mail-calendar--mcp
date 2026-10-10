"""Multi-account adapters against disposable local TLS servers, never providers."""
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bridge.app import ApiError, calendar_id
from bridge.providers import parse_profiles
from mcp_bridge.accounts import ConnectionChecks
from mcp_bridge.operations import Operations
from mcp_bridge.tests.multi_fixtures import MemoryAccounts, synthetic_store
from mcp_bridge.tests.protocol_fixtures import certificate, running, fixture_dial, IMAPHandler, SMTPHandler, DAVHandler


def profiles():
    entries = {}
    for suffix in ('', '2'):
        entries['mail'+suffix] = {'protocol':'mail','name':'Synthetic mail '+suffix,'config':{
            'preset':'custom','imap':{'host':'imap'+suffix+'.example.test','port':993,'tls':'implicit'},
            'smtp':{'host':'smtp'+suffix+'.example.test','port':587,'tls':'starttls_required'}}}
        for protocol, host in (('caldav','calendar'),('carddav','contacts')):
            hostname=host+suffix+'.example.test'
            entries[protocol+suffix]={'protocol':protocol,'name':'Synthetic '+protocol+suffix,
                'config':{'preset':'custom','origin':'https://'+hostname+'/', 'allowed_hosts':[hostname]}}
    return parse_profiles({'version':2,'profiles':entries,'defaults':{'mail':'mail','caldav':'caldav','carddav':'carddav'}})


class MultiProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.stack=ExitStack()
        self.server_tls,self.client_tls=certificate(Path(self.temp.name))
        self.store,self.identity_temp=synthetic_store()
        self.accounts=MemoryAccounts(profiles=profiles())
        for name in ('bridge.app.tls_context','mcp_bridge.mail_ops.tls_context',
                     'mcp_bridge.calendar_ops.tls_context','mcp_bridge.accounts.tls_context'):
            self.stack.enter_context(patch(name,return_value=self.client_tls))
        self.backend=Operations(self.store,self.accounts)
        self.rows={}
        for protocol,rights in (('mail',['mail:read','mail:send']),('caldav',['calendars:read','calendars:write']),('carddav',['contacts:read'])):
            for suffix in ('','2'):
                self.rows[protocol+suffix]=self.accounts.seed(protocol,protocol+suffix+'@example.invalid',rights,
                    profile_id=protocol+suffix,sender='sender'+suffix+'@example.invalid')
        self.servers={}

    def tearDown(self):
        self.stack.close();self.store.close();self.identity_temp.cleanup();self.temp.cleanup()

    def server(self,host,handler,row,port,immediate=True):
        server=self.stack.enter_context(running(handler,self.server_tls,immediate))
        server.expected_pair=(row['username'],'SYNTHETIC_ONLY_NOT_A_PASSWORD')
        self.servers[host]=(server,port)
        return server

    def dial(self,host,port,timeout=8):
        if host not in self.servers:raise AssertionError('unconfigured_synthetic_destination')
        server,expected=self.servers[host]
        return fixture_dial(server,host,expected)(host,port,timeout)

    def call(self,path,key,**data):
        return self.backend.call('POST',path,{'account_id':self.rows[key]['id'],**data})

    def assert_auth(self,server):
        events=[item for item in server.events if 'authentication_matches' in item]
        self.assertTrue(events);self.assertTrue(all(item['authentication_matches'] for item in events))
        self.assertFalse(any(item.get('tls') is False and item.get('command')=='AUTH' for item in server.events))

    def test_two_mail_accounts_isolate_equal_folder_ids_and_read_over_verified_tls(self):
        servers=[self.server('imap'+suffix+'.example.test',IMAPHandler,self.rows['mail'+suffix],993) for suffix in ('','2')]
        with patch('bridge.network.public_socket',side_effect=self.dial):
            folders=[self.call('/mcp/mail/folders','mail'+suffix) for suffix in ('','2')]
            self.assertNotEqual(folders[0]['items'][0]['id'],folders[1]['items'][0]['id'])
            for suffix,result in zip(('','2'),folders):
                found=self.call('/v1/mail/search','mail'+suffix,mailbox_id=result['items'][0]['id'],query='Synthetic')
                self.assertEqual(found['items'][0]['uid'],7)
                item=self.call('/v1/mail/read','mail'+suffix,mailbox_id=result['items'][0]['id'],uid=7,uidvalidity=111)
                self.assertIn('Synthetic body only',item['body'])
        for server in servers:
            self.assert_auth(server)
            self.assertTrue(all(event.get('tls',True) for event in server.events))
            self.assertFalse(any(event.get('command') in ('STORE','MOVE','EXPUNGE','CLOSE','SELECT') for event in server.events))

    def test_two_smtp_accounts_bind_preview_sender_credentials_and_global_replay_receipt(self):
        servers=[self.server('smtp'+suffix+'.example.test',SMTPHandler,self.rows['mail'+suffix],587,False) for suffix in ('','2')]
        for suffix,server in zip(('','2'),servers):server.expected_sender='sender'+suffix+'@example.invalid'
        previews=[self.call('/mcp/mail/prepare-send','mail'+suffix,to=['recipient@example.invalid'],subject='Synthetic',body='Fixture only') for suffix in ('','2')]
        with patch('bridge.network.public_socket',side_effect=self.dial) as sockets:
            with self.assertRaises(ApiError):self.call('/mcp/mail/send','mail2',preview_id=previews[0]['preview_id'],preview_hash=previews[0]['preview_hash'],idempotency_key='synthetic-cross-account-0001',confirmed=True)
            sockets.assert_not_called()
            for index,(suffix,preview) in enumerate(zip(('','2'),previews)):
                result=self.call('/mcp/mail/send','mail'+suffix,preview_id=preview['preview_id'],preview_hash=preview['preview_hash'],idempotency_key='synthetic-local-send-'+str(index),confirmed=True)
                self.assertTrue(result['smtp_accepted'])
            before=sockets.call_count
            with self.assertRaises((ApiError,ValueError)):self.call('/mcp/mail/send','mail2',preview_id=previews[1]['preview_id'],preview_hash=previews[1]['preview_hash'],idempotency_key='synthetic-local-send-0',confirmed=True)
            self.assertEqual(sockets.call_count,before)
        for server in servers:
            self.assert_auth(server);self.assertTrue(all(event.get('sender_matches',True) for event in server.events))
            self.assertEqual(sum(item.get('command')=='DATA' for item in server.events),1)

    def test_caldav_accounts_have_separate_consents_and_conditional_fixture_write(self):
        servers=[self.server('calendar'+suffix+'.example.test',DAVHandler,self.rows['caldav'+suffix],443) for suffix in ('','2')]
        with patch('bridge.network.public_socket',side_effect=self.dial):
            lists=[self.call('/v1/calendars/list','caldav'+suffix) for suffix in ('','2')]
            raw_id=calendar_id('https://calendar.example.test/calendars/example/')
            self.store.set_calendar_consent(self.rows['caldav']['revision'],raw_id,False)
            self.assertFalse(self.call('/v1/calendars/list','caldav2')['items'][0]['write_consent_enabled'])
            preview=self.call('/mcp/calendar/prepare-create','caldav',calendar_id=lists[0]['items'][0]['id'],summary='Synthetic',start='2026-10-10T12:00:00Z',end='2026-10-10T12:05:00Z')
            self.assertEqual(preview['preview']['calendar_audience'],'private_verified')
            with self.assertRaises(ApiError):self.call('/mcp/calendar/commit','caldav2',preview_id=preview['preview_id'],preview_hash=preview['preview_hash'],idempotency_key='synthetic-caldav-wrong-0001',confirmed=True)
            result=self.call('/mcp/calendar/commit','caldav',preview_id=preview['preview_id'],preview_hash=preview['preview_hash'],idempotency_key='synthetic-caldav-right-0001',confirmed=True)
            self.assertTrue(result['changed'])
        for server in servers:self.assert_auth(server)
        self.assertEqual(len(servers[0].objects),1);self.assertEqual(servers[1].objects,{})

    def test_carddav_consent_and_contact_references_cannot_cross_accounts(self):
        servers=[self.server('contacts'+suffix+'.example.test',DAVHandler,self.rows['carddav'+suffix],443) for suffix in ('','2')]
        with patch('bridge.network.public_socket',side_effect=self.dial) as sockets:
            self.assertEqual(self.call('/mcp/contacts/books','carddav')['items'],[])
            self.assertEqual(self.call('/mcp/contacts/books','carddav2')['items'],[])
            identifiers=[]
            for suffix in ('','2'):
                self.store.set_contacts_consent(self.rows['carddav'+suffix]['revision'],calendar_id('https://contacts'+suffix+'.example.test/addressbooks/example/'))
                identifiers.append(self.call('/mcp/contacts/books','carddav'+suffix)['items'][0]['id'])
            result=self.call('/mcp/contacts/search','carddav',addressbook_id=identifiers[0],query='Example')
            before=sockets.call_count
            with self.assertRaises(ApiError):self.call('/mcp/contacts/read','carddav2',contact_id=result['items'][0]['id'])
            self.assertEqual(sockets.call_count,before)
            item=self.call('/mcp/contacts/read','carddav',contact_id=result['items'][0]['id'])
            self.assertEqual(item['emails'],['person@example.invalid']);self.assertNotIn('note',item);self.assertNotIn('photo',item)
        for server in servers:
            self.assert_auth(server)
            self.assertFalse(any(event.get('method') in ('PUT','POST','DELETE','GET') for event in server.events))

    def test_explicit_checks_for_six_accounts_use_correct_profile_and_send_nothing(self):
        for suffix in ('','2'):
            self.server('imap'+suffix+'.example.test',IMAPHandler,self.rows['mail'+suffix],993)
            self.server('smtp'+suffix+'.example.test',SMTPHandler,self.rows['mail'+suffix],587,False)
            for protocol,host in (('caldav','calendar'),('carddav','contacts')):
                self.server(host+suffix+'.example.test',DAVHandler,self.rows[protocol+suffix],443)
        checks=ConnectionChecks()
        with patch('bridge.network.public_socket',side_effect=self.dial):
            for key,row in self.rows.items():
                with self.accounts.operation(row['protocol'],row['id']) as snapshot:
                    self.assertTrue(checks.check(row['protocol'],snapshot.username,snapshot.password,profiles=self.accounts.profiles)['connected'])
        for server,_ in self.servers.values():
            self.assert_auth(server)
            self.assertFalse(any(event.get('command')=='DATA' or event.get('method') in ('REPORT','GET','PUT','POST','DELETE') for event in server.events))

    def test_wrong_tls_hostname_is_rejected_before_any_account_credentials_are_sent(self):
        wrong=parse_profiles({'version':2,'profiles':{'wrong-carddav':{'protocol':'carddav','name':'Synthetic wrong TLS host',
            'config':{'preset':'custom','origin':'https://wrong.example.test/','allowed_hosts':['wrong.example.test']}}},
            'defaults':{'mail':'gmx-mail','caldav':'icloud-caldav','carddav':'wrong-carddav'}})
        self.accounts.catalog.entries.update(wrong.entries)
        row=self.accounts.seed('carddav','wrong@example.invalid',['contacts:read'],profile_id='wrong-carddav')
        self.rows['wrong']=row
        server=self.server('wrong.example.test',DAVHandler,row,443)
        with patch('bridge.network.public_socket',side_effect=self.dial):
            with self.assertRaises(OSError):self.call('/mcp/contacts/books','wrong')
        self.assertFalse(any('authentication_matches' in event or event.get('auth_present') for event in server.events))
