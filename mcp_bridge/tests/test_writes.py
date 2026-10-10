"""All provider mutations are intercepted by fixtures, with networking disabled."""
import copy
import io
import json
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from bridge.app import ApiError, CAL, DAV, calendar_id
from mcp_bridge.calendar_ops import CalendarOperations, CS, event_fields, inspect_event, render_event
from mcp_bridge.config import READ_SCOPES, SCOPES
from mcp_bridge.mail_ops import MailOperations, folder_id
from mcp_bridge.operations import Operations
from mcp_bridge.server import create_app
from mcp_bridge.store import Store
from mcp_bridge.tests.test_security import FixtureCIMD, SecurityTests
from starlette.testclient import TestClient


class FixtureSecrets:
    def revision(self,name):return 'f'*24
    def pair(self,name):
        if name not in {'mail','caldav','carddav'}:raise AssertionError('unapproved_provider')
        return 'owner@example.invalid','fixture-only-not-a-real-password'


class MissingSecrets:
    def pair(self,name):raise ApiError(503,'provider_not_configured')


class IMAPFixture:
    def __init__(self):
        self.capabilities=('IMAP4REV1','MOVE','UIDPLUS')
        self.messages={'INBOX':{7:set()},'Archive':{},'Trash':{}}
        self.validity={'INBOX':111,'Archive':222,'Trash':333}
        self.selected='INBOX';self.commands=[];self.mapping=None

    def factory(self,*args,**kwargs):return self
    def login(self,*args):return 'OK',[]
    def logout(self):return 'BYE',[]
    def _quote(self,name):return '"'+name.replace('\\','\\\\').replace('"','\\"')+'"'
    def list(self):return 'OK',[b'(\\HasNoChildren) "/" "INBOX"',b'(\\HasNoChildren) "/" "Archive"',b'(\\Trash) "/" "Trash"']
    def select(self,name,readonly=False):self.selected=name.strip('"');self.commands.append(('SELECT',readonly));return 'OK',[]
    def response(self,name):
        if name=='UIDVALIDITY':return name,[str(self.validity[self.selected]).encode()]
        if name=='UIDNEXT':return name,[b'8']
        if name=='COPYUID':return name,[self.mapping] if self.mapping else []
        raise AssertionError('unapproved_response')
    def uid(self,command,uid,*args):
        self.commands.append((command,uid,*args))
        if command=='FETCH':
            flags=self.messages[self.selected].get(int(uid))
            return ('OK',[b'1 (UID '+uid.encode()+b' FLAGS ('+b' '.join(x.encode() for x in flags)+b'))']) if flags is not None else ('OK',[])
        if command=='STORE':
            flag=args[1].strip('()');flags=self.messages[self.selected][int(uid)]
            if args[0].startswith('+'):flags.add(flag)
            else:flags.discard(flag)
            return 'OK',[]
        if command=='MOVE':
            target=args[0].strip('"');self.messages[target][77]=self.messages[self.selected].pop(int(uid))
            self.mapping=str(self.validity[target]).encode()+b' '+uid.encode()+b' 77';return 'OK',[]
        raise AssertionError('unrestricted_imap_command')


class SMTPFixture:
    def __init__(self):self.data_count=0;self.payload=None;self.reject=None;self.uncertain=False;self.rcpts=[]
    def factory(self,*args,**kwargs):
        assert args[:2]==('mail.gmx.net',465)
        return self
    def ehlo(self):return 250,b'ok'
    def login(self,*args):return 235,b'ok'
    def mail(self,who):return 250,b'ok'
    def rcpt(self,who):self.rcpts.append(who);return (550,b'no') if who==self.reject else (250,b'ok')
    def rset(self):return 250,b'reset'
    def data(self,raw):
        self.data_count+=1;self.payload=raw
        if self.uncertain:raise TimeoutError('fixture-ambiguous-result')
        return 250,b'accepted'
    def quit(self):return 221,b'bye'
    def close(self):pass


ROOT='https://p01-caldav.icloud.com'
CALENDAR=ROOT+'/calendars/private/'
OBJECT=CALENDAR+'event.ics'
INITIAL=render_event({'UID':'fixture-event@example.invalid','DTSTART':'20261010T120000Z','DTEND':'20261010T130000Z','SUMMARY':'Fixture event','SEQUENCE':'0'})


def xml_response(url,properties):
    root=ET.Element('{'+DAV+'}multistatus');response=ET.SubElement(root,'{'+DAV+'}response')
    ET.SubElement(response,'{'+DAV+'}href').text=url
    state=ET.SubElement(response,'{'+DAV+'}propstat');ET.SubElement(state,'{'+DAV+'}status').text='HTTP/1.1 200 OK'
    prop=ET.SubElement(state,'{'+DAV+'}prop')
    for node in properties:prop.append(node)
    return root


def value(namespace,name,text=None,child=None):
    node=ET.Element('{'+namespace+'}'+name);node.text=text
    if child is not None:node.append(child)
    return node


class DAVFixture:
    def __init__(self):self.private=True;self.shared=False;self.privileges=None;self.deny_write=False;self.objects={OBJECT:(INITIAL,'"v1"')};self.writes=[];self.requests=[];self.force_conflict=False;self.redirect=False
    def factory(self,credentials):return self
    def request(self,method,url,payload,depth='0'):
        names=ET.fromstring(payload)
        if method=='REPORT':
            return xml_response(OBJECT,[value(CAL,'calendar-data',self.objects[OBJECT][0].decode()),value(DAV,'getetag',self.objects[OBJECT][1])]),url
        if names.find('.//{'+DAV+'}current-user-principal') is not None:
            return xml_response(ROOT+'/',[value(DAV,'current-user-principal',child=value(DAV,'href','/principal/owner/'))]),ROOT+'/'
        if names.find('.//{'+CAL+'}calendar-home-set') is not None:
            return xml_response(url,[value(CAL,'calendar-home-set',child=value(DAV,'href','/calendars/'))]),url
        if names.find('.//{'+DAV+'}owner') is not None:
            properties=[value(DAV,'owner',child=value(DAV,'href','/principal/owner/'))]
            if self.private:
                acl=value(DAV,'acl');ace=ET.SubElement(acl,'{'+DAV+'}ace');principal=ET.SubElement(ace,'{'+DAV+'}principal');ET.SubElement(principal,'{'+DAV+'}href').text='/principal/owner/'
                grant=ET.SubElement(ace,'{'+DAV+'}grant');privilege=ET.SubElement(grant,'{'+DAV+'}privilege');ET.SubElement(privilege,'{'+DAV+'}all')
                properties.append(acl)
            if self.shared:properties.append(value(CS,'shared-url','https://calendar.example.invalid/share'))
            if self.privileges is not None:
                privileges=value(DAV,'current-user-privilege-set')
                for name in self.privileges:privileges.append(value(DAV,'privilege',child=value(DAV,name)))
                properties.append(privileges)
            return xml_response(url,properties),url
        if names.find('.//{'+DAV+'}getetag') is not None:
            root=ET.Element('{'+DAV+'}multistatus')
            for href,(_,etag) in self.objects.items():root.extend(xml_response(href,[value(DAV,'getetag',etag)]))
            return root,url
        return xml_response(CALENDAR,[value(DAV,'resourcetype',child=value(CAL,'calendar')),value(DAV,'displayname','Private fixture calendar')]),url

    def connection(self,*args,**kwargs):
        fixture=self
        class Connection:
            def request(self,method,path,body=None,headers=None):self.method,self.url,self.body,self.headers=method,ROOT+path,body,headers;fixture.requests.append((method,headers))
            def getresponse(self):
                method,url,headers=self.method,self.url,self.headers
                status,raw,etag=200,b'',None
                if fixture.redirect:status=307
                elif fixture.deny_write and method in {'PUT','DELETE'}:status=403
                elif method=='GET':
                    if url in fixture.objects:raw,etag=fixture.objects[url]
                    else:status=404
                elif fixture.force_conflict:status=412
                elif method=='PUT':
                    if headers.get('If-None-Match')=='*' and url in fixture.objects:status=412
                    elif headers.get('If-Match') and (url not in fixture.objects or fixture.objects[url][1]!=headers['If-Match']):status=412
                    else:
                        status=204 if url in fixture.objects else 201;etag='"v2"';fixture.objects[url]=(self.body,etag);fixture.writes.append((method,url))
                elif method=='DELETE':
                    if url not in fixture.objects or fixture.objects[url][1]!=headers.get('If-Match'):status=412
                    else:status=204;fixture.objects.pop(url);fixture.writes.append((method,url))
                else:raise AssertionError('unrestricted_caldav_method')
                class Response:
                    def __init__(self):self.status=status
                    def read(self,n):return raw[:n]
                    def getheader(self,key):return etag if key=='ETag' else None
                return Response()
            def close(self):pass
        return Connection()


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.offset=0
        import time
        self.store=Store(Path(self.temp.name)/'identity.sqlite3',clock=lambda:time.time()+self.offset)
        self.imap,self.smtp,self.dav=IMAPFixture(),SMTPFixture(),DAVFixture()
        self.mail=MailOperations(FixtureSecrets(),self.store,self.imap.factory,self.smtp.factory)
        self.calendar=CalendarOperations(FixtureSecrets(),self.store,self.dav.factory,self.dav.connection)
        self.backend=Operations(self.store,FixtureSecrets(),self.mail,self.calendar)
        self.store.set_calendar_consent('f'*24,calendar_id(CALENDAR),False)
    def tearDown(self):self.store.close();self.temp.cleanup()
    def mutation(self,**changes):
        return {'mailbox_id':folder_id('INBOX'),'uid':7,'uidvalidity':111,'idempotency_key':'fixture-operation-0001','confirmed':True,**changes}
    def draft(self,**changes):
        return self.mail.prepare_send({'to':['recipient@example.invalid'],'subject':'Fixture subject','body':'Fixture body',**changes})
    def send_args(self,draft,**changes):
        return {'preview_id':draft['preview_id'],'preview_hash':draft['preview_hash'],'idempotency_key':'fixture-send-0001','confirmed':True,**changes}
    def event(self,**changes):
        return {'calendar_id':calendar_id(CALENDAR),'summary':'Fixture new title','start':'2026-10-10T12:00:00Z','end':'2026-10-10T13:00:00Z','description':'Fixture description',**changes}
    def commit_args(self,preview,**changes):
        return {'preview_id':preview['preview_id'],'preview_hash':preview['preview_hash'],'idempotency_key':'fixture-calendar-0001','confirmed':True,**changes}

    def test_folder_ids_and_trash_discovery(self):
        rows=self.mail.list_folders({})['items'];self.assertEqual(len(rows),3);self.assertEqual([v['id'] for v in rows if v['is_trash']],[folder_id('Trash')])
    def test_flags_read_unread_and_flagged_only(self):
        self.mail.mutate('flags',self.mutation(read=True,flagged=True));self.assertEqual(self.imap.messages['INBOX'][7],{'\\Seen','\\Flagged'})
        self.mail.mutate('flags',self.mutation(read=False,flagged=False,idempotency_key='fixture-operation-0002'));self.assertEqual(len(self.imap.messages['INBOX'][7]),0)
        self.assertFalse(any(command[0] in {'CLOSE','EXPUNGE'} for command in self.imap.commands))
    def test_move_and_stable_new_uid(self):
        result=self.mail.mutate('move',self.mutation(target_mailbox_id=folder_id('Archive')))
        self.assertEqual(result['target_uid'],77);self.assertEqual(result['target_uidvalidity'],222);self.assertNotIn(7,self.imap.messages['INBOX'])
    def test_move_missing_uid_mapping_requires_rescan(self):
        original=self.imap.response
        self.imap.response=lambda name:(name,[]) if name=='COPYUID' else original(name)
        result=self.mail.mutate('move',self.mutation(target_mailbox_id=folder_id('Archive')))
        self.assertTrue(result['rescan_required']);self.assertIsNone(result['target_uid'])
    def test_trash_and_restore_no_purge(self):
        result=self.mail.mutate('trash',self.mutation());self.assertTrue(result['recoverable_trash']);self.assertFalse(result['permanent_purge'])
        self.mail.mutate('move',self.mutation(mailbox_id=folder_id('Trash'),uid=77,uidvalidity=333,target_mailbox_id=folder_id('INBOX'),idempotency_key='fixture-restore-0001'))
        self.assertIn(77,self.imap.messages['INBOX']);self.assertEqual(len(self.imap.messages['Trash']),0)
    def test_stale_uidvalidity_blocks_store(self):
        with self.assertRaises(ApiError):self.mail.mutate('flags',self.mutation(uidvalidity=9,read=True))
        self.assertFalse(any(v[0]=='STORE' for v in self.imap.commands))
    def test_unknown_folder_or_message_blocks_move(self):
        for changes in ({'target_mailbox_id':'0'*24},{'uid':999,'target_mailbox_id':folder_id('Archive')}):
            with self.assertRaises(ApiError):self.mail.mutate('move',self.mutation(**changes,idempotency_key='fixture-key-'+str(len(self.imap.commands)).zfill(8)))
        self.assertFalse(any(v[0]=='MOVE' for v in self.imap.commands))
    def test_move_extension_required_no_unsafe_fallback(self):
        self.imap.capabilities=('IMAP4REV1',)
        with self.assertRaises(ApiError):self.mail.mutate('trash',self.mutation())
        self.assertFalse(any(v[0] in {'MOVE','COPY','STORE','EXPUNGE'} for v in self.imap.commands))
    def test_move_lookalike_denied_failed_receipt_requires_fresh_key(self):
        self.imap.capabilities=('IMAP4REV1','NOTMOVE','UIDPLUS')
        before=copy.deepcopy(self.imap.messages)
        with self.assertRaises(ApiError) as error:self.mail.mutate('trash',self.mutation())
        self.assertEqual(error.exception.code,'server_uid_move_required');self.assertEqual(self.imap.messages,before)
        self.imap.capabilities=('IMAP4REV1','MOVE','UIDPLUS')
        count=len(self.imap.commands)
        with self.assertRaisesRegex(ValueError,'operation_outcome_uncertain_do_not_retry'):self.mail.mutate('trash',self.mutation())
        self.assertEqual(len(self.imap.commands),count)
        self.assertTrue(self.mail.mutate('trash',self.mutation(idempotency_key='fixture-fresh-move-0001'))['recoverable_trash'])
        self.assertEqual(sum(v[0]=='MOVE' for v in self.imap.commands),1)
        self.assertFalse(any(v[0] in {'COPY','EXPUNGE','CLOSE'} for v in self.imap.commands))
    def test_no_arbitrary_flags_or_permanent_delete(self):
        for path in ('/mcp/mail/purge','/mcp/mail/empty-trash','/mcp/mail/command'):
            with self.assertRaises(ApiError):self.backend.call('POST',path,{})
        with self.assertRaises(ApiError):self.mail.mutate('flags',self.mutation(flags=['\\Deleted']))
    def test_move_idempotency_and_payload_conflict(self):
        data=self.mutation(target_mailbox_id=folder_id('Archive'));self.mail.mutate('move',data)
        self.assertTrue(self.mail.mutate('move',data)['replayed_receipt'])
        with self.assertRaises(ValueError):self.mail.mutate('move',{**data,'target_mailbox_id':folder_id('Trash')})
        self.assertEqual(len([c for c in self.imap.commands if c[0]=='MOVE']),1)
    def test_explicit_mutation_confirmation_required(self):
        with self.assertRaises(ApiError):self.mail.mutate('flags',self.mutation(read=True,confirmed=False))
        self.assertEqual(len(self.imap.commands),0)
    def test_prepare_send_never_connects_smtp(self):
        preview=self.draft();self.assertFalse(preview['sent']);self.assertFalse(preview['server_draft_created']);self.assertEqual(self.smtp.data_count,0)
    def test_recipient_header_injection_and_bounds(self):
        for values in (['bad\r\nBcc: attacker@example.invalid'],['Name <recipient@example.invalid>'],['a@example.invalid']*21):
            with self.assertRaises(ApiError):self.draft(to=values)
        with self.assertRaises(ApiError):self.draft(subject='Hello\nInjected')
        with self.assertRaises(ApiError):self.draft(body='x'*10001)
        with self.assertRaises(ApiError):self.draft(attachments=['anything'])
    def test_send_once_bcc_private_and_no_delivery_claim(self):
        draft=self.draft(cc=['cc@example.invalid'],bcc=['hidden@example.invalid']);data=self.send_args(draft)
        result=self.mail.send(data);self.assertTrue(result['smtp_accepted']);self.assertFalse(result['delivery_confirmed'])
        self.assertNotIn(b'Bcc:',self.smtp.payload);self.assertIn('hidden@example.invalid',self.smtp.rcpts)
        self.assertTrue(self.mail.send(data)['replayed_receipt']);self.assertEqual(self.smtp.data_count,1)
        with self.assertRaises(ApiError):self.mail.send({**data,'idempotency_key':'fixture-send-0002'})
        self.assertEqual(self.smtp.data_count,1)
    def test_rejected_recipient_sends_to_nobody(self):
        self.smtp.reject='reject@example.invalid';draft=self.draft(to=['recipient@example.invalid','reject@example.invalid'])
        with self.assertRaises(ApiError):self.mail.send(self.send_args(draft))
        self.assertEqual(self.smtp.data_count,0)
    def test_smtp_quit_error_does_not_erase_acceptance(self):
        def quit_error():raise OSError('fixture-cleanup-error')
        self.smtp.quit=quit_error
        result=self.mail.send(self.send_args(self.draft()))
        self.assertTrue(result['smtp_accepted']);self.assertEqual(self.smtp.data_count,1)
    def test_ambiguous_send_not_retried(self):
        self.smtp.uncertain=True;draft=self.draft();data=self.send_args(draft)
        with self.assertRaises(TimeoutError):self.mail.send(data)
        with self.assertRaises(ValueError):self.mail.send(data)
        with self.assertRaises(ApiError):self.mail.send({**data,'idempotency_key':'fixture-send-0002'})
        self.assertEqual(self.smtp.data_count,1)
    def test_send_expired_changed_unconfirmed_preview(self):
        draft=self.draft()
        with self.assertRaises(ApiError):self.mail.send(self.send_args(draft,confirmed=False))
        with self.assertRaises(ApiError):self.mail.send(self.send_args(draft,preview_hash='wrong'))
        draft=self.draft();self.offset+=601
        with self.assertRaises(ApiError):self.mail.send(self.send_args(draft,idempotency_key='fixture-send-0002'))
        self.assertEqual(self.smtp.data_count,0)
    def test_two_send_keys_cannot_send_one_preview_twice(self):
        draft=self.draft();barrier=threading.Barrier(2)
        def send(n):
            barrier.wait()
            try:self.mail.send(self.send_args(draft,idempotency_key='fixture-concurrent-'+str(n)));return True
            except Exception:return False
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(send,range(2)))
        self.assertEqual(sum(results),1);self.assertEqual(self.smtp.data_count,1)
    def test_calendar_read_returns_object_ids_and_etags(self):
        result=self.calendar.events({'calendar_id':calendar_id(CALENDAR),'start':'2026-10-10T00:00:00Z','end':'2026-10-11T00:00:00Z','limit':10})
        self.assertEqual(result['items'][0]['object_id'],calendar_id(OBJECT));self.assertEqual(result['items'][0]['etag'],'"v1"')
    def test_create_preview_no_write_and_conditional_commit(self):
        preview=self.calendar.prepare('create',self.event());self.assertEqual(len(self.dav.writes),0)
        result=self.calendar.commit(self.commit_args(preview));self.assertEqual(result['action'],'create')
        self.assertEqual(len(self.dav.writes),1);self.assertEqual(self.dav.requests[-1][1]['If-None-Match'],'*')
        self.assertNotIn(b'ATTENDEE',next(raw for url,(raw,_) in self.dav.objects.items() if url!=OBJECT))
    def test_update_preserves_uid_and_uses_etag(self):
        preview=self.calendar.prepare('update',self.event(object_id=calendar_id(OBJECT),etag='"v1"'))
        self.calendar.commit(self.commit_args(preview));values=inspect_event(self.dav.objects[OBJECT][0])
        self.assertEqual(values['UID'],'fixture-event@example.invalid');self.assertEqual(values['SEQUENCE'],'1')
        self.assertEqual(self.dav.requests[-1][1]['If-Match'],'"v1"')
    def test_delete_preview_and_commit_no_hidden_reply(self):
        preview=self.calendar.prepare('delete',{'calendar_id':calendar_id(CALENDAR),'object_id':calendar_id(OBJECT),'etag':'"v1"'})
        self.assertTrue(preview['preview']['calendar_delete_has_no_bridge_undo']);self.assertIn(OBJECT,self.dav.objects)
        self.calendar.commit(self.commit_args(preview));self.assertNotIn(OBJECT,self.dav.objects)
        self.assertEqual(self.dav.requests[-1][1]['Schedule-Reply'],'F')
    def test_calendar_etag_change_after_preview(self):
        preview=self.calendar.prepare('update',self.event(object_id=calendar_id(OBJECT),etag='"v1"'));self.dav.objects[OBJECT]=(INITIAL,'"changed"')
        with self.assertRaises(ApiError):self.calendar.commit(self.commit_args(preview))
        self.assertEqual(len(self.dav.writes),0)
    def test_calendar_atomic_put_conflict(self):
        preview=self.calendar.prepare('create',self.event());self.dav.force_conflict=True
        with self.assertRaises(ApiError):self.calendar.commit(self.commit_args(preview))
        self.assertEqual(len(self.dav.writes),0)
    def test_weak_etag_and_untrusted_ids_rejected(self):
        for changes in ({'etag':'W/"v1"'},{'object_id':'https://attacker.invalid/event.ics'},{'etag':'*'}):
            with self.assertRaises(ApiError):self.calendar.prepare('update',self.event(object_id=calendar_id(OBJECT),etag='"v1"') | changes)
        self.assertEqual(len(self.dav.writes),0)
    def test_shared_or_unknown_calendar_privacy_rejected(self):
        self.dav.shared=True
        with self.assertRaises(ApiError):self.calendar.prepare('create',self.event())
        self.dav.shared=False;self.dav.private=False
        with self.assertRaises(ApiError):self.calendar.prepare('create',self.event())
        self.assertEqual(len(self.dav.writes),0)
    def test_attendees_organizers_recurrence_alarms_rejected(self):
        for line in ('ATTENDEE:mailto:person@example.invalid','ORGANIZER:mailto:owner@example.invalid','RRULE:FREQ=DAILY','ATTACH:https://attacker.invalid','BEGIN:VALARM\r\nEND:VALARM'):
            raw=INITIAL.replace(b'END:VEVENT',line.encode()+b'\r\nEND:VEVENT');self.dav.objects[OBJECT]=(raw,'"v1"')
            with self.assertRaises(ApiError):self.calendar.prepare('delete',{'calendar_id':calendar_id(CALENDAR),'object_id':calendar_id(OBJECT),'etag':'"v1"'})
        self.assertEqual(len(self.dav.writes),0)
    def test_calendar_text_no_ical_injection(self):
        preview=self.calendar.prepare('create',self.event(summary='Meeting\nATTENDEE:mailto:attacker@example.invalid'))
        self.calendar.commit(self.commit_args(preview))
        raw=next(raw for url,(raw,_) in self.dav.objects.items() if url!=OBJECT)
        self.assertNotIn(b'\r\nATTENDEE:',raw);self.assertIn(b'\\nATTENDEE:',raw)
    def test_calendar_preview_hash_confirmation_expiry(self):
        preview=self.calendar.prepare('create',self.event())
        with self.assertRaises(ApiError):self.calendar.commit(self.commit_args(preview,confirmed=False))
        with self.assertRaises(ApiError):self.calendar.commit(self.commit_args(preview,preview_hash='wrong'))
        preview=self.calendar.prepare('create',self.event());self.offset+=601
        with self.assertRaises(ApiError):self.calendar.commit(self.commit_args(preview,idempotency_key='fixture-calendar-0002'))
        self.assertEqual(len(self.dav.writes),0)
    def test_calendar_commit_receipt_and_single_use_preview(self):
        preview=self.calendar.prepare('create',self.event());data=self.commit_args(preview)
        self.calendar.commit(data);self.assertTrue(self.calendar.commit(data)['replayed_receipt'])
        with self.assertRaises(ApiError):self.calendar.commit({**data,'idempotency_key':'fixture-calendar-0002'})
        self.assertEqual(len(self.dav.writes),1)
    def test_calendar_mutation_redirect_never_followed(self):
        preview=self.calendar.prepare('create',self.event());self.dav.redirect=True
        with self.assertRaises(ApiError):self.calendar.commit(self.commit_args(preview))
        self.assertEqual(len(self.dav.writes),0)
    def test_absent_credentials_deny_all_writes(self):
        mail=MailOperations(MissingSecrets(),self.store,self.imap.factory,self.smtp.factory)
        calendar=CalendarOperations(MissingSecrets(),self.store,self.dav.factory,self.dav.connection)
        for action in ('flags','move','trash'):
            with self.assertRaises(ApiError):mail.mutate(action,self.mutation(read=True) if action=='flags' else self.mutation(target_mailbox_id=folder_id('Trash')) if action=='move' else self.mutation())
        with self.assertRaises(ApiError):mail.prepare_send({'to':['a@example.invalid'],'subject':'fixture','body':'fixture'})
        with self.assertRaises(ApiError):mail.send({'preview_id':'0'*24,'preview_hash':'x','idempotency_key':'fixture-none-0001','confirmed':True})
        for action in ('create','update','delete'):
            with self.assertRaises(ApiError):calendar.prepare(action,self.event() if action=='create' else self.event(object_id=calendar_id(OBJECT),etag='"v1"') if action=='update' else {'calendar_id':calendar_id(CALENDAR),'object_id':calendar_id(OBJECT),'etag':'"v1"'})
        with self.assertRaises(ApiError):calendar.commit({'preview_id':'0'*24,'preview_hash':'x','idempotency_key':'fixture-none-0002','confirmed':True})
        self.assertEqual(self.smtp.data_count,0);self.assertEqual(len(self.dav.writes),0);self.assertEqual(len(self.imap.commands),0)
    def test_recovery_preserves_send_receipts(self):
        draft=self.draft();args=self.send_args(draft);self.mail.send(args);self.store.recovery_reset()
        self.assertTrue(self.mail.send(args)['replayed_receipt']);self.assertEqual(self.smtp.data_count,1)


class ScopeTests(SecurityTests):
    # Reuse the HTTP/passkey/OAuth fixture, not its tests (runner filters below).
    def test_read_only_token_cannot_call_any_write(self):
        self.enroll();token=self.token(scope=' '.join(READ_SCOPES))
        calls={'mail_flags':{'mailbox_id':'0'*24,'uid':1,'uidvalidity':1,'idempotency_key':'fixture-key-0001','read':True,'confirmed':True},
               'mail_move':{'mailbox_id':'0'*24,'target_mailbox_id':'1'*24,'uid':1,'uidvalidity':1,'idempotency_key':'fixture-key-0001','confirmed':True},
               'mail_trash':{'mailbox_id':'0'*24,'uid':1,'uidvalidity':1,'idempotency_key':'fixture-key-0001','confirmed':True},
               'mail_prepare_send':{'to':['a@example.invalid'],'subject':'fixture','body':'fixture'},
               'mail_send':{'preview_id':'0'*24,'preview_hash':'x','idempotency_key':'fixture-key-0001','confirmed':True},
               'calendar_prepare_create':{'calendar_id':'0'*24,'summary':'fixture','start':'2026-10-10T12:00:00Z','end':'2026-10-10T13:00:00Z'},
               'calendar_prepare_update':{'calendar_id':'0'*24,'object_id':'1'*24,'etag':'"v1"','summary':'fixture','start':'2026-10-10T12:00:00Z','end':'2026-10-10T13:00:00Z'},
               'calendar_prepare_delete':{'calendar_id':'0'*24,'object_id':'1'*24,'etag':'"v1"'},
               'calendar_commit':{'preview_id':'0'*24,'preview_hash':'x','idempotency_key':'fixture-key-0001','confirmed':True}}
        for name,args in calls.items():
            result=self.rpc(token,'tools/call',{'name':name,'arguments':args}).json()['result']
            self.assertTrue(result['isError']);self.assertIn('insufficient_scope',result['content'][0]['text'])
    def test_mail_write_does_not_include_send_or_calendar_write(self):
        self.enroll();token=self.token(scope='bridge:read mail:write')
        for name,args in (('mail_send',{'preview_id':'0'*24,'preview_hash':'x','idempotency_key':'fixture-key-0001','confirmed':True}),('calendar_commit',{'preview_id':'0'*24,'preview_hash':'x','idempotency_key':'fixture-key-0001','confirmed':True})):
            result=self.rpc(token,'tools/call',{'name':name,'arguments':args}).json()['result']
            self.assertTrue(result['isError']);self.assertIn('insufficient_scope',result['content'][0]['text'])
    def test_scope_omission_defaults_read_only(self):
        self.enroll();response=self.exchange(self.code(scope=None))
        self.assertEqual(response.status_code,200);self.assertEqual(set(response.json()['scope'].split()),set(READ_SCOPES))
    def test_scope_and_side_effect_metadata_truthful(self):
        self.enroll();token=self.token();tools=self.rpc(token,'tools/list').json()['result']['tools']
        byname={tool['name']:tool for tool in tools}
        self.assertEqual(len(byname),18)
        for name in ('mail_send','mail_move','mail_trash','calendar_commit'):
            self.assertFalse(byname[name]['annotations']['readOnlyHint']);self.assertTrue(byname[name]['annotations']['destructiveHint'])
        for name in ('mail_prepare_send','calendar_prepare_create','calendar_prepare_update','calendar_prepare_delete'):
            self.assertFalse(byname[name]['annotations']['readOnlyHint']);self.assertFalse(byname[name]['annotations']['destructiveHint'])
        self.assertEqual(byname['mail_send']['_meta']['securitySchemes'][0]['scopes'],['bridge:read','mail:send'])

    def test_scoped_write_tools_invoke_real_adapters_over_mcp(self):
        self.enroll();token=self.token();imap,smtp,dav=IMAPFixture(),SMTPFixture(),DAVFixture()
        self.store.set_calendar_consent('f'*24,calendar_id(CALENDAR),False)
        backend=Operations(self.store,FixtureSecrets(),MailOperations(FixtureSecrets(),self.store,imap.factory,smtp.factory),CalendarOperations(FixtureSecrets(),self.store,dav.factory,dav.connection))
        app,_,_=create_app(self.store,FixtureCIMD(),backend)
        with TestClient(app,base_url='https://mcp.example.test',headers={'Origin':'https://mcp.example.test'}) as client:
            old=self.client;self.client=client
            try:
                def call(name,args):
                    result=self.rpc(token,'tools/call',{'name':name,'arguments':args}).json()['result']
                    self.assertFalse(result.get('isError',False),name)
                    return json.loads(result['content'][0]['text'])
                call('mail_flags',{'mailbox_id':folder_id('INBOX'),'uid':7,'uidvalidity':111,'idempotency_key':'fixture-mcp-flags-0001','confirmed':True,'read':True})
                draft=call('mail_prepare_send',{'to':['recipient@example.invalid'],'subject':'fixture','body':'fixture'})
                call('mail_send',{'preview_id':draft['preview_id'],'preview_hash':draft['preview_hash'],'idempotency_key':'fixture-mcp-send-0001','confirmed':True})
                preview=call('calendar_prepare_create',{'calendar_id':calendar_id(CALENDAR),'summary':'fixture','start':'2026-10-10T12:00:00Z','end':'2026-10-10T13:00:00Z'})
                call('calendar_commit',{'preview_id':preview['preview_id'],'preview_hash':preview['preview_hash'],'idempotency_key':'fixture-mcp-calendar-0001','confirmed':True})
            finally:self.client=old
        self.assertEqual(smtp.data_count,1);self.assertEqual(len(dav.writes),1);self.assertIn('\\Seen',imap.messages['INBOX'][7])


def load_tests(loader,tests,pattern):
    # Imported/inherited SecurityTests already run once in test_security.py.
    suite=unittest.TestSuite(loader.loadTestsFromTestCase(AdapterTests))
    for name in ScopeTests.__dict__:
        if name.startswith('test_'):suite.addTest(ScopeTests(name))
    return suite
