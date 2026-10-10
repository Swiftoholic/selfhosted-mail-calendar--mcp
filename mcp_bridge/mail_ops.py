"""Restricted IMAP/SMTP operations. No arbitrary commands, EXPUNGE or CLOSE."""
import contextlib
import base64
import binascii
import datetime
import email.policy
import hashlib
import imaplib
import json
import re
import secrets
import smtplib
import threading
from email.headerregistry import Address
from email.message import EmailMessage

from bridge.app import ApiError, Mail, bounded_int, fields, text, tls_context
from bridge.network import TLSIMAP, smtp_connection
from .config import DOMAIN
from .accounts import current_revision, current_account_id


def opaque(value):
    if not isinstance(value,str) or not re.fullmatch(r'[a-f0-9]{24}',value):
        raise ApiError(400,'invalid_stable_id')
    return value


def folder_id(name):
    return hashlib.sha256(name.encode('ascii')).hexdigest()[:24]


def folder_display_name(name):
    """Decode IMAP modified UTF-7 for labels only; retain unsafe/invalid text."""
    parts=name.split('&');label=[parts[0]]
    try:
        for tail in parts[1:]:
            encoded,separator,literal=tail.partition('-')
            if not separator:raise ValueError()
            if not encoded:value='&'
            else:
                if not re.fullmatch(r'[A-Za-z0-9+,]+',encoded):raise ValueError()
                raw=base64.b64decode(encoded.replace(',','/')+'='*(-len(encoded)%4),validate=True)
                if base64.b64encode(raw).decode('ascii').rstrip('=').replace('/',',')!=encoded:raise ValueError()
                value=raw.decode('utf-16-be')
                # Keep encoded control characters and noncanonical shifted
                # printable ASCII out of the displayed Unicode label.
                if not value or any(ord(c)<160 for c in value):raise ValueError()
            label.extend((value,literal))
        return ''.join(label)
    except (ValueError,UnicodeError,binascii.Error):
        return name


def address(value):
    if not isinstance(value,str) or not 3<=len(value)<=254 or any(ord(c)<33 or ord(c)>126 for c in value):
        raise ApiError(400,'invalid_recipient_address')
    try:
        parsed=Address(addr_spec=value)
        if not parsed.username or not parsed.domain or parsed.addr_spec!=value or any(c in value for c in '<>"\\,;'):
            raise ValueError()
    except Exception:
        raise ApiError(400,'invalid_recipient_address') from None
    return value


class MailOperations(Mail):
    def __init__(self,secrets,store,factory=TLSIMAP,smtp=smtp_connection):
        super().__init__(secrets,factory)
        self.store,self.smtp,self.local=store,smtp,threading.local()

    @contextlib.contextmanager
    def connection(self):
        username,password=self.secrets.pair('mail')
        client=self.factory(self.provider.imap_host,self.provider.imap_port,ssl_context=tls_context(),timeout=8)
        try:
            if client.login(username,password)[0]!='OK':raise ApiError(502,'provider_login_failed')
            yield client
        finally:
            try:client.logout()
            except Exception:pass

    @staticmethod
    def folders(client):
        status,rows=client.list()
        if status!='OK' or not rows or len(rows)>100 or sum(len(row) for row in rows if isinstance(row,bytes))>32768:
            raise ApiError(502,'folder_list_unavailable')
        result=[]
        for row in rows:
            if not isinstance(row,bytes):raise ApiError(502,'unsupported_folder_encoding')
            match=re.fullmatch(rb'\(([^)]*)\) (?:"(?:[^"\\]|\\.)*"|NIL) (.+)',row)
            if not match:raise ApiError(502,'unsupported_folder_encoding')
            flags=match[1].split()
            if b'\\Noselect' in flags:continue
            raw=match[2]
            if raw.startswith(b'"') and raw.endswith(b'"'):
                raw=re.sub(rb'\\(.)',rb'\1',raw[1:-1])
            name=raw.decode('ascii')
            if not 1<=len(name)<=200 or any(ord(c)<32 or ord(c)>126 for c in name) or name.startswith('{'):
                raise ApiError(502,'unsupported_folder_encoding')
            result.append({'id':folder_id(name),'name':name,'is_trash':b'\\Trash' in flags,'data_trust':'untrusted'})
        if len({v['id'] for v in result})!=len(result):raise ApiError(502,'ambiguous_folder_list')
        return result

    @staticmethod
    def find(folders,identifier):
        opaque(identifier)
        row=next((v for v in folders if v['id']==identifier),None)
        if not row:raise ApiError(404,'folder_not_found')
        return row

    @contextlib.contextmanager
    def opened(self):
        with self.connection() as client:
            identifier=getattr(self.local,'mailbox_id',None)
            name=self.find(self.folders(client),identifier)['name'] if identifier else 'INBOX'
            if client.select(client._quote(name),readonly=True)[0]!='OK':raise ApiError(502,'folder_unavailable')
            yield client

    def read_operation(self,action,data):
        fields(data,{'query','limit','mailbox_id'} if action=='search' else {'uid','uidvalidity','max_chars','mailbox_id'})
        identifier=data.get('mailbox_id')
        if identifier is not None:opaque(identifier)
        self.local.mailbox_id=identifier
        try:
            result=getattr(super(),action)({k:v for k,v in data.items() if k!='mailbox_id'})
            for item in result.get('items',[result]):
                item['mailbox_id']=identifier or folder_id('INBOX')
                if identifier:item['mailbox']='folder identified by mailbox_id'
            return result
        finally:self.local.mailbox_id=None

    def list_folders(self,data):
        fields(data,set())
        with self.connection() as client:
            # Internal discovery, IDs, SELECT and MOVE retain exact wire names.
            items=[{**folder,'name':folder_display_name(folder['name'])} for folder in self.folders(client)]
            return {'items':items,'data_trust':'untrusted'}

    @staticmethod
    def target_message(client,data):
        uid=bounded_int(data.get('uid'),1,4294967295)
        validity=bounded_int(data.get('uidvalidity'),1,4294967295)
        if Mail.response_number(client,'UIDVALIDITY')!=validity:raise ApiError(409,'stale_message_id')
        status,rows=client.uid('FETCH',str(uid),'(UID FLAGS)')
        raw=b' '.join(row for row in rows or [] if isinstance(row,bytes))
        if status!='OK' or len(raw)>4096 or len(re.findall(rb'\bUID \d+\b',raw))!=1 or re.search(rb'\bUID '+str(uid).encode()+rb'\b',raw) is None:
            raise ApiError(404,'message_not_found')
        return uid

    def mutate(self,action,data):
        allowed={'mailbox_id','uid','uidvalidity','idempotency_key','confirmed'}
        allowed|={'target_mailbox_id'} if action=='move' else {'read','flagged'} if action=='flags' else set()
        fields(data,allowed)
        if data.get('confirmed') is not True:raise ApiError(400,'specific_user_action_confirmation_required')
        self.secrets.pair('mail') # Deny absent credentials before creating a receipt.
        opaque(data.get('mailbox_id'))
        if action=='move':opaque(data.get('target_mailbox_id'))
        if action=='flags' and (not any(k in data for k in ('read','flagged')) or any(type(data[k]) is not bool for k in ('read','flagged') if k in data)):
            raise ApiError(400,'invalid_flags')
        bounded_int(data.get('uid'),1,4294967295);bounded_int(data.get('uidvalidity'),1,4294967295)
        identity,cached=self.store.reserve_operation('mail_'+action,data.get('idempotency_key'),{**data,'account_revision':current_revision(self.secrets,'mail')})
        if cached is not None:return {**cached,'replayed_receipt':True}
        try:
            with self.connection() as client:
                folders=self.folders(client);source=self.find(folders,data['mailbox_id'])
                if client.select(client._quote(source['name']),readonly=False)[0]!='OK':raise ApiError(502,'folder_unavailable')
                uid=self.target_message(client,data)
                if action=='flags':
                    for key,flag in (('read','\\Seen'),('flagged','\\Flagged')):
                        if key in data and client.uid('STORE',str(uid),'+FLAGS.SILENT' if data[key] else '-FLAGS.SILENT','('+flag+')')[0]!='OK':
                            raise ApiError(502,'flag_update_failed')
                    result={'changed':True,'mailbox_id':source['id'],'uid':uid,'uidvalidity':data['uidvalidity'],'flags_requested':{k:data[k] for k in ('read','flagged') if k in data}}
                else:
                    if action=='trash':
                        trash=[v for v in folders if v['is_trash']]
                        if len(trash)!=1:raise ApiError(409,'unique_trash_folder_unavailable')
                        target=trash[0]
                    else:target=self.find(folders,data['target_mailbox_id'])
                    if source['id']==target['id']:raise ApiError(400,'same_folder')
                    if b'MOVE' not in client.capabilities:raise ApiError(409,'server_uid_move_required')
                    if client.uid('MOVE',str(uid),client._quote(target['name']))[0]!='OK':raise ApiError(502,'move_outcome_uncertain')
                    _,mapping=client.response('COPYUID');raw=mapping[0] if mapping else b''
                    match=re.fullmatch(rb'(\d+) (\d+) (\d+)',raw or b'')
                    mapped=bool(match and int(match[2])==uid and all(1<=int(match[i])<=4294967295 for i in (1,2,3)))
                    result={'moved':True,'source_mailbox_id':source['id'],'source_uid':uid,'target_mailbox_id':target['id'],
                            'recoverable_trash':target['is_trash'],'target_uid':int(match[3]) if mapped else None,
                            'target_uidvalidity':int(match[1]) if mapped else None,'rescan_required':not mapped,
                            'permanent_purge':False}
            self.store.finish_operation(identity,result);return result
        except Exception:
            self.store.finish_operation(identity);raise

    def prepare_send(self,data):
        fields(data,{'to','cc','bcc','subject','body'})
        username,_=self.secrets.pair('mail')
        sender=address(self.secrets.sender() if callable(getattr(self.secrets,'sender',None)) else username)
        recipients={}
        for field in ('to','cc','bcc'):
            values=data.get(field,[])
            if not isinstance(values,list):raise ApiError(400,'invalid_recipients')
            recipients[field]=[address(value) for value in values]
        targets=sum(recipients.values(),[])
        if not 1<=len(targets)<=20 or len(set(targets))!=len(targets) or not recipients['to']:
            raise ApiError(400,'invalid_recipients')
        subject,body=data.get('subject'),data.get('body')
        if not isinstance(subject,str) or not 1<=len(subject)<=200 or any(ord(c)<32 for c in subject):raise ApiError(400,'invalid_subject')
        if not isinstance(body,str) or not 1<=len(body.encode())<=10000 or '\x00' in body:raise ApiError(400,'invalid_body')
        preview={'from':sender,**recipients,'subject':subject,'body':body,'message_id':'<'+secrets.token_hex(16)+'@'+DOMAIN+'>',
                 'prepared_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
        account_id = current_account_id(self.secrets, 'mail')
        if account_id is not None: preview['account_id'] = account_id
        if len(json.dumps(preview).encode())>14000:raise ApiError(400,'preview_too_large')
        preview_id=secrets.token_hex(12)
        preview_hash=hashlib.sha256(json.dumps(preview,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.store.put('mail_preview',preview_id,{'preview':preview,'hash':preview_hash,'account_revision':current_revision(self.secrets,'mail'),'account_id':account_id},600)
        return {'preview_id':preview_id,'preview_hash':preview_hash,'preview':preview,'expires_in':600,'sent':False,'server_draft_created':False,
                'requires_separate_specific_user_send_instruction':True,'data_trust':'untrusted'}

    def send(self,data):
        fields(data,{'preview_id','preview_hash','idempotency_key','confirmed'})
        if data.get('confirmed') is not True:raise ApiError(400,'specific_user_send_confirmation_required')
        username,password=self.secrets.pair('mail')
        sender=address(self.secrets.sender() if callable(getattr(self.secrets,'sender',None)) else username)
        preview_id=opaque(data.get('preview_id'))
        revision=current_revision(self.secrets,'mail')
        account_id = current_account_id(self.secrets, 'mail')
        identity,cached=self.store.reserve_operation('mail_send',data.get('idempotency_key'),{**data,'account_revision':revision,'account_id':account_id})
        if cached is not None:return {**cached,'replayed_receipt':True}
        try:
            record=self.store.get('mail_preview',preview_id)
            if not record or record.get('account_revision')!=revision or record.get('account_id')!=account_id or record['hash']!=data.get('preview_hash') or record['preview']['from']!=sender:
                raise ApiError(409,'expired_or_changed_preview')
            # Separate single-use claim also blocks replay with a NEW key.
            with self.store.transaction():
                current=self.store.get('mail_preview',preview_id)
                if not current:raise ApiError(409,'preview_already_consumed')
                self.store.delete('mail_preview',preview_id)
            preview=record['preview'];message=EmailMessage(policy=email.policy.SMTP)
            for header,key in (('From','from'),('Subject','subject'),('Message-ID','message_id')):message[header]=preview[key]
            message['To']=', '.join(preview['to'])
            if preview['cc']:message['Cc']=', '.join(preview['cc'])
            message['Date']=email.utils.format_datetime(datetime.datetime.fromisoformat(preview['prepared_at']))
            message.set_content(preview['body'],charset='utf-8',cte='quoted-printable')
            raw=message.as_bytes()
            if len(raw)>32768:raise ApiError(400,'message_too_large')
            client=self.smtp(self.provider.smtp_host,self.provider.smtp_port,context=tls_context(),timeout=8)
            try:
                if client.ehlo()[0]!=250 or client.login(username,password)[0] not in (235,503):
                    raise ApiError(502,'provider_login_failed')
                if client.mail(sender)[0]!=250:raise ApiError(502,'smtp_sender_rejected')
                targets=preview['to']+preview['cc']+preview['bcc']
                for target in targets:
                    if client.rcpt(target)[0] not in (250,251):
                        client.rset();raise ApiError(502,'smtp_recipient_rejected_no_data_sent')
                if client.data(raw)[0]!=250:raise ApiError(502,'send_outcome_uncertain_do_not_retry')
            finally:
                try:client.quit()
                except Exception:
                    try:client.close()
                    except Exception:pass
            result={'smtp_accepted':True,'delivery_confirmed':False,'recipient_count':len(targets),'preview_id':preview_id,'automatic_retry':False}
            self.store.finish_operation(identity,result);return result
        except Exception:
            self.store.finish_operation(identity);raise
