from .config import ORIGIN
"""Bounded conditional CalDAV writes; selected calendars, simple events only."""
import base64
import datetime as dt
import http.client
import re
import secrets
import xml.etree.ElementTree as ET
from urllib.parse import urljoin

from bridge.app import ApiError, CAL, DAV, Calendar, calendar_id, fields, icloud_url, propfind, successful_props, tls_context
from bridge.network import TLSHTTPS
from .mail_ops import opaque
from .accounts import current_revision, current_account_id
from .calendar_consent import metadata as calendar_metadata

CS='http://calendarserver.org/ns/'
SAFE_PROPERTIES={'UID','SUMMARY','DESCRIPTION','LOCATION','DTSTART','DTEND','DTSTAMP','CREATED','LAST-MODIFIED','SEQUENCE','STATUS','TRANSP','CLASS'}


def strong_etag(value):
    if not isinstance(value,str) or not re.fullmatch(r'"[!#-~]{1,180}"',value):
        raise ApiError(400,'strong_etag_required')
    return value


def child_url(parent,href,validator=icloud_url):
    parsed_parent=validator(parent);value=urljoin(parent,href);parsed=validator(value)
    prefix=parsed_parent.path.rstrip('/')+'/'
    tail=parsed.path[len(prefix):] if parsed.path.startswith(prefix) else ''
    if (parsed.hostname,443 if parsed.port is None else parsed.port)!=(parsed_parent.hostname,443 if parsed_parent.port is None else parsed_parent.port) or parsed.query or not re.fullmatch(r'[A-Za-z0-9_.-]{1,200}\.ics',tail) or tail.startswith('.') or '..' in tail:
        raise ApiError(502,'untrusted_calendar_object_path')
    return value


def utc(value):
    try:
        result=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
        if result.utcoffset()!=dt.timedelta(0) or not 1970<=result.year<=2100:raise ValueError()
        return result
    except Exception:raise ApiError(400,'utc_date_required') from None


def event_fields(data):
    start,end=utc(data.get('start')),utc(data.get('end'))
    if not dt.timedelta(0)<end-start<=dt.timedelta(days=31):raise ApiError(400,'invalid_event_duration')
    result={'DTSTART':start.strftime('%Y%m%dT%H%M%SZ'),'DTEND':end.strftime('%Y%m%dT%H%M%SZ')}
    for key,prop,maximum in (('summary','SUMMARY',500),('description','DESCRIPTION',4000),('location','LOCATION',500)):
        value=data.get(key,'' if key!='summary' else None)
        if not isinstance(value,str) or len(value)>maximum or any(ord(c)<32 and c not in '\n\t' for c in value) or not value and key=='summary':
            raise ApiError(400,'invalid_event_text')
        result[prop]=value.replace('\\','\\\\').replace('\n','\\n').replace(';','\\;').replace(',','\\,')
    return result


def inspect_event(raw):
    try:content=raw.decode('utf-8')
    except UnicodeError:raise ApiError(409,'unsupported_calendar_encoding') from None
    if len(raw)>16384 or '\x00' in content:raise ApiError(409,'unsupported_complex_event')
    lines=re.sub(r'\r?\n[ \t]','',content).splitlines()
    if lines[:1]!=['BEGIN:VCALENDAR'] or lines[-1:]!=['END:VCALENDAR'] or lines.count('BEGIN:VEVENT')!=1 or lines.count('END:VEVENT')!=1:
        raise ApiError(409,'unsupported_complex_event')
    first,last=lines.index('BEGIN:VEVENT'),lines.index('END:VEVENT')
    if first>=last or any(line.startswith('BEGIN:') for line in lines[1:] if line!='BEGIN:VEVENT'):
        raise ApiError(409,'unsupported_complex_event')
    for line in lines[:first]+lines[last+1:]:
        if line in ('BEGIN:VCALENDAR','END:VCALENDAR'):continue
        if not re.match(r'^(VERSION|PRODID|CALSCALE):',line):raise ApiError(409,'scheduling_or_complex_event_rejected')
    values={}
    for line in lines[first+1:last]:
        if ':' not in line:raise ApiError(409,'unsupported_complex_event')
        name,value=line.split(':',1)
        if name not in SAFE_PROPERTIES or name in values:raise ApiError(409,'scheduling_or_complex_event_rejected')
        values[name]=value
    if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,200}',values.get('UID','')):raise ApiError(409,'unsupported_event_uid')
    if not all(re.fullmatch(r'\d{8}T\d{6}Z',values.get(prop,'')) for prop in ('DTSTART','DTEND')):
        raise ApiError(409,'simple_utc_event_required')
    return values


def render_event(values):
    result=['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//Mail & Calendar MCP Private Bridge//EN','BEGIN:VEVENT']
    # Byte-aware folding prevents line injection and keeps iCalendar syntax.
    for name,value in values.items():
        line=name+':'+value;pieces=[];current=''
        for char in line:
            if len((current+char).encode())>72:pieces.append(current);current=' '+char
            else:current+=char
        pieces.append(current);result.extend(pieces)
    result+=['END:VEVENT','END:VCALENDAR']
    raw=('\r\n'.join(result)+'\r\n').encode()
    if len(raw)>16384:raise ApiError(400,'event_too_large')
    return raw


class CalendarOperations(Calendar):
    def __init__(self,secrets,store,factory=None,connection=TLSHTTPS):
        super().__init__(secrets,**({'factory':factory} if factory else {}))
        self.store,self.connection=store,connection

    def write_consent(self, identifier, generation=None):
        revision = current_revision(self.secrets, 'caldav')
        consent = self.store.calendar_consent(revision, opaque(identifier))
        if not consent:
            raise ApiError(403, 'calendar_write_consent_required')
        if generation is not None and consent['generation'] != generation:
            raise ApiError(409, 'calendar_consent_changed_or_revoked')
        return consent

    def write_access(self, action, client, selected, consent):
        details = calendar_metadata(client, selected)
        if details['requires_audience_acknowledgement'] and not consent['audience_acknowledged']:
            raise ApiError(409, 'calendar_audience_acknowledgement_required')
        if details['permitted_actions'][action] is False:
            raise ApiError(403, 'calendar_write_permission_denied')
        return details

    def list(self, data):
        result = super().list(data)
        revision = current_revision(self.secrets, 'caldav')
        for item in result['items']:
            item['write_consent_enabled'] = self.store.calendar_consent(revision, item['id']) is not None
        result['calendar_write_configuration_url'] = ORIGIN + '/accounts#calendar-access'
        result['capability_is_not_event_approval'] = True
        return result

    def private_collection(self,client,selected):
        xml,base=client.request('PROPFIND',self.provider.origin,propfind((DAV,'current-user-principal')))
        principal=next((urljoin(base,p.findtext('{'+DAV+'}current-user-principal/{'+DAV+'}href')) for _,p in successful_props(xml) if p.findtext('{'+DAV+'}current-user-principal/{'+DAV+'}href')),None)
        if not principal:raise ApiError(409,'calendar_privacy_unverified')
        self.validate_url(principal)
        xml,base=client.request('PROPFIND',selected['url'],propfind((DAV,'owner'),(DAV,'acl'),(CS,'invite'),(CS,'shared-url'),(DAV,'resourcetype')))
        props=[p for _,p in successful_props(xml)]
        owner=next((p.findtext('{'+DAV+'}owner/{'+DAV+'}href') for p in props if p.findtext('{'+DAV+'}owner/{'+DAV+'}href')),None)
        acls=[a for p in props for a in p.findall('{'+DAV+'}acl')]
        if not owner or urljoin(base,owner).rstrip('/')!=principal.rstrip('/') or not acls:
            raise ApiError(409,'calendar_privacy_unverified')
        owners=0
        for acl in acls:
            for ace in acl.findall('{'+DAV+'}ace'):
                href=ace.findtext('{'+DAV+'}principal/{'+DAV+'}href')
                if not href or urljoin(base,href).rstrip('/')!=principal.rstrip('/'):
                    raise ApiError(409,'shared_calendar_writes_rejected')
                owners+=1
        if not owners:raise ApiError(409,'calendar_privacy_unverified')
        for p in props:
            if p.find('{'+CS+'}shared-url') is not None or list(p.findall('.//{'+CS+'}invite/{'+CS+'}user')) or p.find('.//{'+CS+'}shared') is not None or p.find('.//{'+CS+'}shared-owner') is not None:
                raise ApiError(409,'shared_calendar_writes_rejected')

    def selected(self,identifier):
        opaque(identifier);client,calendars=self.discover()
        selected=next((c for c in calendars if c['id']==identifier),None)
        if not selected:raise ApiError(404,'calendar_not_found')
        return client,selected

    def object_url(self,client,selected,identifier):
        opaque(identifier)
        xml,_=client.request('PROPFIND',selected['url'],propfind((DAV,'getetag')),depth='1')
        responses=xml.findall('{'+DAV+'}response')
        if len(responses)>200:raise ApiError(409,'calendar_object_scan_limit')
        for response in responses:
            href=response.findtext('{'+DAV+'}href','')
            if href.rstrip('/')==self.validate_url(selected['url']).path.rstrip('/'):continue
            try:url=child_url(selected['url'],href,self.validate_url)
            except ApiError:continue
            if calendar_id(url)==identifier:return url
        raise ApiError(404,'calendar_object_not_found')

    def http(self,method,url,body=None,etag=None):
        if method not in {'GET','PUT','DELETE'}:raise ApiError(405,'method_not_allowed')
        parsed=self.validate_url(url);username,password=self.secrets.pair('caldav')
        headers={'Authorization':'Basic '+base64.b64encode((username+':'+password).encode()).decode(),
                 'User-Agent':'SelfHostedMCP/2.0','Accept':'text/calendar','Schedule-Reply':'F'}
        if method=='PUT':headers['Content-Type']='text/calendar; charset=utf-8'
        if method in {'PUT','DELETE'}:
            if etag is None and method=='PUT':headers['If-None-Match']='*'
            else:headers['If-Match']=strong_etag(etag)
        connection=self.connection(parsed.hostname,443 if parsed.port is None else parsed.port,context=tls_context(),timeout=8)
        try:
            connection.request(method,parsed.path,body=body,headers=headers)
            response=connection.getresponse();status=response.status
            raw=response.read(16385);returned=response.getheader('ETag')
        finally:connection.close()
        if len(raw)>16384:raise ApiError(502,'calendar_response_too_large')
        if status in {401,403} and method in {'PUT','DELETE'}:
            raise ApiError(403,'calendar_provider_write_denied')
        if status in {409,412}:raise ApiError(409,'etag_conflict_refresh_before_retry')
        expected={200} if method=='GET' else {201,204} if method=='PUT' else {204}
        # Mutations never follow redirects; Basic credentials stay fixed-host.
        if status not in expected:raise ApiError(502,'calendar_request_rejected_or_uncertain')
        return raw,returned

    def prepare(self,action,data):
        allowed={'calendar_id','summary','description','location','start','end'}
        if action in {'update','delete'}:allowed|={'object_id','etag'}
        if action=='delete':allowed={'calendar_id','object_id','etag'}
        fields(data,allowed)
        self.secrets.pair('caldav')
        consent = self.write_consent(data.get('calendar_id'))
        client,selected=self.selected(data.get('calendar_id'))
        audience = self.write_access(action, client, selected, consent)
        values={} if action=='delete' else event_fields(data)
        if action=='create':
            url=child_url(selected['url'],secrets.token_hex(16)+'.ics',self.validate_url)
            original={'UID':secrets.token_hex(16)+'@'+__import__('mcp_bridge.config',fromlist=['DOMAIN']).DOMAIN}
            etag=None
        else:
            etag=strong_etag(data.get('etag'))
            url=self.object_url(client,selected,data.get('object_id'));raw,actual=self.http('GET',url)
            if strong_etag(actual)!=etag:raise ApiError(409,'etag_conflict_refresh_before_retry')
            original=inspect_event(raw)
        changes={**original,**values,'DTSTAMP':dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}
        if action=='update':
            sequence=original.get('SEQUENCE','0')
            if not sequence.isdigit() or len(sequence)>7:raise ApiError(409,'unsupported_sequence')
            changes['SEQUENCE']=str(int(sequence)+1)
        payload={'action':action,'calendar_id':selected['id'],'url':url,'etag':etag,
                 'consent_generation':consent['generation'],
                 'body':render_event(changes).decode() if action!='delete' else None,
                 'preview':{'action':action,'calendar_id':selected['id'],'object_id':calendar_id(url),'event_uid':original['UID'],
                            'etag':etag,'summary':data.get('summary',original.get('SUMMARY','')),'start':data.get('start',original.get('DTSTART')),
                            'end':data.get('end',original.get('DTEND')),'description':data.get('description',original.get('DESCRIPTION','')),
                            'location':data.get('location',original.get('LOCATION','')),
                            'calendar_name':selected['name'], **audience,
                            'owner_calendar_write_consent':True,'capability_is_not_event_approval':True,
                            'external_invitations':False,'calendar_delete_has_no_bridge_undo':action=='delete'}}
        preview_id=secrets.token_hex(12)
        account_id = current_account_id(self.secrets, 'caldav')
        if account_id is not None: payload['preview']['account_id'] = account_id
        import hashlib,json
        preview_hash=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.store.put('calendar_preview',preview_id,{'payload':payload,'hash':preview_hash,'account_revision':current_revision(self.secrets,'caldav'),'account_id':account_id},600)
        return {'preview_id':preview_id,'preview_hash':preview_hash,'preview':payload['preview'],'expires_in':600,'changed':False,
                'requires_specific_user_action_confirmation':True,'data_trust':'untrusted'}

    def commit(self,data):
        fields(data,{'preview_id','preview_hash','idempotency_key','confirmed'})
        if data.get('confirmed') is not True:raise ApiError(400,'specific_user_action_confirmation_required')
        self.secrets.pair('caldav');preview_id=opaque(data.get('preview_id'))
        revision=current_revision(self.secrets,'caldav')
        account_id = current_account_id(self.secrets, 'caldav')
        identity,cached=self.store.reserve_operation('calendar_commit',data.get('idempotency_key'),{**data,'account_revision':revision,'account_id':account_id})
        if cached is not None:return {**cached,'replayed_receipt':True}
        try:
            record=self.store.get('calendar_preview',preview_id)
            if not record or record.get('account_revision')!=revision or record.get('account_id')!=account_id or record['hash']!=data.get('preview_hash'):raise ApiError(409,'expired_or_changed_preview')
            payload=record['payload']
            generation = payload.get('consent_generation')
            if not generation: raise ApiError(409,'calendar_consent_changed_or_revoked')
            consent=self.write_consent(payload['calendar_id'],generation)
            client,selected=self.selected(payload['calendar_id'])
            audience=self.write_access(payload['action'],client,selected,consent)
            if audience['calendar_audience'] != payload['preview'].get('calendar_audience'):
                raise ApiError(409,'calendar_audience_changed_new_preview_required')
            url=child_url(selected['url'],payload['url'],self.validate_url)
            if payload['action']!='create':
                current,etag=self.http('GET',url)
                if strong_etag(etag)!=payload['etag']:raise ApiError(409,'etag_conflict_refresh_before_retry')
                inspect_event(current) # Invitations/sharing cannot be added after preview.
            with self.store.transaction():
                if not self.store.get('calendar_preview',preview_id):raise ApiError(409,'preview_already_consumed')
                self.write_consent(payload['calendar_id'],generation)
                self.store.delete('calendar_preview',preview_id)
            _,etag=self.http('DELETE' if payload['action']=='delete' else 'PUT',url,
                            payload['body'].encode() if payload['body'] else None,payload['etag'])
            result={'changed':True,'action':payload['action'],'calendar_id':selected['id'],'object_id':calendar_id(url),
                    'calendar_name':selected['name'], **audience,
                    'etag':etag,'external_invitations':False,'automatic_retry':False,'bridge_undo_available':False}
            self.store.finish_operation(identity,result);return result
        except Exception:
            self.store.finish_operation(identity);raise
