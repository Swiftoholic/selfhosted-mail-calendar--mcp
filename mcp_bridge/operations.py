"""Private MCP-only facade. Existing public REST interface remains read-only."""
from bridge.app import ApiError, App, Secrets
from .calendar_ops import CalendarOperations
from .mail_ops import MailOperations
from .accounts import AccountSecrets, bind_id, connection_status
from .contacts_ops import ContactsOperations


class Operations:
    def __init__(self,store,secrets=None,mail=None,calendar=None,contacts=None):
        self.secrets=secrets if secrets is not None else AccountSecrets()
        self.mail=mail if mail is not None else MailOperations(self.secrets,store)
        self.calendar=calendar if calendar is not None else CalendarOperations(self.secrets,store)
        self.contacts=contacts if contacts is not None else ContactsOperations(self.secrets,store)

    def call(self,method,path,data):
        if method!='POST':raise ApiError(405,'method_not_allowed')
        if path=='/mcp/connection-status':
            if data:raise ApiError(400,'invalid_request')
            return connection_status(self.secrets)
        if getattr(self.secrets,'managed_accounts',False):
            provider='mail' if path.startswith(('/v1/mail/','/mcp/mail/')) else 'caldav' if path.startswith(('/v1/calendars/','/mcp/calendar/')) else 'carddav' if path.startswith('/mcp/contacts/') else None
            if provider is None:raise ApiError(404,'operation_not_allowed')
            account_id = data.get('account_id')
            with self.secrets.operation(provider, account_id) as snapshot:
                mapped=dict(data)
                mapped.pop('account_id', None)
                scope = ('mail:send' if path.endswith(('/prepare-send', '/send')) else 'mail:write' if path.endswith(('/flags', '/move', '/trash')) else 'mail:read') if provider == 'mail' else ('calendars:write' if path.startswith('/mcp/calendar/') else 'calendars:read') if provider == 'caldav' else 'contacts:read'
                if snapshot.capabilities is not None and scope not in snapshot.capabilities:
                    raise ApiError(403, 'account_capability_required')
                for key,purpose in (('mailbox_id','mailbox'),('target_mailbox_id','mailbox'),('calendar_id','calendar'),('object_id','object'),('addressbook_id','addressbook'),('contact_id','contact')):
                    if mapped.get(key) is not None:mapped[key]=bind_id(mapped[key],snapshot.revision,purpose)
                result=self.dispatch(path,mapped)
                def convert(value):
                    if isinstance(value,list):return [convert(item) for item in value]
                    if not isinstance(value,dict):return value
                    result={}
                    purposes={'mailbox_id':'mailbox','source_mailbox_id':'mailbox','target_mailbox_id':'mailbox','calendar_id':'calendar','object_id':'object','addressbook_id':'addressbook'}
                    if path in {'/mcp/mail/folders','/v1/calendars/list'}:purposes['id']='mailbox' if provider=='mail' else 'calendar'
                    if path.startswith('/mcp/contacts/'):purposes['id']='addressbook' if path.endswith('/books') else 'contact'
                    for key,item in value.items():
                        result[key]=bind_id(item,snapshot.revision,purposes[key]) if key in purposes and item is not None else convert(item)
                    return result
                converted = convert(result)
                if snapshot.account_id is not None:
                    converted['account_id'] = snapshot.account_id
                return converted
        return self.dispatch(path,data)

    def dispatch(self,path,data):
        if path in {'/v1/mail/search','/v1/mail/read'}:return self.mail.read_operation(path.rsplit('/',1)[1],data)
        routes={'/v1/calendars/list':self.calendar.list,'/v1/calendars/events':self.calendar.events,
                '/mcp/contacts/books':self.contacts.list_books,'/mcp/contacts/search':self.contacts.search,'/mcp/contacts/read':self.contacts.read,
                '/mcp/mail/folders':self.mail.list_folders,'/mcp/mail/prepare-send':self.mail.prepare_send,'/mcp/mail/send':self.mail.send,
                '/mcp/calendar/commit':self.calendar.commit}
        if path in routes:return routes[path](data)
        for action in ('move','trash','flags'):
            if path=='/mcp/mail/'+action:return self.mail.mutate(action,data)
        for action in ('create','update','delete'):
            if path=='/mcp/calendar/prepare-'+action:return self.calendar.prepare(action,data)
        raise ApiError(404,'operation_not_allowed')
