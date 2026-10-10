"""Bounded CardDAV discovery, search and multiget; no writes or external fetches."""
import http.client
import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
from .app import ApiError, CalDAV, DAV, bounded_int, calendar_id, fields, propfind, successful_props, text
from .providers import ICLOUD_CARDDAV, profiles_for
from .network import TLSHTTPS

CARD='urn:ietf:params:xml:ns:carddav'


def contacts_url(value):
    try:return ICLOUD_CARDDAV.validate_url(value)
    except ValueError:raise ApiError(502,'contacts_upstream_rejected') from None


class CardDAV(CalDAV):
    def __init__(self,credentials,connection=TLSHTTPS,*,provider=ICLOUD_CARDDAV):
        super().__init__(credentials,connection,provider=provider)


def vcard_fields(content):
    if not isinstance(content,str) or len(content.encode('utf-8'))>65536 or '\x00' in content:
        raise ApiError(502,'contact_data_rejected')
    lines=re.sub(r'\r?\n[ \t]','',content).splitlines()
    if not lines or lines[0]!='BEGIN:VCARD' or lines[-1]!='END:VCARD' or any(line.startswith('BEGIN:') or line.startswith('END:') for line in lines[1:-1]):
        raise ApiError(502,'contact_data_rejected')
    result={'name':'','emails':[],'phones':[],'data_trust':'untrusted'}
    version=None
    for line in lines[1:-1]:
        if ':' not in line:continue
        header,value=line.split(':',1)
        field=header.split(';',1)[0].rsplit('.',1)[-1].upper()
        if re.search(r';(?:ENCODING=|VALUE=BINARY(?:;|$))',header,re.IGNORECASE):continue
        if field=='VERSION':
            if version is not None:raise ApiError(502,'contact_data_rejected')
            version=value
        value=re.sub(r'\\([nN,;\\])',lambda m:'\n' if m[1].lower()=='n' else m[1],value)
        if field=='FN' and not result['name']:result['name']=text(value,500)
        elif field=='EMAIL' and len(result['emails'])<10:result['emails'].append(text(value,254))
        elif field=='TEL' and len(result['phones'])<10:result['phones'].append(text(value,100))
    if version not in {'3.0','4.0'}:raise ApiError(502,'contact_version_unsupported')
    return result


class Contacts:
    """Protocol interface; the MCP facade enforces independent book consent."""
    def __init__(self,secrets,factory=None):
        self.secrets,self.factory=secrets,factory

    @property
    def provider(self):
        return profiles_for(self.secrets).carddav

    def validate_url(self,value):
        try:return self.provider.validate_url(value)
        except ValueError:raise ApiError(502,'contacts_upstream_rejected') from None

    def discover(self):
        client=self.factory(self.secrets.pair('carddav')) if self.factory else CardDAV(self.secrets.pair('carddav'),provider=self.provider)
        client.origin,client.url_validator=self.provider.origin,self.validate_url
        xml,base=client.request('PROPFIND',self.provider.origin,propfind((DAV,'current-user-principal')))
        href=next((p.findtext('{'+DAV+'}current-user-principal/{'+DAV+'}href') for _,p in successful_props(xml)),None)
        if not href:raise ApiError(502,'contacts_discovery_rejected')
        principal=urljoin(base,href);self.validate_url(principal)
        xml,base=client.request('PROPFIND',principal,propfind((CARD,'addressbook-home-set')))
        href=next((p.findtext('{'+CARD+'}addressbook-home-set/{'+DAV+'}href') for _,p in successful_props(xml)),None)
        if not href:raise ApiError(502,'contacts_discovery_rejected')
        home=urljoin(base,href);self.validate_url(home)
        xml,base=client.request('PROPFIND',home,propfind((DAV,'displayname'),(DAV,'resourcetype')),depth='1')
        books=[]
        for response,p in successful_props(xml):
            if p.find('{'+DAV+'}resourcetype/{'+CARD+'}addressbook') is None:continue
            href=response.findtext('{'+DAV+'}href')
            if not href:continue
            url=urljoin(base,href);self.validate_url(url)
            books.append({'id':calendar_id(url),'name':text(p.findtext('{'+DAV+'}displayname'),300),'url':url})
            if len(books)>=25:break
        if len({book['id'] for book in books})!=len(books):raise ApiError(502,'ambiguous_addressbook_list')
        return client,books

    def books(self,data):
        fields(data,{'limit'});limit=bounded_int(data.get('limit',25),1,25)
        _,books=self.discover()
        return {'items':[{'id':b['id'],'name':b['name'],'data_trust':'untrusted'} for b in books[:limit]],'limit':limit,'data_trust':'untrusted'}

    def contacts(self,data):
        fields(data,{'addressbook_id','query','limit'});limit=bounded_int(data.get('limit',25),1,50)
        identifier=data.get('addressbook_id')
        if not isinstance(identifier,str) or not re.fullmatch(r'[a-f0-9]{24}',identifier):raise ApiError(400,'invalid_addressbook_id')
        client,books=self.discover();book=next((b for b in books if b['id']==identifier),None)
        if not book:raise ApiError(404,'addressbook_not_found')
        result=self.search_book(client,book,data.get('query',''),limit)
        for item in result['items']:item.pop('_resource_url',None)
        return result

    @staticmethod
    def minimal_props(root):
        prop=ET.SubElement(root,'{'+DAV+'}prop')
        ET.SubElement(prop,'{'+DAV+'}getetag');address=ET.SubElement(prop,'{'+CARD+'}address-data')
        for name in ('VERSION','FN','EMAIL','TEL'):ET.SubElement(address,'{'+CARD+'}prop',{'name':name})

    def resource_url(self,book,href):
        if not href:raise ApiError(502,'contact_resource_outside_addressbook')
        url=urljoin(book['url'],href);parsed=self.validate_url(url);parent=self.validate_url(book['url'])
        prefix=parent.path.rstrip('/')+'/'
        tail=parsed.path[len(prefix):] if parsed.path.startswith(prefix) else ''
        if ((parsed.hostname,443 if parsed.port is None else parsed.port)!=(parent.hostname,443 if parent.port is None else parent.port) or not tail or
                '/' in tail or tail.startswith('.') or '..' in tail or re.search(r'%2f|%5c|%2e|\\',tail,re.IGNORECASE)):
            raise ApiError(502,'contact_resource_outside_addressbook')
        return url

    def items(self,xml,book,limit,expected_url=None):
        items=[];seen=set()
        for response,p in successful_props(xml):
            raw=p.findtext('{'+CARD+'}address-data')
            if raw is None:continue
            url=self.resource_url(book,response.findtext('{'+DAV+'}href',''))
            if url in seen or expected_url is not None and url!=expected_url:
                raise ApiError(502,'contact_response_rejected')
            seen.add(url)
            item=vcard_fields(raw);item.update(id=calendar_id(url),etag=text(p.findtext('{'+DAV+'}getetag'),200),_resource_url=url);items.append(item)
            if len(items)>limit:break
        return {'items':items[:limit],'limit':limit,'truncated':len(items)>limit,'data_trust':'untrusted'}

    def search_book(self,client,book,term,limit):
        if not isinstance(term,str) or len(term)>100 or any(ord(c)<32 or ord(c)==127 for c in term):
            raise ApiError(400,'invalid_contact_query')
        query=ET.Element('{'+CARD+'}addressbook-query');prop=ET.SubElement(query,'{'+DAV+'}prop')
        ET.SubElement(prop,'{'+DAV+'}getetag');address=ET.SubElement(prop,'{'+CARD+'}address-data')
        for name in ('VERSION','FN','EMAIL','TEL'):ET.SubElement(address,'{'+CARD+'}prop',{'name':name})
        filters=ET.SubElement(query,'{'+CARD+'}filter',{'test':'anyof'})
        if term:
            for name in ('FN','EMAIL','TEL'):
                match=ET.SubElement(ET.SubElement(filters,'{'+CARD+'}prop-filter',{'name':name}),'{'+CARD+'}text-match',{'collation':'i;unicode-casemap','match-type':'contains'})
                match.text=term
        limits=ET.SubElement(query,'{'+CARD+'}limit');ET.SubElement(limits,'{'+CARD+'}nresults').text=str(limit+1)
        xml,_=client.request('REPORT',book['url'],ET.tostring(query,encoding='utf-8'),depth='1')
        return self.items(xml,book,limit)

    def read_resource(self,client,book,url):
        self.resource_url(book,url)
        query=ET.Element('{'+CARD+'}addressbook-multiget');self.minimal_props(query)
        ET.SubElement(query,'{'+DAV+'}href').text=self.validate_url(url).path
        xml,_=client.request('REPORT',book['url'],ET.tostring(query,encoding='utf-8'),depth='1')
        result=self.items(xml,book,1,expected_url=url)
        if result['truncated']:raise ApiError(502,'contact_response_rejected')
        if not result['items']:raise ApiError(404,'contact_not_found')
        return result['items'][0]
