"""Synthetic-only read-only CardDAV; no contacts scopes or real credentials."""
import unittest
import xml.etree.ElementTree as ET
from bridge.app import ApiError,DAV,calendar_id
from bridge.carddav import CARD,CardDAV,Contacts,vcard_fields
from mcp_bridge.tests.test_writes import FixtureSecrets,xml_response,value

ROOT='https://p01-contacts.icloud.com'
BOOK=ROOT+'/books/example/'
VCARD='BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Example Person\r\nEMAIL:person@example.invalid\r\nTEL:+0000000\r\nPHOTO:https://untrusted.invalid/photo\r\nNOTE:Untrusted data\r\nEND:VCARD\r\n'


class Fixture:
    def __init__(self):self.methods=[];self.href=BOOK+'person.vcf';self.count=1
    def factory(self,credentials):return self
    def request(self,method,url,payload,depth='0'):
        self.methods.append(method);xml=ET.fromstring(payload)
        if method=='REPORT':
            root=ET.Element('{'+DAV+'}multistatus')
            for i in range(self.count):root.extend(xml_response(self.href if i==0 else BOOK+str(i)+'.vcf',[value(CARD,'address-data',VCARD),value(DAV,'getetag','"fixture"')]))
            return root,url
        if xml.find('.//{'+DAV+'}current-user-principal') is not None:return xml_response(ROOT+'/',[value(DAV,'current-user-principal',child=value(DAV,'href','/principal/'))]),ROOT+'/'
        if xml.find('.//{'+CARD+'}addressbook-home-set') is not None:return xml_response(url,[value(CARD,'addressbook-home-set',child=value(DAV,'href','/books/'))]),url
        return xml_response(BOOK,[value(DAV,'resourcetype',child=value(CARD,'addressbook')),value(DAV,'displayname','Example book')]),url


class CardDAVTests(unittest.TestCase):
    def setUp(self):self.fixture=Fixture();self.adapter=Contacts(FixtureSecrets(),self.fixture.factory)
    def test_discovery_returns_opaque_ids_no_urls(self):
        result=self.adapter.books({});self.assertEqual(result['items'][0]['id'],calendar_id(BOOK));self.assertNotIn('url',result['items'][0]);self.assertEqual(result['data_trust'],'untrusted')
    def test_bounded_contact_fields_and_untrusted_marker(self):
        result=self.adapter.contacts({'addressbook_id':calendar_id(BOOK)})
        item=result['items'][0];self.assertEqual(item['name'],'Example Person');self.assertEqual(item['emails'],['person@example.invalid']);self.assertEqual(item['phones'],['+0000000'])
        self.assertEqual(item['data_trust'],'untrusted');self.assertNotIn('photo',item);self.assertNotIn('note',item);self.assertEqual(set(self.fixture.methods),{'PROPFIND','REPORT'})
    def test_result_limit_and_truncation(self):
        self.fixture.count=4;result=self.adapter.contacts({'addressbook_id':calendar_id(BOOK),'limit':2});self.assertEqual(len(result['items']),2);self.assertTrue(result['truncated'])
    def test_arbitrary_url_unknown_book_and_limit_rejected(self):
        for data in ({'addressbook_id':'https://attacker.invalid/'},{'addressbook_id':'0'*24},{'addressbook_id':calendar_id(BOOK),'limit':51},{'addressbook_id':calendar_id(BOOK),'host':'attacker.invalid'}):
            with self.assertRaises(ApiError):self.adapter.contacts(data)
    def test_contact_resource_outside_selected_book_rejected(self):
        for href in (ROOT+'/other/person.vcf','https://attacker.invalid/person.vcf',BOOK+'nested/person.vcf',BOOK+'%2e%2e.vcf'):
            self.fixture.href=href
            with self.assertRaises(ApiError):self.adapter.contacts({'addressbook_id':calendar_id(BOOK)})
    def test_vcard_folded_name_and_allowed_versions(self):
        self.assertEqual(vcard_fields(VCARD.replace('Example Person','Example\r\n Person'))['name'],'ExamplePerson')
        self.assertEqual(vcard_fields(VCARD.replace('VERSION:3.0','VERSION:4.0'))['name'],'Example Person')
    def test_binary_or_encoded_fields_are_ignored_and_duplicate_version_rejected(self):
        card=VCARD.replace('FN:Example Person','FN;ENCODING=b:U3ludGhldGlj').replace('TEL:+0000000','TEL;VALUE=BINARY:U3ludGhldGlj')
        result=vcard_fields(card);self.assertEqual(result['name'],'');self.assertEqual(result['phones'],[])
        with self.assertRaises(ApiError):vcard_fields(VCARD.replace('VERSION:3.0','VERSION:3.0\r\nVERSION:4.0'))
    def test_complex_bad_or_oversized_vcard_rejected(self):
        for card in ('not vcard',VCARD.replace('VERSION:3.0','VERSION:2.1'),VCARD.replace('END:VCARD','BEGIN:VCARD\r\nEND:VCARD'),VCARD+'x'*65536,VCARD+'\x00'):
            with self.assertRaises(ApiError):vcard_fields(card)
    def test_mutations_never_reach_transport(self):
        def rejected(*args,**kwargs):raise AssertionError('transport_must_not_be_called')
        adapter=CardDAV(('synthetic@example.invalid','SYNTHETIC_ONLY'),connection=rejected)
        for method in ('PUT','DELETE','POST','GET','MKCOL'):
            with self.assertRaises(ApiError):adapter.request(method,'https://contacts.icloud.com/',b'')
    def test_redirect_destination_checked_before_credentials(self):
        requests=[]
        class Connection:
            def __init__(self,host,*args,**kwargs):requests.append(host)
            def request(self,*args,**kwargs):pass
            def getresponse(self):
                class Response:
                    status=302
                    def getheader(self,name):return 'https://caldav.icloud.com/' if name=='Location' else None
                    def read(self,n):return b''
                return Response()
            def close(self):pass
        with self.assertRaises(ApiError):CardDAV(('synthetic@example.invalid','SYNTHETIC_ONLY'),Connection).request('PROPFIND','https://contacts.icloud.com/',b'')
        self.assertEqual(requests,['contacts.icloud.com'])
