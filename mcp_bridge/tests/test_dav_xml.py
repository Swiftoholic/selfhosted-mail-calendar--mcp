import unittest
from bridge.app import ApiError, CalDAV, MAX_UPSTREAM_BYTES


class DAVXMLTests(unittest.TestCase):
    def request(self, raw):
        class Response:
            status=207
            def getheader(self, name): return None
            def read(self, maximum): return raw[:maximum]
        class Connection:
            def __init__(self, *args, **kwargs): pass
            def request(self, *args, **kwargs): pass
            def getresponse(self): return Response()
            def close(self): pass
        client=CalDAV(('fixture@example.invalid','synthetic-only'),connection=Connection)
        return client.request('PROPFIND','https://caldav.icloud.com/',b'<propfind/>')

    def test_normal_utf8_multistatus(self):
        root,_=self.request(b'<d:multistatus xmlns:d="DAV:"/>')
        self.assertEqual(root.tag,'{DAV:}multistatus')

    def test_dtd_entity_null_and_invalid_encoding_rejected(self):
        fixtures=[b'<!DOCTYPE x [<!ENTITY expanded "data">]><x>&expanded;</x>',
                  b'<!doctype x><x/>',b'<!ENTITY x "data"><x/>',b'<x>\x00</x>',
                  '<!DOCTYPE x><x/>'.encode('utf-16'),b'<x>\xff</x>',b'<x>']
        for raw in fixtures:
            with self.subTest(size=len(raw)), self.assertRaises(ApiError): self.request(raw)

    def test_upstream_size_rejected_before_parsing(self):
        with self.assertRaises(ApiError): self.request(b'x'*(MAX_UPSTREAM_BYTES+1))
