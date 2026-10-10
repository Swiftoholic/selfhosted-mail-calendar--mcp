"""Canonical deployment identity, adapter registry and protocol credential boundaries."""
import unittest
from mcp_bridge.config import deployment_identity
from bridge.providers import GMX,dav_provider,mail_provider
from bridge.app import ApiError,CalDAV,icloud_url
from bridge.carddav import contacts_url


class ConfigTests(unittest.TestCase):
    def test_exact_origin_and_nondefault_port(self):
        self.assertEqual(deployment_identity('https://mcp.example.test'),('mcp.example.test','https://mcp.example.test','mcp.example.test'))
        self.assertEqual(deployment_identity('https://mcp.example.test:8443','mcp.example.test'),('mcp.example.test','https://mcp.example.test:8443','mcp.example.test:8443'))
    def test_missing_insecure_noncanonical_or_wildcard_origin_rejected(self):
        for value in (None,'','http://mcp.example.test','https://MCP.example.test','https://mcp.example.test/','https://mcp.example.test:443','https://user@host.example.test','https://mcp.example.test?x','https://mcp.example.test#x','https://*.example.test','https://localhost','https://127.0.0.1','https://[::1]','https://server.local','https://bad_label.example.test','https://mcp.example.test\n','https://mcp.example.test:99999'):
            with self.subTest(kind='invalid_origin'):
                with self.assertRaises(RuntimeError):deployment_identity(value)
    def test_rp_id_cannot_expand_to_parent_or_other_host(self):
        for rp in ('example.test','other.example.test','*.example.test',''):
            with self.assertRaises(RuntimeError):deployment_identity('https://mcp.example.test',rp)
    def test_closed_provider_registry(self):
        self.assertEqual(mail_provider('gmx'),GMX)
        self.assertEqual(dav_provider('icloud','caldav').protocol,'caldav')
        self.assertEqual(dav_provider('icloud','carddav').protocol,'carddav')
        for name in ('imap','https://arbitrary.invalid','../gmx'):
            with self.assertRaises(ValueError):mail_provider(name)
    def test_caldav_and_carddav_credentials_do_not_cross_protocol_hosts(self):
        self.assertEqual(icloud_url('https://p01-caldav.icloud.com/book/').hostname,'p01-caldav.icloud.com')
        self.assertEqual(contacts_url('https://p01-contacts.icloud.com/book/').hostname,'p01-contacts.icloud.com')
        for validator,url in ((icloud_url,'https://contacts.icloud.com/'),(contacts_url,'https://caldav.icloud.com/'),(contacts_url,'https://127.0.0.1/'),(contacts_url,'https://p01-contacts.icloud.com.attacker.invalid/'),(contacts_url,'http://contacts.icloud.com/'),(contacts_url,'https://contacts.icloud.com/?secret=x')):
            with self.assertRaises(ApiError):validator(url)
