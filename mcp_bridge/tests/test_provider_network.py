"""Synthetic DNS/socket/configuration fixtures, never public network requests."""
import copy
import ipaddress
import json
import os
import socket
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from bridge.network import NetworkError, hostname, public_addresses, public_ip, public_socket, wrap_tls
from bridge.providers import DEFAULT_PROFILES, load_profiles, parse_profiles
from bridge.app import ApiError, CalDAV
from mcp_bridge.accounts import AccountSecrets

CUSTOM = {'version': 1, 'mail': {'preset': 'custom', 'imap': {'host': 'imap.example.test', 'port': 993, 'tls': 'implicit'},
           'smtp': {'host': 'smtp.example.test', 'port': 587, 'tls': 'starttls_required'}},
          'caldav': {'preset': 'custom', 'origin': 'https://calendar.example.test:8443/dav/', 'allowed_hosts': ['calendar.example.test', 'shard.example.test']},
          'carddav': {'preset': 'custom', 'origin': 'https://contacts.example.test/dav/', 'allowed_hosts': ['contacts.example.test']}}


def answer(address, port=443):
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (address, port, 0, 0) if family == socket.AF_INET6 else (address, port))


class NetworkTests(unittest.TestCase):
    def test_ip_literals_noncanonical_and_private_names_rejected(self):
        for value in ('localhost', 'server.local', 'server.internal', '127.0.0.1', '[::1]', '2130706433', '0177.0.0.1',
                      'host.example.test.', 'HOST.example.test', '*.example.test', 'host.example.test\n', 'host..example.test', 'host.example.test:443'):
            with self.subTest(kind='invalid_host'), self.assertRaises(ValueError): hostname(value)

    def test_special_private_transition_and_multicast_ips_rejected(self):
        for value in ('127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0',
                      '224.0.0.1', '240.0.0.1', '168.63.129.16', '::1', '::', 'fc00::1', 'fe80::1', 'ff02::1',
                      '::ffff:8.8.8.8', '2002:0808:0808::1', '2001:0000:4136:e378:8000:63bf:3fff:fdd2', '64:ff9b::808:808', '64:ff9b:1::1'):
            with self.subTest(kind='forbidden_ip'), self.assertRaises(NetworkError): public_ip(value)
        self.assertEqual(public_ip('8.8.8.8'), ipaddress.ip_address('8.8.8.8'))

    def test_mixed_dns_answer_rejected_before_any_socket(self):
        with patch('bridge.network.socket.getaddrinfo', return_value=[answer('8.8.8.8'), answer('127.0.0.1')]), patch('bridge.network.socket.socket') as dial:
            with self.assertRaises(NetworkError): public_socket('dav.example.test', 443)
            dial.assert_not_called()

    def test_dns_rebinding_cannot_cause_second_hostname_lookup(self):
        client = Mock(); client.getpeername.return_value = ('8.8.8.8', 443)
        with patch('bridge.network.socket.getaddrinfo', side_effect=[[answer('8.8.8.8')], [answer('127.0.0.1')]]) as resolver, patch('bridge.network.socket.socket', return_value=client):
            self.assertIs(public_socket('dav.example.test', 443), client)
            self.assertEqual(resolver.call_count, 1)
            client.connect.assert_called_once_with(('8.8.8.8', 443))

    def test_mismatched_peer_is_closed_before_tls_or_authentication(self):
        client = Mock(); client.getpeername.return_value = ('1.1.1.1', 443)
        with patch('bridge.network.socket.getaddrinfo', return_value=[answer('8.8.8.8')]), patch('bridge.network.socket.socket', return_value=client):
            with self.assertRaises(NetworkError): public_socket('dav.example.test', 443)
            client.close.assert_called_once()

    def test_dns_answer_bounds_family_scope_port_and_failures(self):
        cases = [[], [answer('8.8.8.8')] * 17, [answer('8.8.8.8', 80)],
                 [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('2606:4700:4700::1111', 443, 0, 1))],
                 [(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP, '', ('8.8.8.8', 443))]]
        for replies in cases:
            with patch('bridge.network.socket.getaddrinfo', return_value=replies), self.assertRaises(NetworkError): public_addresses('dav.example.test', 443)
        with patch('bridge.network.socket.getaddrinfo', side_effect=socket.gaierror('synthetic')), self.assertRaises(NetworkError): public_addresses('dav.example.test', 443)

    def test_resolver_capacity_fails_closed_without_queueing(self):
        with patch('bridge.network._resolver_slots.acquire', return_value=False), patch('bridge.network.socket.getaddrinfo') as resolver:
            with self.assertRaises(NetworkError): public_addresses('dav.example.test', 443)
            resolver.assert_not_called()

    def test_dns_timeout_is_sanitized_and_does_not_connect(self):
        pending=Mock();pending.result.side_effect=TimeoutError('synthetic DNS timeout')
        with patch('bridge.network._resolver_slots'),patch('bridge.network._resolver.submit',return_value=pending),patch('bridge.network.socket.socket') as dial:
            with self.assertRaises(NetworkError) as caught:public_addresses('dav.example.test',443)
            self.assertEqual(str(caught.exception),'provider_network_unavailable');dial.assert_not_called()

    def test_tls_preserves_original_sni_and_requires_verification(self):
        context = Mock(check_hostname=True, verify_mode=ssl.CERT_REQUIRED, minimum_version=ssl.TLSVersion.TLSv1_2)
        client = Mock(); wrap_tls(client, context, 'dav.example.test')
        context.wrap_socket.assert_called_once_with(client, server_hostname='dav.example.test')
        context.check_hostname = False
        with self.assertRaises(NetworkError): wrap_tls(client, context, 'dav.example.test')
        client.close.assert_called_once()


class ProviderConfigTests(unittest.TestCase):
    def test_presets_remain_default_and_custom_has_real_separate_interfaces(self):
        self.assertEqual(parse_profiles({'version':1, 'mail':{'preset':'gmx'}, 'caldav':{'preset':'icloud'}, 'carddav':{'preset':'icloud'}}), DEFAULT_PROFILES)
        profiles = parse_profiles(CUSTOM)
        self.assertEqual(profiles.mail.smtp_port, 587)
        self.assertEqual(profiles.caldav.validate_url('https://shard.example.test:8443/books/').hostname, 'shard.example.test')
        self.assertTrue(all(profile['experimental'] for profile in profiles.public().values()))
        with self.assertRaises(ValueError): profiles.caldav.validate_url(profiles.carddav.origin)

    def test_no_runtime_url_credentials_proxy_or_tls_bypass_options(self):
        for field in ('username', 'password', 'access_token', 'proxy', 'skip_tls', 'ca_file', 'endpoint'):
            value = copy.deepcopy(CUSTOM); value['caldav'][field] = 'synthetic'
            with self.assertRaises(ValueError): parse_profiles(value)

    def test_strict_safe_ports_tls_and_dns_allowlists(self):
        for slot, key, value in (('imap', 'port', 143), ('imap', 'tls', 'starttls'), ('smtp', 'port', 25), ('smtp', 'tls', 'optional'), ('imap','host','127.0.0.1')):
            config=copy.deepcopy(CUSTOM);config['mail'][slot][key]=value
            with self.assertRaises(ValueError):parse_profiles(config)
        for origin in ('http://calendar.example.test:8443/dav/', 'https://calendar.example.test:80/dav/', 'https://user:pass@calendar.example.test:8443/dav/',
                       'https://other.example.test:8443/dav/', 'https://calendar.example.test:8443/dav/?x=1', 'https://calendar.example.test:8443/dav/#x'):
            config=copy.deepcopy(CUSTOM);config['caldav']['origin']=origin
            with self.assertRaises(ValueError):parse_profiles(config)

    def test_redirect_cannot_cross_allowlist_or_forward_credentials(self):
        contacted=[]
        class Connection:
            def __init__(self,host,*args,**kwargs):contacted.append(host)
            def request(self,*args,**kwargs):pass
            def close(self):pass
            def getresponse(self):
                response=Mock(status=302);response.getheader.return_value='https://contacts.example.test/dav/';response.read.return_value=b'';return response
        with self.assertRaises(ApiError):CalDAV(('synthetic','SYNTHETIC_ONLY'),Connection,provider=parse_profiles(CUSTOM).caldav).request('PROPFIND',CUSTOM['caldav']['origin'],b'')
        self.assertEqual(contacted,['calendar.example.test'])

    def test_url_paths_traversal_controls_and_wrong_ports_rejected(self):
        profile=parse_profiles(CUSTOM).caldav
        for tail in ('%2e%2e/resource', '%252e%252e/resource', '%0d%0a', '%00', '%2fresource', '%5cresource', 'a/../b', 'a/./b', '%zz', '?', '#'):
            with self.assertRaises(ValueError):profile.validate_url(profile.origin+tail)
        for url in ('https://calendar.example.test/dav/','https://calendar.example.test:0/dav/'):
            with self.assertRaises(ValueError):profile.validate_url(url)
        config=copy.deepcopy(CUSTOM);config['carddav']['origin']='https://contacts.example.test:0/dav/'
        with self.assertRaises(ValueError):parse_profiles(config)

    def test_operator_file_is_bounded_read_only_schema_without_secret_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'providers.json';self.assertEqual(load_profiles(path),DEFAULT_PROFILES)
            path.write_text(json.dumps(CUSTOM));path.chmod(0o644);self.assertEqual(load_profiles(path),parse_profiles(CUSTOM))
            path.chmod(0o666)
            with self.assertRaises(ValueError):load_profiles(path)
            path.chmod(0o644);path.write_text('{"version":1,"version":1}')
            with self.assertRaises(ValueError):load_profiles(path)
            path.write_text('x'*16385)
            with self.assertRaises(ValueError):load_profiles(path)
            link=Path(directory)/'link.json';link.symlink_to(path)
            with self.assertRaises(ValueError):load_profiles(link)

    def test_changed_profile_requires_credential_reentry_and_changes_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            original=AccountSecrets(directory);saved=original.persist('mail','opaque-login','SYNTHETIC_ONLY',None,'sender@example.invalid')
            changed=AccountSecrets(directory,profiles=parse_profiles(CUSTOM))
            status=changed.status(True)['mail'];self.assertFalse(status['configured']);self.assertNotEqual(saved['revision'],status['revision'])
            with self.assertRaises(ApiError):changed.pair('mail')
            with self.assertRaises(ApiError):
                with changed.operation('mail'):pass
            updated=changed.persist('mail','opaque-login','SYNTHETIC_ONLY',status['revision'],'sender@example.invalid')
            self.assertTrue(updated['configured']);self.assertEqual(changed.pair('mail')[0],'opaque-login');self.assertEqual(changed.sender(),'sender@example.invalid')

    def test_caldav_carddav_credentials_and_revisions_are_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            accounts=AccountSecrets(directory,profiles=parse_profiles(CUSTOM))
            one=accounts.persist('caldav','calendar-login','SYNTHETIC_CAL_ONLY',None)
            two=accounts.persist('carddav','contacts-login','SYNTHETIC_CARD_ONLY',None)
            self.assertNotEqual(one['revision'],two['revision']);self.assertEqual(accounts.pair('caldav')[0],'calendar-login');self.assertEqual(accounts.pair('carddav')[0],'contacts-login')
            with self.assertRaises(ApiError):accounts.persist('carddav','contacts-login','SYNTHETIC_CARD_ONLY',two['revision'],'sender@example.invalid')
