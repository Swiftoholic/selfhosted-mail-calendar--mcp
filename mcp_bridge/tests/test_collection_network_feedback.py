"""Owner collection discovery failures must not look like rejected consent."""
import unittest
from unittest.mock import patch

from bridge.network import NetworkError
from mcp_bridge.tests.test_contacts_access import ContactsAccessTests


class CollectionNetworkFeedbackTests(ContactsAccessTests):
    def list_request(self):
        return self.client.post('/accounts/contacts/list', json={
            'csrf': self.status()['csrf'],
            'account_id': self.accounts.account_id('carddav'),
        })

    def test_discovery_network_failure_is_a_provider_error_without_consent(self):
        self.enroll()
        with patch.object(self.contacts, 'discover', side_effect=NetworkError()):
            response = self.list_request()
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json(), {'error': 'provider_network_unavailable'})
        self.assertEqual(self.store.contacts_consents(self.accounts.revision('carddav')), [])
        self.assertEqual(self.fixture.methods, [])

    def test_discovery_timeout_never_exposes_exception_details(self):
        self.enroll()
        marker = 'SYNTHETIC_PASSWORD_TOKEN_COOKIE_DETAIL'
        with patch.object(self.contacts, 'discover', side_effect=TimeoutError(marker)):
            response = self.list_request()
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json(), {'error': 'provider_network_unavailable'})
        self.assertNotIn(marker, response.text)
        self.assertEqual(self.store.contacts_consents(self.accounts.revision('carddav')), [])

    def test_save_network_failure_does_not_grant_or_change_book_access(self):
        self.enroll()
        listing = self.owner_books()
        book = listing['items'][0]
        payload = {
            'csrf': self.status()['csrf'],
            'account_id': self.accounts.account_id('carddav'),
            'addressbook_id': book['id'],
            'expected_revision': listing['account_revision'],
            'expected_generation': book['generation'],
            'read_access_acknowledged': True,
        }
        with patch.object(self.contacts, 'discover', side_effect=NetworkError()):
            response = self.client.post('/accounts/contacts/save', json=payload)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json(), {'error': 'provider_network_unavailable'})
        self.assertEqual(self.store.contacts_consents(listing['account_revision']), [])


def load_tests(loader, tests, pattern):
    # Use the existing real HTTP/owner fixture without re-running inherited tests.
    return unittest.TestSuite(CollectionNetworkFeedbackTests(name)
        for name in CollectionNetworkFeedbackTests.__dict__ if name.startswith('test_'))
