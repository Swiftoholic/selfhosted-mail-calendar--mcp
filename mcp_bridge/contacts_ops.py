"""Separately consented CardDAV reads; cached references contain no contact data."""
import hashlib

from bridge.app import ApiError, bounded_int, fields
from bridge.carddav import Contacts
from .accounts import bind_id, current_revision, current_account_id
from .config import ORIGIN
from .mail_ops import opaque


class ContactsOperations(Contacts):
    def __init__(self, secrets, store, factory=None):
        super().__init__(secrets, factory)
        self.store = store

    def consent(self, identifier, generation=None):
        revision = current_revision(self.secrets, 'carddav')
        consent = self.store.contacts_consent(revision, opaque(identifier))
        if not consent:
            raise ApiError(403, 'contacts_addressbook_consent_required')
        if generation is not None and consent['generation'] != generation:
            raise ApiError(409, 'contacts_consent_changed_or_revoked')
        return revision, consent

    def selected(self, identifier):
        client, books = self.discover()
        book = next((book for book in books if book['id'] == opaque(identifier)), None)
        if not book:
            raise ApiError(404, 'addressbook_not_found')
        return client, book

    def list_books(self, data):
        fields(data, {'limit'})
        limit = bounded_int(data.get('limit', 25), 1, 25)
        revision = current_revision(self.secrets, 'carddav')
        _, books = self.discover()
        with self.store.lock:
            items = [{'id': book['id'], 'name': book['name'], 'data_trust': 'untrusted'} for book in books
                     if self.store.contacts_consent(revision, book['id']) is not None]
        return {'items': items[:limit], 'limit': limit, 'data_trust': 'untrusted', 'read_only': True,
                'configuration_url': ORIGIN + '/accounts#contacts-access', 'default_read_enabled': False}

    def search(self, data):
        fields(data, {'addressbook_id', 'query', 'limit'})
        term = data.get('query')
        if not isinstance(term, str) or not term.strip() or len(term) > 100 or any(ord(c) < 32 or ord(c) == 127 for c in term):
            raise ApiError(400, 'invalid_contact_query')
        limit = bounded_int(data.get('limit', 25), 1, 50)
        identifier = opaque(data.get('addressbook_id'))
        revision, consent = self.consent(identifier)
        client, book = self.selected(identifier)
        result = self.search_book(client, book, term, limit)
        with self.store.transaction():
            self.consent(identifier, consent['generation'])
            for item in result['items']:
                url = item.pop('_resource_url')
                key = hashlib.sha256((revision + ':' + consent['generation'] + ':' + url).encode('utf-8')).hexdigest()[:24]
                self.store.put('contact_ref', key, {'account_revision': revision, 'account_id':current_account_id(self.secrets, 'carddav'), 'addressbook_id': identifier,
                               'generation': consent['generation'], 'url': url}, 600, maximum=100)
                item['id'], item['addressbook_id'] = key, identifier
        return {**result, 'read_only': True, 'reference_expires_in': 600}

    def read(self, data):
        fields(data, {'contact_id'})
        key = opaque(data.get('contact_id'))
        revision = current_revision(self.secrets, 'carddav')
        reference = self.store.get('contact_ref', key)
        if not reference or reference.get('account_revision') != revision or reference.get('account_id') != current_account_id(self.secrets, 'carddav'):
            raise ApiError(404, 'contact_reference_expired_search_again')
        identifier = reference['addressbook_id']
        self.consent(identifier, reference['generation'])
        client, book = self.selected(identifier)
        item = self.read_resource(client, book, reference['url'])
        with self.store.lock:
            self.consent(identifier, reference['generation'])
        item.pop('_resource_url')
        item.update(id=key, addressbook_id=identifier, read_only=True)
        return item


class ContactsConsents:
    def __init__(self, store, accounts, contacts):
        self.store, self.accounts, self.contacts = store, accounts, contacts

    def list(self):
        with self.accounts.operation('carddav') as account:
            _, books = self.contacts.discover()
            consents = {row['addressbook_id']: row for row in self.store.contacts_consents(account.revision)}
            items = []
            for book in books:
                consent = consents.pop(book['id'], None)
                items.append({'id': bind_id(book['id'], account.revision, 'addressbook'), 'name': book['name'],
                              'read_enabled': consent is not None, 'generation': consent['generation'] if consent else None,
                              'available_for_selection': True, 'data_trust': 'untrusted'})
            for identifier, consent in consents.items():
                items.append({'id': bind_id(identifier, account.revision, 'addressbook'), 'name': 'Adressbuch nicht mehr verfügbar',
                              'read_enabled': True, 'generation': consent['generation'], 'available_for_selection': False, 'data_trust': 'untrusted'})
            return {'items': items, 'account_revision': account.revision, 'default_read_enabled': False,
                    'read_only': True, 'configuration_url': ORIGIN + '/accounts#contacts-access'}

    def target(self, data, revision):
        if data.get('expected_revision') != revision:
            raise ApiError(409, 'contacts_account_changed_reload')
        identifier = bind_id(opaque(data.get('addressbook_id')), revision, 'addressbook')
        expected = data.get('expected_generation')
        if expected is not None:
            opaque(expected)
        consent = self.store.contacts_consent(revision, identifier)
        if (consent['generation'] if consent else None) != expected:
            raise ApiError(409, 'contacts_consent_changed_reload')
        return identifier

    def action(self, action, data, authorize):
        allowed = {'addressbook_id', 'expected_revision', 'expected_generation'}
        if action == 'save':
            allowed.add('read_access_acknowledged')
        fields(data, allowed)
        if set(data) != allowed or action not in ('save', 'revoke'):
            raise ApiError(400, 'invalid_contacts_consent_request')
        with self.accounts.operation('carddav') as account:
            identifier = self.target(data, account.revision)
            if action == 'save':
                if data['read_access_acknowledged'] is not True:
                    raise ApiError(400, 'contacts_read_confirmation_required')
                self.contacts.selected(identifier)
            with self.store.transaction():
                authorize()
                self.target(data, account.revision)
                if action == 'save':
                    consent = self.store.set_contacts_consent(account.revision, identifier)
                    generation = consent['generation']
                else:
                    self.store.revoke_contacts_consent(account.revision, identifier)
                    generation = None
            return {'addressbook_id': data['addressbook_id'], 'read_enabled': action == 'save',
                    'generation': generation, 'stale_references_invalidated': True, 'provider_changed': False, 'read_only': True}
