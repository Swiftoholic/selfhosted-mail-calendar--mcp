from .config import ORIGIN
"""Human-only, revision-bound calendar write capabilities; never event approval."""
import re
from urllib.parse import urljoin

from bridge.app import ApiError, DAV, propfind, successful_props, icloud_url, fields
from bridge.providers import ICLOUD_CALDAV
from .accounts import bind_id
from .mail_ops import opaque

CS = 'http://calendarserver.org/ns/'
AUDIENCE_WARNING = 'Andere Kalendermitglieder oder Empfänger einer öffentlichen Freigabe können Änderungen sehen. Der Anbieter kann sie über Änderungen benachrichtigen.'
CAPABILITY_WARNING = 'Diese Freigabe erlaubt der Bridge technisch das Schreiben in genau diesen Kalender. Für jeden Termin ist weiterhin ein konkreter Auftrag mit Vorschau nötig.'


def metadata(client, selected):
    validate = getattr(client, 'url_validator', icloud_url)
    validate(selected['url'])
    xml, base = client.request('PROPFIND', selected['url'], propfind(
        (DAV, 'owner'), (DAV, 'acl'), (DAV, 'current-user-privilege-set'),
        (CS, 'invite'), (CS, 'shared-url'), (DAV, 'resourcetype')))
    props = [p for response, p in successful_props(xml)
             if urljoin(base, response.findtext('{' + DAV + '}href', '')).rstrip('/') == base.rstrip('/')]
    principal_xml, principal_base = client.request('PROPFIND', getattr(client, 'origin', ICLOUD_CALDAV.origin), propfind((DAV, 'current-user-principal')))
    principals = [urljoin(principal_base, href).rstrip('/') for _, p in successful_props(principal_xml)
                  if (href := p.findtext('{' + DAV + '}current-user-principal/{' + DAV + '}href'))]
    principal = principals[0] if len(principals) == 1 else None
    if principal:
        try: validate(principal + '/')
        except ApiError: principal = None
    owners = [urljoin(base, href).rstrip('/') for p in props if (href := p.findtext('{' + DAV + '}owner/{' + DAV + '}href'))]
    acls = [element for p in props for element in p.findall('{' + DAV + '}acl')]
    aces = [ace for acl in acls for ace in acl.findall('{' + DAV + '}ace')]
    owner_only = bool(principal and owners == [principal] and len(acls) == 1 and aces)
    for ace in aces:
        element = ace.find('{' + DAV + '}principal')
        href = ace.findtext('{' + DAV + '}principal/{' + DAV + '}href')
        owner_property = ace.find('{' + DAV + '}principal/{' + DAV + '}property/{' + DAV + '}owner') is not None
        if (element is None or len(element) != 1 or
            ace.find('{' + DAV + '}grant') is None and ace.find('{' + DAV + '}deny') is None or
            not owner_property and (not href or urljoin(base, href).rstrip('/') != principal)):
            owner_only = False
    sharing = any(p.find('{' + CS + '}shared-url') is not None or p.findall('.//{' + CS + '}invite/{' + CS + '}user') or
                  p.find('.//{' + CS + '}shared') is not None or p.find('.//{' + CS + '}shared-owner') is not None for p in props)
    audience = 'shared_or_public' if sharing else 'private_verified' if owner_only else 'unknown'
    sets = [element for p in props for element in p.findall('{' + DAV + '}current-user-privilege-set')]
    if len(sets) == 1:
        privileges = {child.tag for privilege in sets[0].findall('{' + DAV + '}privilege') for child in list(privilege)}
        def has(*names): return any('{' + DAV + '}' + name in privileges for name in names)
        # DAV:write aggregates bind/unbind as well as write-content (RFC 3744).
        actions = {'create': has('all', 'write', 'bind'), 'update': has('all', 'write', 'write-content'), 'delete': has('all', 'write', 'unbind')}
        permission = 'available' if any(actions.values()) else 'denied'
    else:
        actions = {name: None for name in ('create', 'update', 'delete')}
        permission = 'unknown'
    return {'calendar_audience': audience, 'other_members_may_see_changes': audience != 'private_verified',
            'provider_may_notify_members': audience != 'private_verified', 'write_permission': permission,
            'permitted_actions': actions, 'requires_audience_acknowledgement': audience != 'private_verified'}


class CalendarConsents:
    def __init__(self, store, accounts, calendar):
        self.store, self.accounts, self.calendar = store, accounts, calendar

    def list(self):
        with self.accounts.operation('caldav') as account:
            _, calendars = self.calendar.discover()
            consents = {row['calendar_id']: row for row in self.store.calendar_consents(account.revision)}
            items = []
            for calendar in calendars:
                consent = consents.pop(calendar['id'], None)
                items.append({'id': bind_id(calendar['id'], account.revision, 'calendar'), 'name': calendar['name'],
                              'write_enabled': consent is not None, 'generation': consent['generation'] if consent else None,
                              'available_for_selection': True, 'data_trust': 'untrusted'})
            for identifier, consent in consents.items():
                items.append({'id': bind_id(identifier, account.revision, 'calendar'), 'name': 'Nicht mehr in der aktuellen Kalenderliste',
                              'write_enabled': True, 'generation': consent['generation'], 'available_for_selection': False, 'data_trust': 'untrusted'})
            return {'items': items, 'account_revision': account.revision, 'default_write_enabled': False,
                    'capability_is_not_event_approval': True, 'configuration_url': ORIGIN + '/accounts#calendar-access'}

    def target(self, data, revision):
        if data.get('expected_revision') != revision:
            raise ApiError(409, 'calendar_account_changed_reload')
        identifier = bind_id(opaque(data.get('calendar_id')), revision, 'calendar')
        expected = data.get('expected_generation')
        if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r'[a-f0-9]{24}', expected)):
            raise ApiError(400, 'invalid_calendar_consent_request')
        consent = self.store.calendar_consent(revision, identifier)
        if (consent['generation'] if consent else None) != expected:
            raise ApiError(409, 'calendar_consent_changed_reload')
        return identifier

    def action(self, action, data, authorize):
        allowed = {'calendar_id', 'expected_revision', 'expected_generation'}
        if action == 'save':
            allowed |= {'audience_acknowledged', 'capability_only_acknowledged'}
        fields(data, allowed)
        if set(data) != allowed or action not in {'inspect', 'save', 'revoke'}:
            raise ApiError(400, 'invalid_calendar_consent_request')
        with self.accounts.operation('caldav') as account:
            identifier = self.target(data, account.revision)
            if action == 'revoke':
                with self.store.transaction():
                    authorize()
                    self.target(data, account.revision)
                    self.store.revoke_calendar_consent(account.revision, identifier)
                return {'calendar_id': data['calendar_id'], 'write_enabled': False, 'stale_previews_invalidated': True, 'provider_changed': False}
            client, selected = self.calendar.selected(identifier)
            details = metadata(client, selected)
            result = {'calendar_id': data['calendar_id'], 'calendar_name': selected['name'], **details,
                      'audience_warning': AUDIENCE_WARNING, 'capability_warning': CAPABILITY_WARNING,
                      'capability_is_not_event_approval': True, 'provider_changed': False}
            if action == 'inspect':
                authorize()
                return result
            if data.get('capability_only_acknowledged') is not True or type(data.get('audience_acknowledged')) is not bool:
                raise ApiError(400, 'calendar_capability_confirmation_required')
            if details['requires_audience_acknowledgement'] and data['audience_acknowledged'] is not True:
                raise ApiError(400, 'calendar_audience_acknowledgement_required')
            if details['write_permission'] == 'denied':
                raise ApiError(403, 'calendar_write_permission_denied')
            with self.store.transaction():
                authorize()
                self.target(data, account.revision)
                consent = self.store.set_calendar_consent(account.revision, identifier, data['audience_acknowledged'])
            return {**result, 'write_enabled': True, 'generation': consent['generation'], 'stale_previews_invalidated': True}
