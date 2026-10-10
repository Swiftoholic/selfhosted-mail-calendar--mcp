"""Documented endpoint templates; live provider access is not implied.

Primary sources and authentication prerequisites are shown in the owner UI.
OAuth-only choices have no password transport. See docs/provider-templates.md.
"""
import re
from .providers import DAVProvider, GMX, ICLOUD_CALDAV, ICLOUD_CARDDAV, MailProvider

GMX_AUTH = 'https://hilfe.gmx.net/sicherheit/2fa/anwendungsspezifisches-passwort.html'
WEBDE_AUTH = 'https://hilfe.web.de/sicherheit/2fa/anwendungsspezifisches-passwort.html'
APPLE_AUTH = 'https://support.apple.com/en-us/102654'
FASTMAIL = 'https://www.fastmail.help/hc/en-us/articles/1500000278342-Server-names-and-ports'
GOOGLE_AUTH = 'https://support.google.com/accounts/answer/185833'
MICROSOFT = 'https://support.microsoft.com/en-au/outlook/pop-imap-and-smtp-settings-for-outlook-com'
MAILBOX_AUTH = 'https://kb.mailbox.org/en/business/security-and-privacy/application-passwords-for-external-programs/'
YAHOO_MAIL = 'https://uk.help.yahoo.com/kb/SLN3697.html'


def bundle():
    entries, info = {}, {}

    def add(key, name, profile, note, auth, sources, help_url=None):
        entries[key] = (profile.protocol if isinstance(profile, DAVProvider) else 'mail', name, profile)
        info[key] = {'info_key': note, 'auth_mode': auth, 'source_urls': list(sources),
                     'auth_help_url': help_url or sources[0], 'verification': 'documented_not_live_tested'}

    def mail(key, name, ident, imap, smtp, port, note, auth, sources, help_url=None):
        add(key, name, MailProvider(ident, imap, 993, smtp, port), note, auth, sources, help_url)

    def dav(key, name, ident, protocol, origin, host, note, auth, sources, help_url=None):
        add(key, name, DAVProvider(ident, protocol, origin, re.escape(host)), note, auth, sources, help_url)

    # Exact legacy fingerprints and iCloud shard policy remain unchanged.
    add('gmx-mail', 'GMX (DE/AT)', GMX, 'provider.gmx', 'app_password_recommended',
        ['https://hilfe.gmx.net/pop-imap/imap/imap-serverdaten.html', GMX_AUTH], GMX_AUTH)
    add('icloud-caldav', 'iCloud', ICLOUD_CALDAV, 'provider.icloud_dav', 'app_password_required', [APPLE_AUTH])
    add('icloud-carddav', 'iCloud', ICLOUD_CARDDAV, 'provider.icloud_dav', 'app_password_required', [APPLE_AUTH])
    for protocol in ('caldav', 'carddav'):
        gmx_source = ('https://hilfe.gmx.net/kalender/synchronisieren/mac.html' if protocol == 'caldav'
                      else 'https://hilfe.gmx.net/ios/addressbuch-bearbeiten.html')
        web_source = ('https://hilfe.web.de/kalender/synchronisieren/mac.html' if protocol == 'caldav'
                      else 'https://hilfe.web.de/ios/einstellungen/sync.html')
        dav('gmx-' + protocol, 'GMX (DE/AT)', 'gmx', protocol, 'https://' + protocol + '.gmx.net/',
            protocol + '.gmx.net', 'provider.gmx_dav', 'app_password_required', [gmx_source, GMX_AUTH], GMX_AUTH)
        dav('webde-' + protocol, 'WEB.DE', 'webde', protocol, 'https://' + protocol + '.web.de/',
            protocol + '.web.de', 'provider.webde_dav', 'app_password_required', [web_source, WEBDE_AUTH], WEBDE_AUTH)
        host = protocol + '.fastmail.com'
        dav('fastmail-' + protocol, 'Fastmail', 'fastmail', protocol, 'https://' + host + '/',
            host, 'provider.fastmail', 'app_password_required', [FASTMAIL])
        origin = 'https://dav.mailbox.org/' if protocol == 'caldav' else 'https://dav.mailbox.org/carddav/'
        dav('mailbox-' + protocol, 'mailbox.org', 'mailbox', protocol, origin, 'dav.mailbox.org',
            'provider.mailbox', 'app_password_with_2fa',
            ['https://kb.mailbox.org/en/private/addressbook-and-calendar/caldav-carddav-for-outlook-caldav-synchronizer/', MAILBOX_AUTH], MAILBOX_AUTH)
    mail('webde-mail', 'WEB.DE', 'webde', 'imap.web.de', 'smtp.web.de', 587, 'provider.webde', 'app_password_recommended',
         ['https://hilfe.web.de/pop-imap/imap/imap-serverdaten.html', WEBDE_AUTH], WEBDE_AUTH)
    mail('gmx-com-mail', 'GMX International', 'gmx-com', 'imap.gmx.com', 'mail.gmx.com', 587, 'provider.gmx_com', 'app_password_recommended',
         ['https://support.gmx.com/pop-imap/imap/server.html'])
    mail('icloud-mail', 'iCloud Mail', 'icloud', 'imap.mail.me.com', 'smtp.mail.me.com', 587, 'provider.icloud_mail', 'app_password_required',
         ['https://support.apple.com/en-ie/102525', APPLE_AUTH], APPLE_AUTH)
    mail('yahoo-mail', 'Yahoo', 'yahoo', 'imap.mail.yahoo.com', 'smtp.mail.yahoo.com', 465, 'provider.yahoo_mail', 'app_password_required', [YAHOO_MAIL])
    dav('yahoo-caldav', 'Yahoo', 'yahoo', 'caldav', 'https://caldav.calendar.yahoo.com/', 'caldav.calendar.yahoo.com',
        'provider.yahoo_caldav', 'app_password_required', ['https://help.yahoo.com/kb/SLN4707.html'])
    mail('mailbox-mail', 'mailbox.org', 'mailbox', 'imap.mailbox.org', 'smtp.mailbox.org', 465, 'provider.mailbox', 'app_password_with_2fa',
         ['https://kb.mailbox.org/en/business/e-mail/e-mail-configuration/', MAILBOX_AUTH], MAILBOX_AUTH)
    mail('fastmail-mail', 'Fastmail', 'fastmail', 'imap.fastmail.com', 'smtp.fastmail.com', 465, 'provider.fastmail', 'app_password_required', [FASTMAIL])
    mail('google-mail', 'Gmail (app password)', 'google', 'imap.gmail.com', 'smtp.gmail.com', 465,
         'provider.google_mail', 'conditional_app_password', ['https://developers.google.com/workspace/gmail/imap/imap-smtp', GOOGLE_AUTH], GOOGLE_AUTH)
    unsupported = [
        {'id': 'google-caldav', 'protocol': 'caldav', 'name': 'Google Calendar', 'supported': False,
         'auth_mode': 'oauth_required', 'info_key': 'provider.google_oauth',
         'source_urls': ['https://developers.google.com/workspace/calendar/caldav/v2/guide']},
        {'id': 'google-carddav', 'protocol': 'carddav', 'name': 'Google Contacts', 'supported': False,
         'auth_mode': 'oauth_required', 'info_key': 'provider.google_oauth', 'source_urls': ['https://developers.google.com/people/carddav']},
        {'id': 'microsoft-mail', 'protocol': 'mail', 'name': 'Outlook.com / Microsoft 365', 'supported': False,
         'auth_mode': 'oauth_required', 'info_key': 'provider.microsoft_oauth', 'source_urls': [MICROSOFT,
         'https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth']},
    ] + [{'id': 'posteo-' + protocol, 'protocol': protocol, 'name': 'Posteo', 'supported': False,
          'auth_mode': 'manual_only', 'info_key': 'provider.posteo_unverified', 'source_urls': ['https://posteo.de/hilfe']}
         for protocol in ('mail', 'caldav', 'carddav')]
    for choice in unsupported:
        choice['auth_help_url'] = choice['source_urls'][0]
    return entries, info, unsupported
