# Documented provider templates

Sources checked on 2026-10-10. These templates supply documented endpoints and authentication guidance, not a claim of live interoperability. Each account still needs its own successful connection check and explicit storage confirmation. Checks authenticate mail or read DAV discovery metadata only; calendar audience/privileges and addressbook consent are assessed separately. Existing GMX/iCloud profile fingerprints and the iCloud shard policy remain unchanged.

## Mail

Every listed IMAP endpoint uses implicit TLS on 993. SMTP 465 uses implicit TLS; SMTP 587 requires STARTTLS before authentication. The template selects the SMTP port shown below; manual configuration can use another officially documented supported TLS pair.

| Template | IMAP host | SMTP host / port | Login and prerequisites | Official sources |
| --- | --- | --- | --- | --- |
| GMX (DE/AT) | imap.gmx.net | mail.gmx.net / 465 | Full email address; enable IMAP; use an app password with 2FA | [Server settings](https://hilfe.gmx.net/pop-imap/imap/imap-serverdaten.html), [app passwords](https://hilfe.gmx.net/sicherheit/2fa/anwendungsspezifisches-passwort.html) |
| WEB.DE | imap.web.de | smtp.web.de / 587 | Full email address; enable IMAP; use an app password with 2FA | [Server settings](https://hilfe.web.de/pop-imap/imap/imap-serverdaten.html), [app passwords](https://hilfe.web.de/sicherheit/2fa/anwendungsspezifisches-passwort.html) |
| GMX International | imap.gmx.com | mail.gmx.com / 587 | Full email address; separate from the DE/AT endpoints | [Server settings](https://support.gmx.com/pop-imap/imap/server.html) |
| iCloud Mail | imap.mail.me.com | smtp.mail.me.com / 587 | Full iCloud email address; Apple 2FA and an app-specific password required | [Mail settings](https://support.apple.com/en-ie/102525), [app-specific passwords](https://support.apple.com/en-us/102654) |
| Yahoo | imap.mail.yahoo.com | smtp.mail.yahoo.com / 465 | Full email address and an app password | [Mail settings](https://uk.help.yahoo.com/kb/SLN3697.html) |
| mailbox.org | imap.mailbox.org | smtp.mailbox.org / 465 | Primary account email address; app password required with 2FA, recommended for integration isolation | [Mail settings](https://kb.mailbox.org/en/business/e-mail/e-mail-configuration/), [app passwords](https://kb.mailbox.org/en/business/security-and-privacy/application-passwords-for-external-programs/) |
| Fastmail | imap.fastmail.com | smtp.fastmail.com / 465 | Original account address and app password with mail permission; Basic plans lack external protocol access | [Server settings and prerequisites](https://www.fastmail.help/hc/en-us/articles/1500000278342-Server-names-and-ports) |
| Gmail (app password) | imap.gmail.com | smtp.gmail.com / 465 | Full address; eligible accounts can use a 2FA app password. Organization policy, security-key-only settings or Advanced Protection may prevent this | [IMAP/SMTP](https://developers.google.com/workspace/gmail/imap/imap-smtp), [app-password eligibility](https://support.google.com/accounts/answer/185833) |

## Calendar and contacts

Each CalDAV/CardDAV template uses HTTPS on 443 and an exact host, except the preserved iCloud policy which permits its established discovery shards. A manual DAV configuration permits only its URL's host; a redirect to another hostname fails closed. Mail, calendar and contacts are separate integrations and can need different login identifiers or app-password permissions.

| Provider | CalDAV root | CardDAV root | Login and prerequisites | Official sources |
| --- | --- | --- | --- | --- |
| iCloud | https://caldav.icloud.com/ | https://contacts.icloud.com/ | Existing bridge roots/shard policy; Apple account login and app-specific password. Apple's cited article establishes authentication requirements, not these DAV root URLs | [Apple app-specific passwords](https://support.apple.com/en-us/102654) |
| GMX (DE/AT) | https://caldav.gmx.net/ | https://carddav.gmx.net/ | Full email address and app password | [Calendar](https://hilfe.gmx.net/kalender/synchronisieren/mac.html), [contacts](https://hilfe.gmx.net/ios/addressbuch-bearbeiten.html), [app passwords](https://hilfe.gmx.net/sicherheit/2fa/anwendungsspezifisches-passwort.html) |
| WEB.DE | https://caldav.web.de/ | https://carddav.web.de/ | Full email address and app password | [Calendar](https://hilfe.web.de/kalender/synchronisieren/mac.html), [contacts](https://hilfe.web.de/ios/einstellungen/sync.html), [app passwords](https://hilfe.web.de/sicherheit/2fa/anwendungsspezifisches-passwort.html) |
| mailbox.org | https://dav.mailbox.org/ | https://dav.mailbox.org/carddav/ | Primary account address; use an app password with the relevant DAV permission, required with 2FA | [CalDAV/CardDAV setup](https://kb.mailbox.org/en/private/addressbook-and-calendar/caldav-carddav-for-outlook-caldav-synchronizer/), [app passwords](https://kb.mailbox.org/en/business/security-and-privacy/application-passwords-for-external-programs/) |
| Fastmail | https://caldav.fastmail.com/ | https://carddav.fastmail.com/ | Original account address and app password with calendar/contact permission; Basic plans excluded | [Server settings and prerequisites](https://www.fastmail.help/hc/en-us/articles/1500000278342-Server-names-and-ports) |
| Yahoo | https://caldav.calendar.yahoo.com/ | No verified template | Yahoo ID and app-generated password | [CalDAV setup](https://help.yahoo.com/kb/SLN4707.html) |

## Informative choices and authentication limits

Keep the provider's 2FA enabled. These password transports cannot show an interactive second-factor prompt; the owner UI explains the applicable app-password rule beside the password field and links to official help. No instruction suggests disabling 2FA.

Google Calendar and Contacts require provider OAuth and appear as unavailable informative choices: [Google CalDAV](https://developers.google.com/workspace/calendar/caldav/v2/guide), [Google CardDAV](https://developers.google.com/people/carddav). Microsoft Outlook.com/Microsoft 365 mail likewise requires an OAuth transport; its choice cannot run a password check or save: [Outlook settings](https://support.microsoft.com/en-au/outlook/pop-imap-and-smtp-settings-for-outlook-com), [Microsoft protocol OAuth](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth). Gmail's conditional mail app-password template does not imply Google DAV or provider OAuth support.

Posteo's official endpoint documentation could not be retrieved for verification during this change. Its informative choices link to [official help](https://posteo.de/hilfe); they contain no guessed endpoints. An owner can use **Other provider / Manual** after independently checking the provider's current instructions. Yahoo CardDAV, GMX International DAV and Microsoft DAV are not advertised as templates without verified compatible endpoints.

New templates grant no capabilities or collection consent. A successful connection check does not prove that a calendar is private, that all writes are supported or that notifications are absent. See [limits](limitations.md) and [account management](accounts.md).
