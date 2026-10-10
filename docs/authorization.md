# Owner authorization

The first browser creates a short-lived enrollment request. An operator with access to the deployment's interactive terminal approves only the fingerprint displayed in that same browser. Approval expires after five minutes. Enrollment uses WebAuthn on the configured HTTPS origin; there is no enrollment bearer token, default owner password or reusable setup secret.

After passkey login, `/accounts` allows the owner to check and replace separate mail, CalDAV and CardDAV credentials. Its JSON endpoints require the exact origin, a session, CSRF protection and recent owner verification. Bearer tokens cannot save accounts or grant calendar/contact capability. Account replacement uses atomic files and a new revision; stale provider IDs/previews and calendar/contact permissions cannot carry over to the new account.

The OAuth implementation uses authorization code, S256 PKCE and exact resource/client/callback binding. It verifies only the supported ChatGPT client metadata URLs, resolves only public IPs and does not follow metadata redirects. All scopes require owner consent:

| Scope | Capability |
| --- | --- |
| `bridge:read` | Sanitized configured/connection status |
| `mail:read` | Bounded mail/folder search and reading |
| `calendars:read` | Bounded calendar discovery and event reading |
| `contacts:read` | Minimal contact search/read in owner-enabled books; excluded from default scopes |
| `mail:write` | Explicitly confirmed read/star flag changes, moves and trash |
| `mail:send` | Fresh send preview followed by explicit confirmation |
| `calendars:write` | Fresh calendar preview followed by explicit confirmation, in owner-enabled calendars only |
| `offline_access` | Optional bounded rotating refresh family; not a provider password |

Access tokens expire after 900 seconds. Refresh families have a 30-day idle limit, a 90-day absolute limit and at most four active families. Refresh rotation consumes the previous token atomically; replay revokes the family. Signing out revokes the browser session. The login page allows OAuth grant revocation; recovery revokes the owner's passkeys, sessions and grants.

## Calendar capability and audience

Open `/accounts#calendar-access` in a passkey session verified within the past five minutes. Load the calendars explicitly, select the exact calendar, inspect its provider metadata and enable it. There is no automatic selection by calendar name and no hidden allowlist.

An audience of `unknown` is an honest uncertainty, not a finding that the calendar is private. iCloud can omit ACL/sharing properties. Shared or uncertain calendars require an acknowledgement about other members and possible notifications. A provider denial of write permission still blocks writes. This setting enables technical capability only; an assistant still needs a specific instruction and confirmation for each action. Revoke it on the same page.

Calendar consent binds the provider-account revision, exact calendar ID and a generation. Revocation, re-enablement, account replacement and owner recovery invalidate prepared operations. Commit rechecks the provider and current audience; a changed audience requires a new preview. Create/update/delete exclude attendees, scheduling invitations, recurrence, complex events and reminders. Update/delete use an ETag to reject stale content. Repeated or uncertain commits do not blindly retry provider writes.

## Contact capability

Open /accounts#contacts-access in a recent passkey session. Load metadata explicitly, select exactly one book and acknowledge reading names, emails and phones. No book is preselected. This capability and a separately approved contacts:read OAuth scope are both required. Existing grants cannot upgrade through refresh; reconnect and approve the new scope. Contact writes have no scope or tool.

Consent binds the CardDAV account revision, exact book and generation. Revocation/re-enablement, account replacement, profile change and recovery invalidate references. Search returns at most 50 minimal records; read needs an unexpired opaque reference from search. URLs/photos/notes/binary fields are never fetched or returned. Book consent is rechecked after network work and OAuth validity before disclosure. Operator endpoint changes require credential reentry; previous secrets cannot automatically go to new hosts.

## Recovery

Use an interactive terminal you control:

```sh
docker compose exec mcp python -m mcp_bridge.admin recover
```

Read its effects and type the exact printed confirmation yourself. Then enroll a new passkey with a new browser fingerprint. This is an operator action, never an HTTP API or a support workflow that asks for your credentials. Provider app passwords must be revoked separately at their provider if they may have been compromised.
