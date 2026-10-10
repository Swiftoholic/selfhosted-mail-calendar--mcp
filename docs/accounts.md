# Independent account management

The bridge still has one owner and one passkey/OAuth identity. It supports up to 32 independent integrations in total, including several accounts of the same protocol. A mail integration uses both IMAP and SMTP; calendar and contact integrations use CalDAV and CardDAV separately. Two integrations may use the same provider or login without sharing capabilities or collection consent.

After a recent passkey login, `/accounts` shows the integration's label, provider, protocol, login, selected capabilities and last explicitly recorded connection test. Opening the page does not test a provider or discover collections. A successful past check is a timestamped result; it does not guarantee current availability. Passwords are never returned by the owner API or MCP tools. The host administrator can still read the private credential volume.

## Add, edit, test and remove

The wizard has three steps: choose protocol/profile, enter credentials and capabilities, then review a successful connection test before confirming storage. Only profiles from the fixed operator configuration appear. There are no browser-supplied server URLs. Mail requires an explicit sender email address. The owner enters the app password locally; empty passwords are accepted only while editing an unchanged profile and retain the existing password.

New integrations start with no MCP capabilities. A successful connection test authenticates IMAP/SMTP or reads DAV discovery metadata. It never sends mail, reads contact bodies or writes events. The test creates a five-minute proof bound to the owner session and the exact submitted credentials, sender, profile, label and capabilities. Changing input, going back or canceling requires another test; passwords and test proofs are cleared from the wizard. Saving does not repeat the network test. Back/cancel are disabled during the final storage request, and uncertain saves require a status check before retrying.

Editing keeps the stable account ID and rotates its revision. All previous IDs, previews and references for that revision become stale; affected calendar/addressbook consent must be selected again. Retesting keeps the revision and changes only the stored connection result. Removing an integration deletes its local account record and retires its local permissions/previews/references. It does not delete folders, messages, calendars, events or contacts at the provider. Operation receipts, passkeys, OAuth grants and other integrations remain intact.

Calendar and addressbook review panels select one account explicitly. Calendar audience uncertainty and reported permission denial retain their existing meaning. A calendar capability does not authorize a particular event action. A contact account capability also requires separately selected addressbooks; contacts remain read-only.

## MCP routing and authorization

`connection_status` returns safe integration IDs, labels, protocol/profile, capabilities and connection state. It omits login, sender, password and revision. Provider operations accept an optional `account_id`. When exactly one integration of that type exists, omission preserves older clients' selection behavior. When several exist, omission fails with `account_selection_required`; the caller must select an ID from status. Unknown IDs and wrong protocol types fail before provider access.

Every request must satisfy the OAuth scope, the selected account capability and any calendar/addressbook consent. Global OAuth grants do not implicitly authorize newly added integrations. A single immutable credential/revision context selects the transport profile and SMTP sender for the whole operation. Opaque folder/calendar/resource IDs and contact references bind the selected revision. Send/calendar previews additionally bind the stable account ID; switching accounts cannot commit a preview. Idempotency receipts retain their existing global action/key namespace, with account/revision in the payload binding.

## Private storage and offline migration

The new `accounts.json` catalog uses version 3, a generation token and complete account records. It is bounded to 64 KiB, owned by the runtime UID, mode 0600, regular and single-link, in a mode-0700 directory. Reads reject symlinks, wrong ownership/modes, malformed/duplicate JSON keys and oversized files. Changes publish complete files atomically, fsync the file/directory and compare the catalog generation. The runtime is single-process; the operator must not run concurrent writers or an online migration against the same volume.

Without a catalog, the existing version-2 `mail.json`, `caldav.json` and `carddav.json` remain compatible for provider operations and existing grants. The management page displays them but requires an explicit operator import before add/edit/retest/remove. Import copies each existing integration into the catalog with its effective revision, the corresponding trusted profile and its prior protocol capabilities. It adds no global OAuth scope or collection consent. Passkeys, grants, consent revisions/generations and irreversible-operation receipts stay in the untouched identity database. Legacy files remain byte-for-byte unchanged.

Prepare and review a consistent encrypted backup first. Stop only this project's MCP process through the operator's maintenance procedure. In an offline Linux environment running as UID 1000, with the provider volume mounted privately and the exact existing profile file read-only, the prepared command is:

```sh
python -m scripts.migrate_accounts --accounts-directory /run/secrets --profiles /run/config/providers.json --offline-confirmed
```

The command requires absolute paths, never opens the identity database, contacts a provider or prints credentials. A repeated successful import reports the existing catalog without duplicating accounts. A failure leaves either no catalog or a complete published catalog; inspect sanitized status before retrying. A profile mismatch blocks import until the operator resolves it through the established credential reentry process.

Old previews/contact references lack the new stable account binding and cannot be used after import, even though consent revisions are preserved. Prepare/search again. The import does not restore or reset receipt/token history. After adding multiple accounts, an old binary cannot route them and must not be used as a rollback; use a reviewed forward repair. Never restore an old identity database after uncertain provider actions. No migration, deployment or service restart is automatic.
