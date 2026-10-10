# Architecture and extension boundaries

The server exposes streamable HTTP MCP, OAuth discovery and the owner UI. Identity modules implement one owner, passkeys and scoped grants. Account storage uses a private version-3 catalog of independent integrations, with explicit offline import from the separate version-2 protocol files. Operations intersect global scopes, account capabilities and collection consent, and enforce confirmation, previews, idempotency and account/revision binding. The backend has no published port. See [account management](accounts.md).

bridge.providers defines immutable mail/DAV protocol profiles and transport-factory interfaces. ProviderCatalog loads documented presets and validated operator choices at startup; ProviderProfiles represents the selected operation's profiles. The recent-passkey owner wizard also accepts strictly validated manual endpoints stored in one account's optional server_config. A manual profile never mutates the shared catalog. MCP inputs cannot supply endpoints. Stored accounts include a profile fingerprint. Changing endpoints requires owner credential reentry and an exact new connection proof; a saved edit changes the revision and invalidates old IDs/previews.

multi_accounts pins an immutable credential/revision snapshot, including its actual frozen profile, in a thread-local operation context. Transports obtain their descriptor from that context for every operation. Independent account locks protect edits/removal against active operations; catalog writes serialize under one catalog lock. Mutations acquire account lock, catalog lock, then identity-store lock/transaction. Network I/O holds neither the catalog nor identity lock. The legacy save path uses the same virtual account lock as legacy operations. The runtime has one writer process.

bridge.network implements IMAPS, implicit TLS SMTP, mandatory STARTTLS SMTP and HTTPS. Bounded DNS resolution checks every answer for public addresses and rejects mixed/private/special addresses. Numeric socket.connect pins the validated IP; peer checking precedes TLS/authentication. TLS verifies the original hostname, requires trusted certificates and TLS 1.2 or newer. Every new connection repeats validation. No HTTP proxy, TLS bypass, private-network targets or client-selected URLs are available. DAV requests/redirects additionally match the explicit protocol host/port policy before credentials are sent.

Mail and calendar read/write adapters consume the selected profiles. Mail separates an opaque login from the explicit sender email. SMTP 587 completes STARTTLS and a second EHLO before authentication. CalDAV discovery, audience metadata, resource lookup and conditional writes use the same selected descriptor. Collection boundaries, audience acknowledgement, reported privilege denial, ETags and complex-event rejection remain enforced for custom providers.

## CardDAV reads

bridge.carddav.Contacts implements discovery of up to 25 books, queries of at most 50 results and addressbook-multiget. Bounded vCard 3.0/4.0 parsing returns only name, emails and phones. Notes, photos, binary values and embedded URLs are never fetched. The transport permits PROPFIND/REPORT only; resources must be immediate children of the selected book on the same host/port.

contacts_ops adds owner-selected book consent to contacts_addressbooks, contacts_search and contacts_read. The separately requested contacts:read scope is excluded from defaults. Book consent starts off, requires recent passkey/CSRF verification, and binds account revision and generation. Search requires a nonempty bounded query. At most 100 references cache validated URLs/book IDs/revisions/generations for ten minutes; contact bodies are not cached. Read accepts only a reference learned from search.

Revocation/re-enablement, credential replacement, profile change and recovery invalidate references. Reads recheck book consent after network work and OAuth validity before returning MCP results. There are no contact write methods or scopes.

## Python source and tests

bridge, mcp_bridge and scripts are packages copied to /app. Entry points use python -m package.module from that root. Docker is the deployment format; no PyPI distribution is supplied. Tests inject trusted factories/local dialers, with no runtime bypass exposed by configuration. Offline TLS servers exercise generic adapters, while separate DNS/peer/TLS fixtures cover production connection policy. Custom profiles remain experimental and unverified live.

Adding another MCP OAuth client still requires an exact reviewed metadata/callback/resource policy and substitution/PKCE/replay tests. Only verified ChatGPT clients are currently accepted. Gmail/Microsoft provider OAuth, contact writes and notes need separate integrations and authorization.
