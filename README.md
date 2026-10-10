# Self-hosted Mail, Calendar and Contacts MCP

A small, single-owner MCP bridge using IMAP, SMTP, CalDAV and CardDAV. Run it on infrastructure you control and enroll your own passkey. Manage multiple independent mail, calendar and contact accounts through an owner-only account overview and a three-step setup wizard. Provider credentials stay in private local Docker volumes. GMX and iCloud are presets; an operator can configure additional protocol profiles in a validated local file.

**Status: experimental source release.** Custom profiles are tested against synthetic TLS servers, without a claim of universal or live-provider compatibility. This is not an audited hosted service. The bundled OAuth client policy currently accepts ChatGPT's verified client metadata and exact callback URLs only. Other MCP clients are not supported yet. The account UI uses German labels; project documentation is in English.

## Protocol and provider support

| Protocol | Implemented protocol code | Supported provider preset | Available through MCP | Validation |
| --- | --- | --- | --- | --- |
| IMAP over TLS | Generic bounded IMAP transport and folder capabilities | GMX, or operator-configured DNS host on 993 | Search/read, folders, read/star flags, move and trash | Offline TLS server and security fixtures |
| SMTP with required TLS | Generic MIME preparation and SMTP submission | GMX, or operator-configured DNS host on 465 or mandatory STARTTLS on 587 | Preview, then explicitly confirmed send | Offline implicit TLS/STARTTLS fixtures; no plaintext fallback |
| CalDAV over HTTPS | Generic discovery/query, metadata and conditional simple-event operations | iCloud, or explicit operator HTTPS origin/host allowlist | List/read; preview and confirmed create/update/delete in owner-enabled calendars | Offline TLS discovery/read/create/commit and audience/privilege fixtures |
| CardDAV over HTTPS | Generic discovery/query/multiget and minimal vCard parsing | iCloud, or separate operator HTTPS origin/host allowlist | Addressbooks, search and reference-based reading, with separate consent | Offline TLS and MCP/consent fixtures; no live contact access verified |

Custom adapters use the same account storage, TLS transports, MCP tools and permission checks as presets. Endpoints come only from [the operator provider file](docs/providers.md); browser/MCP inputs cannot supply server URLs. Every DNS answer must contain only public IPs; connections pin the checked IP while TLS verifies the original hostname. Private-network servers and unsupported ports are rejected. App-password/basic authentication is supported where the provider permits it; Gmail/Microsoft provider OAuth is not implemented. Existing mail/calendar grants do not include contacts. Contact writes and notes are outside this release.

## Security model

- One exact canonical HTTPS origin and WebAuthn RP ID; invalid or missing configuration stops startup.
- Owner enrollment requires an interactive server-side approval of the exact fingerprint shown in the owner's browser. There is no default password or HTTP reset endpoint.
- Provider credentials are never OAuth tokens. OAuth access lasts 15 minutes; optional refresh uses bounded rotating token families with reuse detection and revocation.
- OAuth scopes separate mail/calendar reads, contact reads, mail changes, sending and calendar changes. Contacts are excluded from default scopes and require per-addressbook owner consent. Write tools require explicit confirmation; send/calendar changes require a fresh preview and idempotency key.
- New accounts start with no MCP capabilities. Account capabilities, OAuth scopes and collection consent must all permit an operation. Account IDs route every request; multiple accounts of the same type require an explicit selection. Editing or removing one account invalidates only its consents, previews and contact references. Global operation receipts remain intact.
- Calendar writes start disabled. The owner must select each calendar in a recent passkey session. If the provider cannot establish its audience, the UI requires acknowledgement that members may see changes or receive notifications. Enabling a calendar grants technical capability; each actual action still needs a separate instruction.
- TLS verification remains enabled for all providers and client metadata. Redirects cannot carry credentials outside the matching explicit protocol host/port policy. Stored credentials bind the operator profile; endpoint changes require reentry and invalidate previous IDs/previews.
- Backend HTTP is private to the dedicated Compose network. Only the sanitizing TLS proxy is published. Request bodies, resource sizes, concurrency and address space are bounded; access logging is disabled.

Read [SECURITY.md](SECURITY.md) and [limitations](docs/limitations.md) before putting this service online. A host administrator or Docker administrator can read its stored credentials; storage permissions do not protect against a compromised host.

## Start on your own server

Use Docker Engine with Compose v2 on Linux AMD64 or ARM64, or Docker Desktop's Linux containers. Native Windows/macOS Python and 32-bit ARM are not supported by this lock. The included configuration does not install Docker, change a firewall, configure DNS, request a certificate or schedule renewal.

1. Clone this repository into a **new** directory. Copy `.env.example` to `.env` and set `MCP_PUBLIC_ORIGIN` to your exact HTTPS origin. Use a domain you control. Keep the default loopback bind until you intentionally configure public reachability. The public port must match the client-facing URL; the internal TLS listener is always 8443. Create ignored `runtime/` and copy `providers.example.json` to `runtime/providers.json`; keep presets or use [the exact custom schema](docs/providers.md). The file contains no credentials, is mounted read-only, and must be owned by root or UID 1000, readable by UID 1000 and not group/world-writable. Compose refuses to create a missing config path.
2. Obtain a trusted certificate covering that hostname through your own certificate manager. Put `fullchain.pem` and `privkey.pem` in the ignored `runtime/tls/` directory. On Linux, UID 1000 inside the proxy must be able to traverse the directory and read both files; use restricted ownership and mode, such as UID 1000 and directory 0700/files 0600. Never commit these files. Docker Desktop permissions differ; verify readability inside its Linux VM.
3. Build and initialize **only the new named volumes**:

   ```sh
   docker compose build
   docker compose --profile setup run --rm init-storage
   ```

4. Render the fixed proxy configuration. The following uses only public configuration, an isolated container and the repository's template:

   ```sh
   mkdir -p runtime
   docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --env-file .env --user "$(id -u):$(id -g)" --volume "$PWD:/workspace" --workdir /workspace --entrypoint python selfhosted-mail-calendar-mcp:local -m scripts.render_proxy
   docker compose run --rm --no-deps proxy -t -c /etc/nginx/nginx.conf
   docker compose up -d mcp proxy
   ```

   The shell commands above are for Linux. The renderer writes mode 0600 as the host caller. If that caller is not UID 1000, explicitly assign the generated `runtime/nginx.conf` to UID/GID 1000 using your administrator process before starting the proxy; do the same for TLS files and permit directory traversal. On Docker Desktop, render with a Linux-container command suited to your terminal and check file readability. This render container has no provider/identity mounts. The proxy does not start if configuration or certificate files are missing or unreadable.
5. Open `https://YOUR-HOST/login` yourself, start enrollment and compare its fingerprint. Approve exactly that request in your own interactive server terminal:

   ```sh
   docker compose exec mcp python -m mcp_bridge.admin bootstrap
   ```

   Register the passkey yourself in the browser within five minutes. Do not paste passkey identifiers or the filled account form into an issue or support chat.
6. Sign in and open `/accounts`. Select **Konto hinzufügen**, choose the protocol and operator-provided profile, enter credentials yourself, then test and explicitly confirm storage. Mail also needs its sender email address. Select account capabilities deliberately; each new account starts with none. Calendar/contact accounts have independent revisions and collection consent, even when both use iCloud. Checks are explicit owner actions; failures return sanitized categories. See [account management and migration](docs/accounts.md). Keep credentials out of `.env`, provider config, command lines, images and GitHub secrets.
7. Connect the HTTPS `/mcp` endpoint using a supported ChatGPT MCP connection, sign in with your passkey and approve the requested scopes. Reconnect for new scopes; do not widen an existing read grant silently. See [owner authorization](docs/authorization.md).

For direct public exposure, deliberately choose an appropriate `MCP_BIND_ADDRESS`, external port/routing and certificate renewal solution. Ensure external TLS reaches this proxy and preserves the exact client-facing host. The backend must stay unexposed. Deployment is your explicit operator action; CI never deploys or contacts a real provider.

## Tests

```sh
docker build --target tests -t mcp-synthetic-tests .
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 32 --memory 256m --tmpfs /tmp:size=32m,mode=1777 --env MCP_PUBLIC_ORIGIN=https://mcp.example.test mcp-synthetic-tests
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 32 --memory 256m --tmpfs /tmp:size=8m,mode=1777 --tmpfs /run/identity:size=8m,mode=700,uid=1000,gid=1000 --tmpfs /run/secrets:size=1m,mode=700,uid=1000,gid=1000 --env MCP_PUBLIC_ORIGIN=https://mcp.example.test --entrypoint python mcp-synthetic-tests -m scripts.test_runtime
node scripts/test_frontend.cjs
node scripts/scan_release.cjs
python3 -m scripts.test_deployment
```

Run Python commands from the repository root using `python -m`; the image uses `/app`. Tests use synthetic data and disposable storage, never production mounts or provider accounts. Generic protocol tests create local ephemeral TLS servers inside a network-disabled container; test-only injection routes logical names to them. Separate DNS/socket tests verify production IP pinning, private/mixed IP rejection and original SNI. There is no runtime bypass. Deployment tests create an ephemeral TLS fixture; they do not obtain a certificate or create an SSH key. CI also probes fresh runtime startup, builds pinned dependencies and runs the same backend suite on AMD64 and ARM64. The installer bounds address space to 384 MiB and CPU time to five minutes; build-engine overhead is additional. Passing CI is not a penetration test or proof of every live provider's behavior.

For portable development checks, run `python -m unittest -q mcp_bridge.tests.test_multi_accounts mcp_bridge.tests.test_multi_protocols mcp_bridge.tests.test_provider_network.NetworkTests` with the synthetic origin above. These use in-memory account files and disposable SQLite/local TLS fixtures. The actual Linux UID/mode/atomic-file checks are explicitly skipped on Windows; passing portable checks does not replace the full Linux suite or runtime/deployment checks.

## Operations and development

See [operations](docs/operations.md) for restart behavior, renewal, backups and recovery; [architecture](docs/architecture.md) for extension boundaries; and [CONTRIBUTING.md](CONTRIBUTING.md) for contribution checks.

The project's own source is licensed under [MIT](LICENSE). Dependency licenses remain separate and are retained in [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt) and [the inventory](docs/dependency-licenses.md). No prebuilt binary image is distributed by this source release. Before redistributing an image, inventory the base system and bundled native components as well. This project is not affiliated with GMX, Apple or OpenAI.
