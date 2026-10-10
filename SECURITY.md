# Security policy

This is an experimental single-owner project. Keep the backend private, use the supplied sanitizing TLS proxy, keep exact-origin checks enabled, and use your own passkey and provider credentials. Custom endpoints may be entered through the recent-passkey owner account form or the validated operator file. The owner form requires exact-origin/CSRF checks, a strict endpoint schema and a successful connection proof bound to the complete configuration before storage. MCP requests cannot supply endpoints. Manual DAV authorizes exactly the URL's DNS host; operator allowlists require review because every allowed host may receive credentials.

Every transport still rejects private/special or mixed DNS answers, connects to a checked numeric IP, verifies the peer and uses certificate verification with the original hostname. Manual configuration cannot disable TLS, select a proxy or custom trust store, or reach LAN/localhost services. Endpoint edits require credential reentry and a new check; saved edits rotate the account revision and invalidate previews. Host/Docker administrators can access stored data.

Report suspected vulnerabilities through this repository's **private vulnerability reporting** if available. If no private reporting channel is enabled, open a content-free issue asking the maintainer to arrange one. Do not post exploit details, credentials, raw mail/events/contacts, identity databases, OAuth tokens, passkey identifiers, filled forms, TLS/SSH private keys or network captures in a public issue.

Include a minimal synthetic reproduction, affected version, expected/actual behavior and sanitized failure category. Do not run a reproduction against another person's instance. Security fixes require synthetic tests and review of authorization, TLS, resource bounds and replay protection. There is no support commitment or promised response time yet.

If your instance is compromised, isolate it using your own operator process, revoke provider app passwords at their providers, revoke OAuth grants, and recover/enroll fresh owner credentials. Do not blindly retry uncertain external writes or restore old authorization/operation state.
