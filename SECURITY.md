# Security policy

This is an experimental single-owner project. Keep the backend private, use the supplied sanitizing TLS proxy, keep exact-origin checks enabled, and use your own passkey and provider credentials. Custom endpoints belong only in the validated operator file; never add user-controlled endpoint or TLS-bypass fields to HTTP/MCP requests. Review allowed hosts because they can receive credentials. Host/Docker administrators can access stored data.

Report suspected vulnerabilities through this repository's **private vulnerability reporting** if available. If no private reporting channel is enabled, open a content-free issue asking the maintainer to arrange one. Do not post exploit details, credentials, raw mail/events/contacts, identity databases, OAuth tokens, passkey identifiers, filled forms, TLS/SSH private keys or network captures in a public issue.

Include a minimal synthetic reproduction, affected version, expected/actual behavior and sanitized failure category. Do not run a reproduction against another person's instance. Security fixes require synthetic tests and review of authorization, TLS, resource bounds and replay protection. There is no support commitment or promised response time yet.

If your instance is compromised, isolate it using your own operator process, revoke provider app passwords at their providers, revoke OAuth grants, and recover/enroll fresh owner credentials. Do not blindly retry uncertain external writes or restore old authorization/operation state.
