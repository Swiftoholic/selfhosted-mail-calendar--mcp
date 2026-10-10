# Operator-controlled protocol profiles

Copy providers.example.json to ignored runtime/providers.json. Compose mounts it read-only at fixed /run/config/providers.json and refuses missing paths. Direct application execution without this file uses presets; a present invalid file stops startup. Use a regular single-link file owned by root or UID 1000, readable by UID 1000 and not group/world-writable. Credentials, unknown fields, duplicate JSON keys, wildcards, IP literals and unsupported ports/TLS modes are rejected.

The sample selects GMX mail and independent iCloud calendar/contact profiles. Both iCloud accounts need their own owner-entered credentials and permissions. Preset shard policies are deliberately encoded in trusted code; custom profiles have exact DNS allowlists.

Example custom config (replace fixture DNS names with your provider's documented public endpoints):

```json
{
  "version": 1,
  "mail": {
    "preset": "custom",
    "imap": {"host": "imap.example.test", "port": 993, "tls": "implicit"},
    "smtp": {"host": "smtp.example.test", "port": 587, "tls": "starttls_required"}
  },
  "caldav": {
    "preset": "custom",
    "origin": "https://calendar.example.test/dav/",
    "allowed_hosts": ["calendar.example.test"]
  },
  "carddav": {
    "preset": "custom",
    "origin": "https://contacts.example.test/dav/",
    "allowed_hosts": ["contacts.example.test"]
  }
}
```

SMTP 465 uses implicit TLS; 587 requires starttls_required, with no plaintext AUTH fallback. IMAP supports implicit TLS 993 only. DAV needs HTTPS, an absolute path, no URL credentials/query/fragment and port 443 or 8443. All hosts in a profile share its one port. Discovery, principals, homes, resources and read redirects use the same allowlist. Calendar mutations never follow redirects. Every allowed host can receive credentials: add only documented discovery shards. Calendar/contact lists remain independent.

Every connection resolves once, rejects mixed/private/special IP answers, connects numerically to a checked public IP, checks its peer and verifies the original TLS hostname. New connections revalidate DNS. There is no runtime bypass or arbitrary endpoint field in browser/MCP requests.

Profiles load at startup. After editing this file, recreate only this project's mcp service, review displayed hosts and personally reenter each changed account's credentials. Old profile credentials cannot be forwarded to new hosts; effective revisions change and old IDs/previews/references become invalid. Reselect affected calendar/contact capabilities; reconnect MCP for new scopes. No other services/passwords/grants are changed automatically.

Custom providers remain experimental and unverified live. Use app passwords or provider-approved basic credentials. Account checks authenticate mail protocols or read DAV discovery metadata without sending mail, reading contact bodies or writing events. They do not prove every folder, event, sharing property or vCard behavior. OAuth-only providers need a future explicit integration. Live tests remain separate owner actions.
