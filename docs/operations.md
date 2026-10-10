# Operations

The default Compose project manages only its own `mcp` and `proxy` services and two named volumes. It does not alter other Compose projects, Docker daemon settings, host routing, firewall, kernel settings or system services. Use its exact project directory for every operator command. Avoid `docker system prune`, volume deletion and host-wide restarts as recovery methods.

## Restart and health

Both long-running containers use `restart: unless-stopped`. They recover after a Docker daemon restart if Docker itself starts on boot and the operator has not stopped them. The application is single-process; this deployment does not offer high availability. The named volumes and ignored TLS/config files (including runtime/providers.json) must survive host reboot.

The proxy re-resolves the backend through Docker DNS, with a ten-second cache and shared upstream zone. This avoids retaining an obsolete container IP after the backend is recreated. Request failure during restart remains possible. Verify the public HTTPS certificate normally, OAuth discovery and a rejected unauthenticated `/mcp` request after maintenance; provider reads and writes are separate explicit checks, never startup health probes.

Restart only these services when needed:

```sh
docker compose up -d mcp proxy
```

The container memory limits are 256 MiB for the backend and 64 MiB for the proxy. The backend also uses a 256 MiB virtual-address limit, four admitted HTTP requests, bounded worker counts and upstream/resource size limits. These are workload caps, not a promise of host-wide RAM use; Docker, page cache, TLS and the operating system need additional memory. Capacity errors intentionally fail closed.

Verify that your host's Docker/cgroup configuration actually supports the requested container limits. A warning that memory-limit capabilities are unsupported and the limitation was discarded means that Docker's RAM cap is **not enforced**. The application address-space limit still applies, but it is not a substitute for a working host-wide container memory boundary. Resolve host support through your administrator process; this project does not change kernel or daemon settings automatically.

## Certificates

The release deliberately does not enable a renewal timer. Choose an external certificate manager for the domain and configure renewal as an explicit operator task. Do not place DNS API credentials, ACME account keys or certificates in this repository or the MCP provider volume.

A safe renewal design must validate the full chain and hostname with ordinary TLS checks, confirm the certificate/private-key match without logging key bytes, verify non-expiry and expected paths, replace files atomically and reload/recreate **only this proxy** after success. A failed renewal must leave the last good files in place. A reload alone may retain old bind mounts if the external manager replaced the whole directory; verify the actual served certificate after rotation. Use a staging ACME test before unattended production renewal.

Privilege depends on the chosen certificate manager and host. Installing a system timer, changing Docker boot configuration, accessing privileged certificate directories or granting Docker control requires explicit administrator approval. A user timer requires a persistent user manager/linger configuration or another supported startup arrangement. No root installer or renewal automation is activated by this release.

## Backups

The identity database and provider volume contain sensitive state. Keep backups encrypted, outside the repository, with restricted access. An identity backup may contain passkey public credential identifiers, hashed token state, authorization records and prepared operation metadata; provider backups contain actual app passwords. Never attach either to issues or CI artifacts.

For a simple consistent backup, deliberately stop only `mcp`, snapshot both named volumes through a trusted local backup tool, then start `mcp` again. Do not copy a live SQLite file while ignoring its WAL. Keep the exact configured origin with the backup. Do not restore an old database automatically after uncertain sends or calendar commits: stale operation/token state can defeat replay protection. Prefer recovery and fresh grants after an incident; revoke provider credentials separately when appropriate.

Storage initialization refuses a root-owned nonempty or unexpected directory. It never recursively rewrites existing data permissions. Restore ownership/mode deliberately in a maintenance window using the operator's backup process: UID/GID 1000, directory 0700, account files 0600. Do not bypass application checks for a filesystem that cannot enforce them. Named volumes provide Linux permissions under Docker Desktop; host bind directories may not.

## Updates and origin changes

Review the source diff, dependency pins, license inventory and synthetic CI before rebuilding. Back up sensitive state through the process above, then recreate only these containers. Keep the old local image available for rollback; do not roll back database state blindly. The source release does not automatically pull, deploy or migrate your installation.

An identity store is bound to its initial origin. Changing the configured origin/RP ID fails closed. Use a deliberately new deployment, new enrollment and fresh client grants for a domain change; do not edit the stored origin to preserve old credentials silently.

Provider profiles load at startup from the read-only operator file. Recreate only mcp after a reviewed profile change and personally reenter affected credentials. Changes to endpoint fingerprints invalidate old account IDs, calendar previews and contact references; review affected capabilities again. There is no automatic migration of legacy preset-named credential files.
