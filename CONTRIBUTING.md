# Contributing

Keep changes small and provider behavior explicit. Run the backend, frontend, release scan and deployment checks documented in the README. Use synthetic messages/events/contacts and disposable storage only. Never add a test that reads a contributor's live account or automatically sends mail/creates an event.

Do not weaken host, TLS, Origin/CSRF, scope, recent-owner, calendar-audience, ETag or replay checks to make a provider pass. Missing metadata must remain an honest uncertainty or rejection. New protocols need separate human authorization and scope design.

Dependency updates must preserve complete pins and hashes, both supported architecture wheels, original notices and the license inventory. CI uses read-only permissions, a pinned checkout action, no persisted credentials and no deployment step. Do not change it to `pull_request_target` for untrusted source.

Before submitting, inspect every tracked file and the proposed diff for secrets and personal infrastructure details. `.gitignore` is an accident guard, not proof that a release is clean. Explain concrete resulting behavior and relevant validation in the pull request. MIT covers your own contributed source; retain third-party notices.
