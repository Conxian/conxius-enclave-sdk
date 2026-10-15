# Corporate identity boundary — 15 October 2026

Scope: documentation reconciliation of SDK #545, aligned with the evidence boundaries proposed in Business #1364. This file configures no identity provider, application, mailbox, signing service or release authority.

Mail delivery, an identity provider, application provisioning, active sessions and API tokens are distinct control surfaces. Corporate administrators may use scoped human roles. Workload identities and SDK signing/key custody remain separately authenticated and authorized. An email-domain match establishes neither hardware provenance nor signing permission.

Per-service acceptance requires the exact identity-provider/application configuration, role/permission scope, provisioning behavior, and measured session/token revocation results. No immediate organization-wide offboarding or guaranteed data isolation is claimed without that evidence. Alerts require reviewed sanitization and access controls and must never contain signing secrets or credentials.

The current `SECURITY.md`, ownership model and SDK boundary contract state these constraints. Earlier proposal commits remain in PR #545 history; unsupported claims are not retained as active policy. Independent review of external tenant controls, provider qualification and production release remains open.
