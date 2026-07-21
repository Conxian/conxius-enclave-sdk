# Public Operations Runbook

> **Status:** Beta / conditional public guidance for SDK-local operations. This runbook is not a production-support approval and does not publish private deployment procedures.

This runbook gives public-safe response boundaries for the opt-in telemetry surface and related release operations. It is intentionally actionable without exposing private endpoints, credentials, privileged identifiers, custody procedures, key-recovery details, raw attestation material, or incident secrets.

## Scope and status

- The SDK telemetry path is opt-in, coarse, asynchronous, bounded, and best effort.
- `RailProxy` has no telemetry client unless an integrator explicitly attaches one. `TelemetryClient::disabled()` is the explicit no-send mode.
- Telemetry is not an authorization, attestation, signing, replay, settlement, or policy control.
- The repository contains SDK-local implementation and test evidence only. Service-side retention, alerting, deployment ownership, on-call assignment, independent review, rollback drills, and exact release artifacts remain separate gates.
- Value-bearing operations must remain unavailable when their independent security evidence or configuration is missing. Never use simulated or software signing as a fallback for value-bearing paths.

## Roles and responsibilities

| Role | Responsibility | Escalates when |
| --- | --- | --- |
| SDK Maintainer | Owns SDK behavior, payload minimization, status semantics, tests, and documentation. | A code, schema, redaction, endpoint-validation, or failure-isolation change is needed. |
| Telemetry Service Owner | Owns the private service endpoint, credential handling, service retention/access/deletion policy, and aggregate service monitoring. | Service errors, unexpected data, retention uncertainty, or credential exposure is suspected. |
| Operations/Deployment Owner | Owns deployment configuration, telemetry enablement/disablement, alert routing, and execution of an approved rollback. | A deployment must be disabled, isolated, or reverted. |
| Release Owner | Owns exact candidate identity, release hold, release evidence, and promotion/rollback coordination. | Candidate identity, artifact, provenance, or release evidence does not match. |
| Security Reviewer | Owns privacy/security review of sensitive-data handling and security-boundary impact. | Any unexpected payload/header, secret exposure, attestation exposure, or security-control change is suspected. |
| Incident Commander | Coordinates severity, containment, decisions, communications, and closure for a material incident. | Multiple teams or a value-bearing security boundary is affected. |
| Evidence Custodian | Captures and protects the public-safe evidence bundle and records role decisions. | Evidence is incomplete, sensitive, or not attributable to the exact artifact. |

These are role assignments, not unverifiable individual names. The deployment record must assign people or teams privately before enablement; the public repository does not claim that assignment exists.

## Monitoring signals and trigger classes

The expected monitoring view is aggregate and public-safe. The SDK exposes `TelemetryDeliveryStatus`, `TelemetryFailureKind`, `failure_count`, `retries_exhausted`, and an optional HTTP status code; it does not expose payloads or credentials.

| Signal or condition | Trigger class | Immediate action | Primary roles |
| --- | --- | --- | --- |
| Unexpected payload field, header, endpoint value, or sensitive category | Privacy / security | Disable telemetry, preserve sanitized evidence, and open a private incident. | Telemetry Service Owner, Security Reviewer, Incident Commander |
| Rising `Failed` status, retry exhaustion, timeout, or network failure | Availability | Confirm independent security paths remain healthy; investigate service/deployment health without capturing request data. | Telemetry Service Owner, Operations/Deployment Owner, SDK Maintainer |
| Non-retryable HTTP failure or repeated status-class change | Service/configuration | Hold enablement changes and validate the private service contract. | Telemetry Service Owner, Operations/Deployment Owner |
| `NoRuntime`, invalid configuration, or unexpected `Disabled` state | Runtime/configuration | Keep telemetry disabled, correct deployment/configuration, and do not treat telemetry recovery as a security approval. | SDK Maintainer, Operations/Deployment Owner |
| Candidate tag, commit, checksum, provenance, or evidence mismatch | Release integrity | Place the candidate on hold; use the release recovery runbook. | Release Owner, Evidence Custodian, Security Reviewer |
| Any effect on attestation, signing, replay, settlement, or policy checks | Security boundary | Stop the affected value-bearing path and escalate immediately. Do not substitute telemetry or software signing. | Incident Commander, Security Reviewer, SDK Maintainer |

## Sensitive-exposure response

If unexpected telemetry content or secret egress is suspected:

1. **Contain:** The Operations/Deployment Owner disables telemetry by removing the client attachment or using `TelemetryClient::disabled()`. Stop public sharing of the suspected material.
2. **Protect the security boundary:** Keep attestation, signing, replay, settlement, and policy checks independent. Do not resume a blocked value-bearing path because telemetry is unavailable, and never fall back to simulated or software signing.
3. **Preserve safe evidence:** Record the exact public artifact reference, coarse time window, aggregate status/failure categories, sanitized CI or validator links, and the roles involved. Do not copy payloads, headers, credentials, private endpoints, raw attestations, or recovery material.
4. **Escalate privately:** Notify the Telemetry Service Owner, Security Reviewer, and Incident Commander through the organization’s private incident process. Credential rotation, access review, and service containment follow private procedures that are intentionally not reproduced here.
5. **Hold affected releases:** The Release Owner and Security Reviewer decide whether the candidate remains held, is rolled back, or requires a new review. The Evidence Custodian records the decision and its exact artifact scope.

## Telemetry disablement

Use one of these supported boundaries:

- Do not attach a telemetry client to `RailProxy`.
- Replace the enabled client with `TelemetryClient::disabled()` when a stable object is required.
- Use `TelemetryClient::try_new` or `try_new_with_policy` and treat a configuration error as disabled; the compatibility constructor also fails closed.

After disablement, verify the deployment state through its private configuration and aggregate monitoring. The SDK has no durable queue or shutdown flush guarantee, so an in-flight event may be lost; do not attempt to flush or export private data during containment. Signer and settlement decisions must continue to use only their independent security controls.

## Incident escalation

Use the following public-safe escalation classes:

- **Privacy or security exposure:** immediate private escalation to the Security Reviewer and Incident Commander; include the Telemetry Service Owner when service handling may be involved.
- **Service availability or TLS/configuration failure:** escalate to the Telemetry Service Owner and Operations/Deployment Owner; involve the SDK Maintainer for SDK behavior changes.
- **Release or artifact mismatch:** escalate to the Release Owner and Evidence Custodian; keep the candidate on hold until exact evidence is reconciled.
- **Value-bearing security boundary impact:** stop the affected path and escalate to the Incident Commander, Security Reviewer, SDK Maintainer, and Release Owner. No software-only or simulated signing fallback is permitted.

Public communication must contain only a sanitized status, affected public artifact scope, and remediation state. Vulnerability details, credentials, private endpoint values, privileged identifiers, custody/recovery procedures, raw attestation material, and incident secrets belong only in the private incident process.

## Rollback to an exact previously verified artifact

Rollback is allowed only to an exact previously verified artifact. Before switching, record and independently verify:

- the target tag or immutable release identity;
- the full source commit and package version;
- the artifact checksum/digest and target/runtime scope;
- the retained CI, provenance, SBOM, independent-review, and support-decision references; and
- the rollback decision, owner role, and reason.

Do not roll back to a moving branch, an unverified rebuild, or an artifact selected only by “latest.” If the exact prior artifact or its evidence bundle cannot be verified, keep the affected deployment held and escalate to the Release Owner and Incident Commander. See [RELEASE_RECOVERY_RUNBOOK.md](./RELEASE_RECOVERY_RUNBOOK.md) for the release-specific evidence boundary.

## Evidence capture

### Public-safe evidence

- exact public tag, full commit, package version, or artifact digest;
- public CI, validator, test, SBOM, or provenance links;
- aggregate telemetry status/failure counts and HTTP status classes;
- coarse time window and deployment scope without private identifiers;
- enablement/disablement state, role decision, release hold, or rollback outcome; and
- sanitized incident and closure summaries.

### Never capture in public records

Payloads, headers, API credentials, private endpoints, cookies or tokens, private keys or shares, raw signatures or signature-derived identifiers, raw attestations or certificates, addresses or transaction/request data, privileged identifiers, custody or key-recovery procedures, and incident secrets.

## Closure criteria

An incident or operational change is closed only when:

- telemetry is disabled, corrected, or re-enabled under an explicit reviewed decision;
- the Security Reviewer confirms that no public-safe record contains forbidden values;
- independent security and value-bearing controls remain enforced;
- the exact artifact and deployment scope are recorded;
- the Telemetry Service Owner confirms service-side access, retention, and deletion handling privately when relevant;
- the Evidence Custodian has stored the sanitized evidence bundle; and
- the Incident Commander or responsible role records the closure decision and any follow-up owner.

Documentation completion alone does not satisfy these criteria or establish production support.

## Review triggers

Review this runbook before each release and after any change to the payload schema, event set, endpoint or authentication behavior, timeout/retry policy, deployment scope, service retention/access/deletion policy, alerting, on-call assignment, security boundary, rollback target, independent review, or incident outcome.
