# Release Recovery Runbook

> **Status:** Beta / conditional public guidance. This runbook defines evidence and decision boundaries; it does not authorize publication, production support, or value-bearing operation.

Use [RELEASING.md](../../RELEASING.md) for release mechanics. This document intentionally does not duplicate credentials, private endpoint values, privileged commands, custody procedures, key-recovery details, or incident secrets.

## Conditional release wording

Use this wording until every required gate is evidenced for the exact candidate and deployment scope:

> **This candidate remains Beta / conditional. Publication, passing repository checks, or the presence of telemetry and operations documentation does not establish production support. Telemetry remains unsupported until service-side privacy/retention, monitoring, named operational assignment, independent review, rollback evidence, and exact release artifacts are verified.**

Do not describe a documentation-only or simulated/software path as production-supported. Never use simulated or software signing as a fallback for value-bearing operations.

## Exact candidate identity and evidence bundle

Release evidence must identify one immutable candidate. Branch names, moving references, package metadata alone, and “latest” labels are insufficient.

| Required item | Evidence requirement | Public-safe record |
| --- | --- | --- |
| Source identity | Exact tag and full commit for the candidate. | Public tag/commit link or immutable identifier. |
| Package identity | Exact package name/version and target/runtime scope. | Public package/version and supported scope. |
| Artifact identity | Exact artifact checksum/digest and retained artifact reference. | Checksum/digest and public artifact link where available. |
| Build and test evidence | Format, lint, tests, locked dependency/toolchain checks, and the exact CI run. | Public workflow/run links and pass/fail summary. |
| Supply-chain evidence | SBOM, provenance/attestation, registry/release match, and release notes for the same candidate. | Public links or sanitized evidence references. |
| Security evidence | Independent review and scope, including any explicit exclusions. | Public review reference and bounded status; raw security material stays private. |
| Operations evidence | Telemetry enablement decision, service retention/access/deletion policy, aggregate monitoring, named on-call assignment, and rollback drill for the deployment scope. | Public-safe status and role ownership; private deployment values stay private. |
| Recovery evidence | Exact previously verified rollback target, decision record, and verification result. | Public tag/commit/checksum and sanitized decision summary. |

The evidence bundle must be internally consistent: every result must refer to the same candidate, target, runtime, hardware boundary, and deployment scope. The repository currently records no artifact evidence for telemetry.

## Release-hold triggers

Place the candidate on hold when any of the following is true:

- the tag, full commit, package version, checksum, or target scope does not match;
- format, lint, test, locked dependency/toolchain, CI, SBOM, provenance, registry, or release evidence is missing or belongs to another candidate;
- independent security/privacy review is missing, stale, or does not cover the candidate;
- service-side retention/access/deletion, aggregate monitoring, named operational assignment, or rollback-drill evidence is missing;
- telemetry payload, header, endpoint, failure, or status behavior differs from the public contract;
- a release, deployment, or incident record contains forbidden sensitive values;
- a publisher or recovery path would rebuild, retag, or publish from changed source; or
- the candidate would require bypassing attestation, signing, replay, settlement, policy, or other security checks.

An unresolved hold means no production-support claim and no value-bearing enablement.

## Failed-publish recovery boundaries

Recovery may retry the same exact validated candidate through the authoritative release path described in [RELEASING.md](../../RELEASING.md), but it must not:

- rebuild from a changed worktree or moving branch;
- retag a different commit under the same release identity;
- publish a package whose checksum or provenance differs from the validated evidence;
- bypass validation, security, provenance, environment-approval, or artifact checks; or
- copy credentials, private endpoint values, privileged identifiers, or recovery secrets into this public runbook.

If the exact candidate or its retained evidence cannot be recovered, keep publication held and escalate to the Release Owner, Evidence Custodian, Security Reviewer, and Incident Commander as appropriate. A new candidate requires a new identity and a new evidence bundle.

## Rollback decision and evidence

Rollback requires a decision based on impact, exact artifact identity, and security scope. The Release Owner coordinates the decision with the Incident Commander and Security Reviewer when a release or security boundary is affected. The Operations/Deployment Owner executes only the approved switch.

Before rollback, verify the target’s tag, full commit, package version, checksum/digest, target/runtime scope, retained CI/provenance/SBOM evidence, and prior support decision. Record the failed candidate, the target artifact, decision reason, role approvals, time window, and post-switch verification. Never select a target by branch head, timestamp alone, or “latest.”

If no exact previously verified artifact is available, keep the deployment held. Do not substitute a software-only, simulated, placeholder, or unreviewed build for a value-bearing path.

## Post-release verification

After publication or recovery, the Release Owner and Evidence Custodian verify:

1. The public tag, full commit, package version, artifact checksum/digest, and registry/release identity match.
2. The retained CI, SBOM, provenance, and independent-review references correspond to that exact candidate.
3. The deployment scope, telemetry enablement state, endpoint/TLS policy, service retention/access/deletion decision, monitoring, on-call assignment, and rollback target match the reviewed decision.
4. Aggregate telemetry signals remain within the reviewed contract; no payload or header capture is used for verification.
5. Any mismatch triggers a release hold or rollback and is recorded as evidence, not silently corrected in place.

## Public-safe versus private evidence

| Public-safe evidence | Private-only evidence |
| --- | --- |
| Tags, full commits, package versions, checksums/digests, public CI/SBOM/provenance links, sanitized review scope, aggregate status classes, role decisions, release holds, rollback outcomes, and closure summaries. | Credentials, private endpoints, auth headers, privileged identifiers, custody or key-recovery procedures, raw attestation/certificate material, raw payloads or signatures, incident secrets, and private access/retention records. |

The public repository may state that private evidence exists or is missing, but must not reproduce its values. Absence of a public value is not evidence that the private control exists.

## Role ownership

| Role | Release-recovery responsibility |
| --- | --- |
| SDK Maintainer | Confirms SDK-local behavior, tests, and public contract changes. |
| Telemetry Service Owner | Confirms private service configuration, retention/access/deletion policy, monitoring, and credential handling. |
| Operations/Deployment Owner | Confirms deployment scope, on-call routing, enablement/disablement, and executes an approved rollback. |
| Release Owner | Owns candidate identity, release holds, publication/recovery decision, and exact artifact verification. |
| Security Reviewer | Reviews privacy, security-boundary, independent-review, and exposure implications. |
| Incident Commander | Coordinates material incident containment, rollback decision, communications, and closure. |
| Evidence Custodian | Maintains the immutable public-safe and private evidence classification, links, and retention record. |

No role may override a missing attestation, signer, replay, settlement, policy, or artifact gate. Role assignment in this table is not proof that a person or on-call rotation has been assigned for a deployment.

## Completion criteria and review triggers

Release recovery is complete only when the exact candidate or rollback target is verified, the hold/rollback decision is recorded, post-release checks pass, public-safe evidence is captured, private evidence remains private, and the responsible roles accept the outcome. The capability remains Beta / conditional until external evidence is independently verified.

Review this runbook before each release and after any change to the release workflow, candidate identity rules, artifact/provenance format, telemetry contract, service retention or monitoring, named operational assignment, rollback target, security review, incident outcome, or support decision.
