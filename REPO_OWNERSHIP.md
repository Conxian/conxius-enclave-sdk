# Repo ownership

## Purpose

`conxius-enclave-sdk` is the secure signer and device trust layer for the Conxian builder platform.

## This repo owns

- enclave-backed signing abstractions
- secure execution and hardware trust integrations
- signer policy enforcement where tied to secure execution
- device trust and attestation support where relevant

## This repo does not own

- network adapters
- application orchestration
- wallet UX
- general platform runtime concerns

## Boundary rule

If the concern is about secure signing, device trust, or controlled key use, it belongs here. If it is about layer-specific broadcast, observation, or application behavior, it belongs elsewhere.

## Operational role model

The repository uses named roles rather than unverifiable individual names. Role assignment for a deployment is private operational evidence and is not implied by this table.

| Role | Responsibility boundary |
| --- | --- |
| **SDK Maintainer** | Owns SDK-local code, tests, telemetry payload/status semantics, public documentation, and fail-closed security boundaries. |
| **Telemetry Service Owner** | Owns the private telemetry service endpoint, credential handling, service-side retention/access/deletion policy, aggregate monitoring, and service evidence. |
| **Operations/Deployment Owner** | Owns deployment configuration, enablement/disablement, alert routing, on-call coordination, and execution of an approved rollback. |
| **Release Owner** | Owns exact candidate identity, release holds, publication/recovery decisions, and artifact evidence for the release scope. |
| **Security Reviewer** | Owns privacy/security review, independent-review scope, sensitive-exposure assessment, and security-boundary decisions. |
| **Incident Commander** | Coordinates material incident containment, escalation, communications, rollback decisions, and closure. |
| **Evidence Custodian** | Maintains the exact public-safe evidence bundle, artifact references, role decisions, and private/public evidence separation. |

## Escalation boundaries

- SDK behavior, serialization, redaction, endpoint validation, or failure-isolation changes escalate to the **SDK Maintainer**.
- Endpoint, credential, service retention/access/deletion, dashboard, or service failure concerns escalate to the **Telemetry Service Owner** and **Operations/Deployment Owner**.
- Candidate identity, provenance, checksum, publication, or rollback mismatches escalate to the **Release Owner** and **Evidence Custodian**.
- Unexpected sensitive data, raw attestation/signature material, or a possible security-control bypass escalates immediately to the **Security Reviewer** and **Incident Commander**.
- No role may authorize, relax, or replace attestation, signing, replay, settlement, policy, or exact-artifact checks. A missing value-bearing security gate must remain unavailable; simulated or software signing is never an operational fallback.

## Strategic role

Primary strategic repo.
