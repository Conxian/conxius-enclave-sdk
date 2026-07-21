# Telemetry Privacy and Delivery Semantics

> **Status:** Beta / conditional 2.x implementation and operations guidance. This document is SDK-local evidence, not production-acceptance evidence.

This document defines the public-safe contract for the SDK telemetry surface. It deliberately does not publish deployment-specific endpoints, privileged identifiers, credentials, retention secrets, custody or recovery procedures, raw attestation material, or incident secrets. Service-side controls must be documented and evidenced separately before telemetry is enabled for a supported deployment.

## Scope and privacy defaults

Telemetry is **opt-in at the SDK integration boundary**. `RailProxy` starts without a telemetry client, and an integrator must explicitly attach one with `with_telemetry`. Telemetry is best effort and must never become a prerequisite for signing, attestation, replay protection, settlement, or rail execution.

The compatibility constructor `TelemetryClient::new` fails closed when configuration is invalid and records a configuration failure without making a request. Integrations that need explicit configuration errors should use `try_new` or `try_new_with_policy`. The deprecated `track_signature` method discards its identifier argument and emits only the coarse event described below; new integrations should call `track_event`.

## Per-surface defaults

| Surface | Default state | Explicit enablement or disablement | SDK-local behavior when delivery fails |
| --- | --- | --- | --- |
| Direct client | No client is created by default. An explicitly constructed client is enabled. | Construct with `TelemetryClient::try_new` or `try_new_with_policy`; invalid configuration is returned to the caller. | Delivery is detached and best effort. The caller receives local scheduling/configuration status, not an authorization result. |
| Rail integration | `RailProxy` has no telemetry client and sends nothing. | Attach an enabled client with `RailProxy::with_telemetry`. The event is scheduled only after the verified operation has passed its independent policy and replay checks. | Telemetry failure is ignored for the verified rail result. Attestation, signing, replay, settlement, and rail checks remain authoritative. |
| Explicit disabled client | Disabled. | Use `TelemetryClient::disabled()` when a stable object is required but no telemetry may be sent. | No request is scheduled, no payload is built, and the local status is `Disabled`. |

## Allowed data contract

### Request payload

The only allowed JSON payload is exactly:

```json
{"schema_version":1,"event":"signed_intent"}
```

No additional fields, optional metadata, request context, or caller-supplied identifiers are part of this public contract.

### Headers, local diagnostics, and operational artifacts

| Surface | Allowed content |
| --- | --- |
| Request headers | `Content-Type: application/json` and, only when configured, the sensitive `X-Api-Key` transport header. The credential is not a payload field and must not be copied into diagnostics. |
| Local diagnostics | `TelemetryDeliveryStatus`, `TelemetryFailureKind`, `failure_count`, `retries_exhausted`, and an optional HTTP status code. These are coarse process-local signals, not event records. |
| Logs and dashboards | Aggregate event counts, delivery status, failure kind, retry exhaustion, HTTP status class/code where needed, and coarse time windows. Do not capture a request body or header dump. |
| Tickets and support artifacts | A public commit/tag or exact reviewed artifact reference, validator/test outcome, aggregate status counts, failure categories, sanitized time window, and links to public CI evidence. |

The SDK does not prescribe a logging or dashboard backend. Any deployment implementation must preserve this minimization boundary. Category names in this policy may be discussed; sensitive values must not be recorded.

### Forbidden data categories

| Surface | Never include |
| --- | --- |
| Payloads | API credentials, private keys, seeds, shares, raw signatures, signature-derived identifiers or hashes, raw attestation reports or certificates, nonces, addresses, recipients, assets, amounts, request or intent data, user identifiers, or business metadata. |
| Headers | URL credentials, cookies, bearer tokens, query/fragment secrets, private endpoint values, or any credential other than the configured sensitive API-key header held by the transport. Never log the API-key value. |
| Logs and dashboards | Raw payloads, full endpoint values, credential material, request/intent identifiers, attestation contents, signature material, custody or recovery data, or incident secrets. |
| Tickets and support artifacts | Payload captures, header captures, private service configuration, privileged identifiers, raw attestation evidence, custody procedures, key-recovery details, credentials, or unreleased incident information. |

## Endpoint, TLS, and delivery policy

Production construction accepts only an HTTPS endpoint with a host. The endpoint may not contain URL credentials, query parameters, or fragments. Deployment-specific endpoint values stay in private configuration and outside public documentation. HTTP endpoints are accepted only by the `cfg(test)` request-capturing transport used to exercise serialization and delivery behavior without contacting a service.

| Policy | Default | SDK maximum or boundary |
| --- | --- | --- |
| Request timeout | 5 seconds | 30 seconds; zero and values above the maximum are rejected |
| Retries | 2 retries, 3 total attempts | 3 retries maximum |
| Initial retry backoff | 50 milliseconds | 1 second maximum accepted initial backoff; delays are exponential from the configured base |
| Retryable HTTP status | `408`, `429`, `500`, `502`, `503`, `504` | Other HTTP failures are recorded without retry |
| Success | Any HTTP `2xx` response | The SDK records `Delivered`; it does not validate service-side processing beyond the response class |

`track_event` schedules delivery and returns without waiting for the network. Native scheduling without an active Tokio runtime is rejected as an observable `NoRuntime` failure and does not panic. Transport and timeout failures are bounded by the configured policy.

## Duplicate, loss, shutdown, and aggregate status semantics

- The SDK provides no exactly-once or at-least-once guarantee and does not attach an idempotency key. Retries or ambiguous transport outcomes may produce duplicate service observations; a service that needs deduplication must define and evidence that policy separately.
- There is no durable queue, local persistence, or shutdown flush guarantee. An in-flight event may be lost when the process or runtime stops, and event ordering is not durable.
- `delivery_status` is one coarse, process-local status for the latest scheduling/terminal activity; it is not an event ledger or service health proof. The statuses are `Disabled`, `Idle`, `Pending`, `Delivered`, and `Failed`.
- `failure_count` is a cumulative local count of terminal/configuration failures. `last_failure` contains the most recent safe failure category, retry-exhaustion flag, and optional HTTP status. A later `Delivered` status does not erase prior failure history.
- A status, retry result, or aggregate dashboard signal cannot authorize, approve, or substitute for any security-critical operation.

## Failure-isolation invariant

**Telemetry cannot authorize, relax, bypass, or substitute for attestation, signing, replay, settlement, policy, or other security checks.** The rail integration schedules its coarse event only after the independent verified-operation and replay boundaries have passed. A telemetry outage, disabled client, invalid configuration, timeout, or service-side failure must not make those checks fail open. If an independent security gate is unavailable, the value-bearing path remains unavailable; do not fall back to simulated or software signing.

## Retention and service-side responsibilities

The SDK has no durable telemetry queue or storage and does not define service-side retention. Before enablement or any production-support claim, the **Telemetry Service Owner** must explicitly define and privacy-review service-side retention, access, deletion, incident handling, and aggregate dashboard behavior. The decision must be evidenced for the exact deployment scope and artifact. Retention should be minimized to the operational purpose, and exact private values remain outside public documentation.

## Public-safe monitoring and response

Monitor only aggregate delivery outcomes, retry exhaustion, safe failure categories, and HTTP status classes. A suspected sensitive-data exposure requires immediate telemetry disablement at the deployment boundary, preservation of sanitized evidence, and private escalation to the Security Reviewer and Incident Commander. Do not paste credentials, private endpoints, privileged identifiers, custody or recovery procedures, raw attestations, signature material, or payload captures into public issues, tickets, dashboards, or attachments.

Use the actionable [public operations runbook](./PUBLIC_OPERATIONS_RUNBOOK.md) for monitoring, disablement, incident escalation, evidence capture, and rollback boundaries. Use the [release recovery runbook](./RELEASE_RECOVERY_RUNBOOK.md) for exact-candidate hold and rollback evidence. Those runbooks do not establish service-side evidence or production support by themselves.

## Ownership and review triggers

| Owner role | Responsibility |
| --- | --- |
| SDK Maintainer | Owns the payload schema, constructors, redaction behavior, status semantics, tests, and public contract. |
| Telemetry Service Owner | Owns the private endpoint, transport credential handling, service retention/access/deletion policy, aggregate monitoring, and service evidence. |
| Operations/Deployment Owner | Owns deployment configuration, enablement/disablement, alert routing, and rollback execution for the deployed artifact. |
| Security Reviewer | Reviews privacy, endpoint, credential, data-minimization, and security-boundary changes; independent review remains a separate evidence gate. |
| Release Owner | Verifies the exact candidate, release evidence, conditional wording, and release hold or rollback decision. |
| Evidence Custodian | Maintains the public-safe evidence bundle and prevents sensitive artifacts from entering public records. |

Review this contract before each release and whenever the payload schema, event set, endpoint or authentication behavior, timeout/retry defaults, status semantics, service retention/access/deletion policy, deployment scope, incident outcome, or independent-review scope changes.

## Evidence boundary

SDK-local evidence includes minimized serialization, sensitive-header placement, HTTPS endpoint validation, bounded timeout/retry policy, failure observability, explicit disabled mode, no-runtime handling, and rail failure isolation in `src/telemetry.rs` and `src/protocol/rails/mod.rs`. The capability remains `partial` / `not-evidenced` / `unsupported` for the relevant axes until the exact deployment has service-side retention and monitoring evidence, named operational assignment, independent review, rollback evidence, and exact release artifacts.
