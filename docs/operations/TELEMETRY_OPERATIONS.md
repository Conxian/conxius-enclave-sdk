# Telemetry Privacy and Delivery Semantics

> **Status:** implementation and operations guidance for the Beta / conditional 2.x line. This document is not production-acceptance evidence.

This document defines the public-safe contract for the SDK telemetry surface. It deliberately does not publish service endpoints, privileged identifiers, credentials, retention secrets, or incident-recovery details.

## Privacy model

- Telemetry is **disabled by default**. `RailProxy` only sends an event after an integrator explicitly attaches a `TelemetryClient` with `with_telemetry`.
- Production construction uses `TelemetryClient::try_new` or `try_new_with_policy`. The endpoint must use HTTPS and may not contain URL credentials, query parameters, or fragments.
- The compatibility constructor `TelemetryClient::new` fails closed when configuration is invalid. Integrators that need explicit configuration errors should use `try_new`.
- An API credential, when configured, is held as a sensitive `X-Api-Key` transport header. It is never a JSON payload field and is not emitted by the telemetry module's diagnostics.
- The event body contains only a schema version and a coarse event name. It does not contain API credentials, private keys, raw signatures, signature-derived identifiers, raw attestation reports, addresses, assets, request data, or business metadata.
- The deprecated `track_signature` compatibility method discards its identifier argument and emits only the same coarse event. New integrations should call `track_event`.
- The SDK does not define server-side retention or deletion policy. A service owner must publish and review that policy before enabling telemetry for a deployment.

## Delivery semantics

Telemetry is best effort and is never a prerequisite for signing, attestation, settlement, or rail execution.

- `track_event` schedules delivery and returns without waiting for the network.
- On native targets, scheduling outside an active Tokio runtime is rejected and recorded as a safe failure; it does not panic.
- Each request has a five-second default timeout. Policies may be configured only within the SDK's bounded 30-second maximum.
- The default is two retries (three total attempts). The SDK bounds retries to three and applies exponential backoff from a 50 ms default, with a one-second maximum initial backoff.
- Transport failures and HTTP `408`, `429`, `500`, `502`, `503`, and `504` are retryable. Other HTTP failures are recorded without retry.
- The client exposes `delivery_status`, `last_failure`, and `failure_count` for safe local observability. Failure categories and optional HTTP status codes are exposed; request bodies, credentials, and endpoint values are not.
- There is no durable queue or shutdown flush guarantee. An in-flight best-effort event may be lost during process or runtime shutdown. Telemetry must therefore remain non-authoritative and must not gate security decisions.

## Test boundary

The request-capturing transport used by the telemetry unit tests is compiled only under `cfg(test)`. It accepts HTTP test URLs so serialization, header placement, timeout, retry, and failure behavior can be verified without contacting a service. Production code accepts only HTTPS endpoints.

## Public-safe operating runbook

### Monitoring

The SDK maintainer and telemetry service owner should monitor aggregate delivery outcomes, retry exhaustion, and HTTP status classes. Store only the safe status categories needed for alerting. Do not record payloads, API headers, private keys, raw attestations, signature material, or full endpoint values in logs, dashboards, tickets, or attachments.

### Rollback and disablement

The service owner can disable telemetry by omitting `with_telemetry` or by supplying the explicit disabled client. Signing and settlement must continue to use their independent security and policy controls. A rollback should preserve only aggregate failure evidence and the exact reviewed artifact reference; it must not require copying credentials or private service configuration into a public issue.

### Release recovery

Before promoting a telemetry-enabled artifact, the release owner should verify the exact commit, format/lint/test results, dependency/toolchain evidence, and the service-side retention and alerting decision. If any evidence is missing, keep the capability Beta / conditional and disable telemetry for the affected deployment. This repository does not claim production acceptance from the presence of these APIs or tests alone.

### Incident escalation

If secret egress or unexpected telemetry content is suspected:

1. Disable telemetry at the deployment boundary without changing signing or settlement policy.
2. Preserve safe evidence such as the artifact reference, timestamps, failure categories, and CI links.
3. Escalate to the SDK maintainer, service owner, and security reviewer through the organization's private incident channel.
4. Do not paste credentials, private endpoints, privileged identifiers, custody procedures, recovery secrets, raw attestations, or payload captures into public documentation or issue trackers.

## Evidence boundary

The implementation is covered by serialization redaction, HTTPS endpoint validation, bounded timeout/retry, failure-observability, disabled-mode, and no-runtime tests in `src/telemetry.rs`. The capability remains unsupported for production until the exact deployment has independent review, service-side operational evidence, and release-acceptance artifacts.
