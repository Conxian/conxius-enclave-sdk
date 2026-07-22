# Issue #240 Phase A: Trust and Durable Replay Contract

> **Status:** Contract and containment implementation only. The SDK remains
> Beta / conditional. This document does not claim a provider, hardware,
> runtime, durable backend, independent review, release artifact, or production
> support.

## Purpose and boundary

Phase A supplies a provider-neutral contract for the part of an attestation
flow that must be stable before Android, Nitro, TPM, FIDO, or another provider
can be promoted:

```text
untrusted evidence
        │
        ▼
provider verifier + authenticated trust/collateral material
        │
        ▼
normalized `SingleMechanismAttestationResult`
        │ `TrustScope::SingleMechanism`
        │
        ▼
ProofPolicy / ProofVerificationContext checks
        │
        ▼
durable replay identity + consume-once authorization
```

The layers are intentionally separate. Evidence is transport data, trust and
collateral are authenticated inputs, and the normalized result is a
privacy-safe **single-mechanism evidence boundary**. `ProofPolicy` and the
exact verifier identity remain required contextual bindings, but this result
does not satisfy the six-factor production policy. Complete all-required
authorization remains exclusively the composed proof-bundle path through
`ProofVerifierRegistry::verify_bundle` (or an equally explicit composed type),
and durable replay cannot convert a single-mechanism result into that
authorization.

The production trust authenticator, provider verifier, and durable replay store
are explicit unavailable routes in this phase. Provider extension traits,
verified material, and normalization factories are crate-private test seams;
external provider adapters are not enabled in Phase A. Test fixtures are
compiled only for unit tests and cannot satisfy a production route.

## Versioned schemas and invariants

The public transport types are versioned and bounded:

- `TrustAnchor` identifies a provider/profile-scoped verification key and its
  validity, revision, revocation, and TCB state.
- `TrustBundle` carries a duplicate-free anchor set with deterministic sorted
  canonical encoding, authenticated release metadata, a rollback floor, a
  payload digest, and a signature.
- `CollateralSnapshot` carries provider/profile/mechanism-scoped opaque
  collateral, its digest, revision, validity, status, and signature.
- `AttestationEvidence` carries provider/profile/mechanism-scoped evidence,
  subject and key identity digests, the `ProofVerificationContext` binding
  digest, validity, status, payload digest, and signature.

The four public aggregate types are `Serialize`-only for transport preparation
and diagnostics; they intentionally do not implement generic `Deserialize`.
Untrusted JSON must enter through `deserialize_trust_bundle_json`,
`deserialize_collateral_snapshot_json`, or
`deserialize_attestation_evidence_json`. Each helper rejects input larger than
`MAX_TRUST_TRANSPORT_BYTES` before parsing private `deny_unknown_fields` wire
types, which retain bounded identifier, byte-field, and vector visitors. There
is no alternate public raw-JSON constructor that bypasses this outer bound.

Every security-relevant field is present in a deterministic SHA-256 encoding.
The encoding uses an explicit domain and version, enum tags, length-prefixed
values, fixed-width integer encodings, and deterministic anchor ordering. JSON
is transport only; it is never a signature or digest encoding. Existing proof
canonical bytes and `ProofReplayKey` encoding remain unchanged.

The only authorizable revocation and TCB state is `Good`. `Revoked`, `Unknown`,
`Unavailable`, `Expired`, `NotYetValid`, and `Unsupported` are explicit
fail-closed states. New or unknown wire values cannot default to `Good`.

Authentication and normalization reject:

- unknown fields, unsupported versions, oversized IDs/payloads/signatures, and
  malformed arrays;
- duplicate anchor IDs; canonical encoding sorts anchors deterministically
  regardless of input order;
- provider, profile, mechanism, bundle, collateral, or evidence mismatches;
- empty/reduced/optional-only policies, wrong proof kinds, wrong verifier IDs,
  and any policy that is not the exact production policy;
- signer anchors that do not match the requested provider/profile/algorithm,
  are not `Good`, are outside their inclusive validity window, violate the
  bundle revision or rollback floor, or fail the configured constraint digest;
- payload or metadata digest mutations and signature mutations;
- invalid or expired validity windows, future-dated evidence, and failed
  trusted-clock reads;
- revisions below the supplied rollback floor or invalid revision relationships.

Signer-anchor authorization is one fail-closed check reused for bundle,
collateral, and evidence signatures. Rotation is therefore allowed only when
the selected anchor is an overlapping, currently valid, authorized anchor in
the same bundle; a second revoked, expired, not-yet-valid, or rolled-back
anchor cannot be substituted for a valid signer.

The default production clock retains a process-global monotonic high-water
mark and rejects backward observations. Normalization replaces any caller
supplied freshness timestamp with a trusted clock copy before provider
verification and result canonicalization; operation, purpose, audience, nonce,
and bounded freshness windows are preserved. Durable replay also keeps a
non-resettable per-authorizer high-water mark before store invocation. This is
process-local rollback protection only: Phase A does not claim persistence
across process restarts, distributed clock coordination, or a durable rollback
database. Deterministic timestamp injection is private/test-only.

## Normalized result and privacy

`SingleMechanismAttestationResult` binds the provider, profile, mechanism,
exact verifier ID, `TrustScope::SingleMechanism`, subject digest, key identity
digest, exact trusted `ProofVerificationContext`, exact
`ProofPolicy::digest`, evidence/trust/collateral digests, status values, and
issued/expires/verified times. Its result digest covers the complete normalized
single-mechanism record. The exact production policy is retained as a
contextual composition requirement; it is not evidence that this one result
satisfies all six requirements. Raw evidence,
nonce bytes, trust-anchor payloads, collateral payloads, signatures, and raw
subject/key identifiers are not exposed by default `Debug` or audit output.

There is no public constructor or conversion from this result to a complete
proof-set authorization. A complete all-required/value-bearing authorization
must be produced by the explicit proof-bundle verifier/composer path.

`AttestationAuditMetadata` is intentionally smaller: it contains approved
digests, status values, and timestamps only. It is suitable for audit joins,
not for reconstructing evidence or secrets.

## Durable replay contract

`SingleMechanismReplayIdentity` is a new versioned identity for one normalized
mechanism. It does not change the existing `ProofReplayKey` or local
`ReplayGuard`. The durable identity binds:

- provider, profile, mechanism, and exact verifier identity;
- subject and key identity digests;
- operation and nonce digests;
- purpose and audience digests;
- exact policy, evidence, trust-bundle, and collateral digests; and
- the authorization expiry.

`IdempotencyKey` is a separate bounded non-empty value. A synchronous,
object-safe `DurableReplayStore` exposes atomic `consume_once` semantics with
the explicit outcomes `Consumed`, `AlreadyConsumedSameRequest`,
`ConflictingRequest`, `Unavailable`, and `UncertainCommit`. Expiry and malformed
input are errors. The unavailable production placeholder never authorizes.

The contract-only wrapper obtains time from an internal trusted-clock object,
builds a `SingleMechanismReplayIdentity` from a
`SingleMechanismAttestationResult`, and returns only a
`SingleMechanismReplayAuthorization` for `Consumed` or a backend-confirmed
`AlreadyConsumedSameRequest`. Conflict, unavailable, uncertain commit, clock
failure, status failure, and all other errors fail closed. The wrapper does not
call `EnclaveManager`, `RailProxy`, signing, settlement, or the existing local
`ReplayGuard`, and it cannot return a complete all-required/value-bearing
authorization.

## Non-goals

Phase A does **not** provide:

- Android KeyMint/StrongBox certificate-chain or revocation verification;
- AWS Nitro NSM/COSE verification, PCR policy, or KMS integration;
- a provider registration mechanism or production route availability;
- an OCSP/CRL/TCB service, trust-anchor distribution service, or persistent
  rollback database;
- a distributed replay backend, replica protocol, recovery implementation, or
  regional durability claim;
- WASM exposure, signing, settlement, rail dispatch, or capability promotion;
- independent security review, SBOM/provenance, release, or artifact evidence.

## Follow-on gates

1. Select one provider scope and pin its official verifier, roots, collateral,
   status source, runtime, and test vectors.
2. Add provider-specific verification and integration tests, including outage,
   rotation, rollback, recovery, and hardware/runtime evidence.
3. Select and independently review a durable replay implementation with
   atomicity, idempotency, uncertainty, restart, replica, and regional recovery
   evidence.
4. Attach exact CI, artifact, SBOM, provenance, and independent-review evidence
   to the same reviewed ref before changing any `productionSupport` value.

## Primary references

- [RFC 9334 — RATS Architecture](https://www.rfc-editor.org/rfc/rfc9334.html)
- [RFC 9711 — Entity Attestation Token](https://www.rfc-editor.org/rfc/rfc9711.html)
- [RFC 5280 — PKIX Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280.html)
- [RFC 6960 — OCSP](https://www.rfc-editor.org/rfc/rfc6960.html)
- [RFC 6024 — Trust Anchor Management Requirements](https://www.rfc-editor.org/rfc/rfc6024)
- [Android hardware-backed key attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [AWS Nitro attestation setup](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html)
- [AWS KMS cryptographic attestation](https://docs.aws.amazon.com/kms/latest/developerguide/cryptographic-attestation.html)
