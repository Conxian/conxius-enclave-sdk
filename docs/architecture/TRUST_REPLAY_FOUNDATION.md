# Trust and Replay Foundation

> **Status:** Beta / conditional. This document records provider-neutral
> contract foundations and local negative tests. It does **not** establish
> provider support, production readiness, distributed durability, or a release
> decision.

Issue [#240](https://github.com/Conxian/conxius-enclave-sdk/issues/240) adds a
bounded contract boundary for trust collateral and replay authorization. The
durable provider-facing entry points are additive, while legacy process-local
proof authorization helpers are crate-test-only containment paths. The public
`RailProxy` value-bearing integrity and typed dispatch paths are durable-only:
`RailProxy::new` has no replay store until `with_replay_store` accepts one that
reports `ReplayStoreDurability::DurableProvider`. Missing, process-local,
unavailable, or indeterminate replay state fails closed before authorization or
rail execution. The public `EnclaveManager::sign_value_bearing` method remains
only as a source-compatible fail-closed shim: it rejects before provider
invocation and cannot authorize production signing with process-local replay.

## 1. Trust-bundle contract

`src/enclave/trust.rs` defines a versioned `TrustBundleSnapshot` with:

- schema version and exact provider namespace;
- monotonic sequence number;
- issued, not-before, stale-after, and expiry times;
- collateral digest;
- bounded acceptable TCB identifiers and measurement digests; and
- bounded revoked-evidence digests.

The snapshot is canonicalized with the domain separator
`CONXIAN-TRUST-BUNDLE/v1`. Set-like TCB, measurement, and revocation fields are
sorted before encoding, so construction order cannot change the authenticated
digest. Unknown fields, invalid ordering, duplicate set members, zero digests,
and bounded-content violations fail closed.

`TrustBundleEnvelope` carries an authenticated envelope digest, an exact
verifier route/profile, source classification, and signature bytes. The
authenticated digest is domain-separated and binds the canonical snapshot
digest, provider, verifier ID/version, authentication profile, and source
classification. The validator checks that digest before delegating
authentication to the registered `(provider, verifier_id, version, profile)`
route, and `TrustValidationReceipt::bundle_digest()` retains that authenticated
digest. Changing any authenticated route or source field after signing fails
closed. A URI or transport location is not trust evidence and is intentionally
absent from the authenticated schema. The production registry contains explicit
unavailable routes for the known provider namespaces; it does not ship vendor
roots, collateral, or provider verifier implementations.

The provider-neutral validator has deterministic rejection states for:

- unknown schema, provider, or authentication route;
- unavailable or failed authentication;
- malformed or oversized content;
- not-yet-valid, expired, or stale collateral;
- revoked evidence, unacceptable TCB, or unacceptable measurement;
- provider/evidence mismatch;
- evidence issued-at outside the authenticated bundle interval, beyond the
  bounded future skew, or older than the configured maximum age;
- test/software fixture promotion; and
- unavailable, untrusted, or rolled-back security-clock input.

`TrustBundleSource::TestFixture` and the snapshot fixture flag are accepted
only by the crate-internal test validator. They cannot be promoted through the
production validator.

## 2. Rotation and refresh semantics

`TrustBundleCache` is a process-local coordination primitive for defining the
state machine, not a durable refresh service. Install, refresh, and read paths
must observe a trusted clock. The cache tracks a trusted-time high-water mark
and rejects rollback. A provider snapshot can be installed only after
authenticated validation and only when its sequence is strictly newer than the
current snapshot. Equal or lower sequences return `SequenceRollback` without
replacing the current receipt.

Trust validity uses an exclusive expiry convention: `now >= expires_at` (and the
receipt's `valid_until`) is expired. `current_for` never returns an expired
receipt, including while the refresh state is `RefreshUnavailable`; callers
receive an explicit expiry/error state and must revalidate or recover.

Refresh state is explicit:

| State | Meaning |
| --- | --- |
| `Empty` | No validated snapshot has been installed. |
| `Active` | A validated snapshot is available locally. |
| `RefreshUnavailable` | The refresh backend reported an outage; no unverified replacement is installed. |

An accepted refresh after an outage returns `Recovered`. Durable refresh
coordination, revocation distribution, provider collateral retrieval, and
cross-replica consistency remain integration work.

## 3. Replay-store contract

`src/enclave/replay_guard.rs` defines the provider-neutral `ReplayStore` trait:

- `consume_once` returns `Accepted` or `Duplicate` for one reservation;
- `consume_once_batch` returns an accepted count only after an atomic batch;
- retention horizons are explicit and expired reservations are rejected;
- backend unavailable, transaction-indeterminate, clock rollback, invalid
  input, and capacity outcomes are typed; and
- atomic batches return a typed failure and must not partially insert new
  reservations.

`UnavailableReplayStore` is the explicit fail-closed placeholder for a missing
backend. `ReplayGuard` implements the contract for compatibility and local
containment, but its durability is explicitly `ProcessLocal`: it is not
restart-safe, multi-replica, cross-region, or production replay coordination.
No distributed database or arbitrary persistence technology is selected by
this foundation. Any in-memory store used by crate tests to exercise the
`DurableProvider` contract is a test fixture only; it is not evidence of a
distributed backend.

`RailProxy::with_replay_store` rejects `ProcessLocal` and `Unavailable` stores
at configuration time. A proxy created without a store fails closed at its
public attestation/integrity boundary and before typed rail dispatch can emit
telemetry or invoke a rail. The production-facing rail reservation uses the
complete `ReplayBinding` with rail/provider identity, an explicit
rail-attestation subject and mechanism, nonce or replay token, operation,
settlement purpose, policy digest, operation-key identity, and an attestation
or combined evidence digest. Only the reservation digest and retention horizon
cross into the store; raw reports and secrets do not.

The crate-internal `ProofVerifierRegistry::verify_bundle_with_store` helper
exercises the explicit store contract for local fixture/contract tests. The
public durable APIs are:

- `ProofVerifierRegistry::verify_bundle_with_durable_store`,
  `authorize_value_bearing_with_durable_store`, and
  `authorize_settlement_with_durable_store` for value-bearing boundaries that
  reject any store other than `DurableProvider` before authorization is issued.
- `sign_value_bearing_with_proof_authorization_and_durable_store` for the final
  value-bearing boundary. It requires the same caller-supplied durable store,
  consumes a distinct complete operation replay binding at signing time before
  provider invocation, and treats duplicate, unavailable, indeterminate,
  rollback, and non-durable outcomes as failures.

Provider proof verification and durable replay are independent gates. A
process-local store, unavailable backend, or indeterminate transaction cannot
silently satisfy a value-bearing production path. Existing legacy APIs remain
available only as explicit crate-test containment helpers, while the public
legacy manager signature is a fail-closed compatibility shim. The durable final
signing path also requires the request-side expected policy digest to be present
and equal to the authorization digest before consuming operation replay or
invoking a provider. None of these contract foundations constitute provider
support or a production-readiness decision.

## 4. Canonical replay binding

`ReplayBinding` uses a domain-separated binding domain. Proof reservations use
`CONXIAN-REPLAY-BINDING/v1`; final value-bearing signing uses the distinct
`CONXIAN-VALUE-BEARING-OPERATION-REPLAY/v1` domain. Each complete binding binds
all security-relevant dimensions needed by issue #240:

- provider;
- proof subject and mechanism;
- nonce digest;
- operation digest;
- value-bearing purpose;
- complete policy digest;
- key-identity digest;
- evidence digest; and
- proof and audience identifiers when present.

The constructor hashes nonce and key identity before retaining them. Replay
reservations and store keys retain only the binding digest and retention
horizon; raw evidence, credentials, private keys, nonces, and secrets are not
stored. Debug output exposes identifiers and fixed-size digests, never raw
secret-bearing inputs or evidence payloads.

The proof-store path creates one complete binding per independently verified
proof and consumes all reservations atomically. A replay duplicate or uncertain
backend result therefore fails the complete authorization attempt rather than
silently accepting a partial proof set. Legacy incomplete bindings are not
upgraded into the new durable path. The final signing path consumes its
distinct operation reservation immediately before provider signing, and the
carrier is one-shot and signer-bound so reuse across manager instances cannot
produce a second signature.

The rail path uses the same complete-binding rule for attestation and typed
settlement authorization. Its local `ReplayGuard` and durable-contract fixtures
exist only under crate-test containment and must not be described as restart-
safe, multi-replica, or distributed evidence.

## 5. Evidence and remaining gates

The foundation is covered by focused unit/contract tests for canonical ordering,
digest mutation, trust rejection states, fixture non-promotion, sequence
rollback, evidence freshness boundaries, refresh outage/recovery, expired-cache
reads, trusted-time rollback, redacted diagnostics, atomic duplicate semantics,
exclusive retention, clock rollback, unavailable backends, exact production
policy enforcement, one-shot final signing, and indeterminate durable-store
outcomes.

The following evidence is deliberately **not** claimed:

- vendor roots, provider signature verification, quote/certificate parsing,
  collateral retrieval, or revocation services;
- a durable store implementation, restart recovery, multi-replica atomicity,
  or multi-region behavior;
- hardware-backed runtime integration or deployment-specific trusted-clock
  evidence;
- independent security review;
- exact release artifacts, SBOM, provenance, checksum, or publication evidence;
  or
- repository-wide production support.

These gaps remain release-blocking for affected value-bearing capabilities and
must be closed with a traceable requirement -> code -> test -> CI -> artifact
evidence chain before any production or compatibility claim is made.
