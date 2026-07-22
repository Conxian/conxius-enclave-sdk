# Trust and Replay Foundation

> **Status:** Beta / conditional. This document records provider-neutral
> contract foundations and local negative tests. It does **not** establish
> provider support, production readiness, distributed durability, or a release
> decision.

Issue [#240](https://github.com/Conxian/conxius-enclave-sdk/issues/240) adds a
bounded contract boundary for trust collateral and replay authorization. The
boundary is intentionally additive: existing process-local containment APIs
remain source-compatible, while new provider-facing entry points require the
explicit capabilities described below.

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

`TrustBundleEnvelope` carries the canonical digest, an exact verifier route,
and the signature bytes. The validator checks that the supplied digest is the
digest of the canonical snapshot and then delegates authentication to the
registered `(provider, verifier_id)` route. A URI, transport location, or
digest by itself is never treated as authenticated evidence. The production
registry contains explicit unavailable routes for the known provider
namespaces; it does not ship vendor roots, collateral, or provider verifier
implementations.

The provider-neutral validator has deterministic rejection states for:

- unknown schema, provider, or authentication route;
- unavailable or failed authentication;
- malformed or oversized content;
- not-yet-valid, expired, or stale collateral;
- revoked evidence, unacceptable TCB, or unacceptable measurement;
- provider/evidence mismatch;
- test/software fixture promotion; and
- unavailable, untrusted, or rolled-back security-clock input.

`TrustBundleSource::TestFixture` and the snapshot fixture flag are accepted
only by the crate-internal test validator. They cannot be promoted through the
production validator.

## 2. Rotation and refresh semantics

`TrustBundleCache` is a process-local coordination primitive for defining the
state machine, not a durable refresh service. A provider snapshot can be
installed only after authenticated validation and only when its sequence is
strictly newer than the current snapshot. Equal or lower sequences return
`SequenceRollback` without replacing the current receipt.

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
this foundation.

The additive proof APIs are:

- `ProofVerifierRegistry::verify_bundle_with_store` for an explicit store
  contract, including local fixture/contract tests; and
- `ProofVerifierRegistry::verify_bundle_with_durable_store`,
  `authorize_value_bearing_with_durable_store`, and
  `authorize_settlement_with_durable_store` for value-bearing boundaries that
  reject any store other than `DurableProvider` before authorization is issued.

Provider proof verification and durable replay are independent gates. A
process-local store, unavailable backend, or indeterminate transaction cannot
silently satisfy a value-bearing production path. Existing legacy APIs remain
available for source compatibility and local containment only; they do not
constitute production support.

## 4. Canonical replay binding

`ReplayBinding` uses the domain separator `CONXIAN-REPLAY-BINDING/v1` and binds
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
upgraded into the new durable path.

## 5. Evidence and remaining gates

The foundation is covered by focused unit/contract tests for canonical ordering,
digest mutation, trust rejection states, fixture non-promotion, sequence
rollback, refresh outage/recovery, redacted diagnostics, atomic duplicate
semantics, retention, clock rollback, unavailable backends, and indeterminate
durable-store outcomes.

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
