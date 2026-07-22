# Provider-neutral trust, replay, and release-evidence contracts

**Status:** Implemented typed seams; provider, authority, backend, and
production-support gates remain closed.

This document records the safe portion of [Linear CON-1543](https://linear.app/conxian-labs/issue/CON-1543/p0-operationalize-attestation-roots-collateral-revocation-and) and [GitHub #240](https://github.com/Conxian/conxius-enclave-sdk/issues/240). The implementation is in `src/enclave/trust_contracts.rs` and is intentionally provider-neutral.

The contracts provide reviewable requirement-to-code-to-test seams. They do
not establish a production provider, import trust roots, authenticate vendor
collateral, select an authority, provide distributed storage, or change the
repository's Beta / conditional support posture.

## Collateral metadata

`AttestationProvider` is a closed typed vocabulary for Android KeyMint/
StrongBox, AWS Nitro, Intel SGX DCAP, AMD SEV-SNP, and ARM PSA/CCA. The
existing broad `AttestationLevel` maps to a provider only when the mapping is
lossless enough to be safe: `StrongBox` maps to Android KeyMint/StrongBox;
generic `TEE` and `CloudTEE` labels do not identify a vendor and therefore do
not map back to Nitro, SGX, SEV-SNP, or CCA.

`CollateralMetadata` stores only:

- bundle identity and version;
- root-set and collateral digests;
- issued/expiry timestamps;
- revocation epoch;
- schema and verifier versions; and
- policy, measurement, and TCB digests.

`CollateralValidationContext` accepts a selected root-set digest, never raw
roots or arbitrary string labels. Validation is deterministic and fail-closed:

1. malformed shape, unknown schema, and unknown verifier versions are rejected;
2. provider and root-set mismatches are rejected;
3. future-dated metadata is rejected, with zero future skew by default;
4. `now >= expires_at` is expired, with no stale grace; and
5. revocation rollback and stale epochs are rejected separately.

`AuthenticatedCollateralMetadata` binds authority and authentication digests
without pretending that a digest is a signature. Metadata can be validated,
but the complete wrapper returns `AuthenticationUnavailable` until a concrete
provider verifier and collateral-signing authority are selected and evidenced.

## Secret-free replay binding

`ReplayBinding` explicitly covers provider, proof subject, proof mechanism,
nonce, operation, purpose, policy digest, key identity, and evidence digest.
Raw nonce, key identity, and evidence bytes are used only transiently to
calculate labelled digests; they are not retained, serialized, or included in
debug output. The final digest uses the versioned
`CONXIAN-REPLAY-BINDING/v1` domain and a fixed canonical encoding.

The contract is independent of the existing `ReplayGuard`. That guard remains
process-local and continues to serve existing containment paths; it is not
durable replay coordination.

## Durable replay contract

`DurableReplayStore` defines atomic `consume_once` and
`consume_once_batch` semantics over typed `ReplayReservation` values. The
contract requires future production implementations to provide:

- atomic insert-if-absent behavior for a complete batch;
- replica, restart, and region durability appropriate to the deployment;
- explicit duplicate, unavailable, uncertain, clock rollback, expiry
  ambiguity, invalid, backend rollback, and recovery-required outcomes; and
- fail-closed behavior whenever the store cannot prove the result.

`NonProductionInMemoryReplayStore` exists only for tests and development. It
implements batch preflight and no-partial-insert behavior, is process-local,
and is not wired into signing, settlement, attestation, or provider paths. The
repository still has no selected production database, replay owner, retention
policy, or recovery authority.

## Release-evidence manifest

`ReleaseEvidenceManifest` validates exact references and digests for the
candidate, commit, package, SBOM, provenance, independent review, and support
decision. `ReleaseEvidenceExpectation` checks candidate, commit, and package
digests; every reference must bind to the same candidate scope. Missing
independent review, missing support decision, schema mismatch, or inconsistent
scope remains non-promotable.

The manifest validator does not choose approvers, evidence locations,
retention, or a promotion authority. A complete manifest is evidence of
consistency only and does not enable production support by itself. Capability
evidence files remain unchanged because this branch does not have an exact
current release/artifact/support decision to record.

## Unresolved decisions

The following remain intentionally open and are tracked by the provider and
release issues:

- first protocol-signing provider and the concrete Android/Nitro portfolio
  integration;
- authenticated root/collateral authority and distribution policy;
- durable replay backend, replay owner, retention, and recovery semantics;
- promotion authority and evidence-store ownership; and
- exact release candidate, artifact, independent-review, and support decision
  evidence.

Until those decisions produce reviewable provider, deployment, authority,
independent-review, and artifact evidence, production attestation and
provider status remain unavailable/fail-closed.
