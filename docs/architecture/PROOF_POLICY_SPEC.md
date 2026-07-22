# Proof Policy Specification

> **Status:** Phase A implementation for policy integrity, all-required
> composition, and the provider-neutral trust/replay contract foundation is
> present. Provider verification, vendor collateral, a real durable replay
> backend, runtime integration, and production support remain unsupported.

This document defines the public-safe contract for the canonical
`ProofPolicy`/`ProofBoundValueBearingAuthorization` types in
`src/enclave/proofs.rs` and their use at value-bearing authorization
boundaries. The older `ProofSetPolicy` and `VerifiedProofSet` types in
`src/enclave/proof.rs` remain source-compatible legacy types; they are not an
authorization substitute at the canonical rail boundary. It deliberately separates
identity, user authorization, device provenance, and secure-hardware claims;
one claim must not be silently promoted into another.

## 1. Claim separation

The proof taxonomy is a set of distinct claim families:

- **Server identity:** TLS certificate/server identity evidence. RFC 8446 and
  RFC 9266 describe TLS identity and authentication behavior; neither is a TEE
  quote or proof of the server's execution environment.
- **User authorization:** WebAuthn/FIDO assertions can authorize an RP
  ceremony. User authorization is separate from authenticator provenance and
  metadata-service information.
- **FIDO provenance:** Authenticator attestation and FIDO metadata describe
  provenance/capability when the RP chooses to verify it. They do not replace
  user presence, user verification, RP-origin, or operation authorization.
- **Device/platform attestation:** TPM, Android Key Attestation, App Attest,
  SGX/DCAP, TDX, SEV-SNP, Nitro, PSA, and CCA claims are provider-specific
  namespaces. A generic `DeviceIntegrityReport` is not silently converted into
  any of these claims.

The current implementation provides typed taxonomy and composition. It does
not claim that any provider verifier exists.

## 2. Canonical policy digest

**Implemented.** The policy integrity commitment is a SHA-256 digest over a
length-delimited, versioned, domain-separated canonical encoding:

- domain: `CONXIAN-PROOF-POLICY/v1`;
- version: `PROOF_POLICY_VERSION = 1`;
- policy production/test mode;
- `policy_id` as a label in the canonical record (the label itself is never
  treated as an integrity commitment);
- operation digest and `ValueBearingPurpose`;
- challenge nonce and replay identity;
- maximum age and maximum future skew;
- exact requirement count; and
- the canonical digest of every exact requirement.

Each `ProofRequirement` digest commits to its proof key (proof type and
subject), issuer identity, trust identity, and subject binding. Requirement
declarations are canonicalized as a set, so declaration order does not change
the policy digest. Duplicate requirement keys are rejected. The policy digest
therefore commits to the complete current security-relevant composition rather
than merely to `policy_id`.

`VerifiedProofSet` stores the verified policy digest privately and includes it
in the versioned `CONXIAN-PROOF-SET/v1` set binding. Canonical digest accessors
expose fixed-size digests only; raw evidence and private policy fields are not
exposed through diagnostics.

## 3. Required and alternative semantics

**Implemented:** the Phase A composer is **all-required**. Every requirement in
the policy must have one independently verified, exact-key proof. Missing,
duplicate, conflicting, stale, future, malformed, wrong-type, or fixture-only
evidence fails closed.

**Proposed, not implemented:** an alternative/threshold composition language
could support explicit groups, cardinality, and nested policies. Such a
language must have its own versioned canonical encoding, duplicate rules,
operator semantics, and tests before it can be accepted. An omitted
requirement must never be interpreted as an alternative.

## 4. Request, authorization, and dispatch binding

The canonical value-bearing rail binding is:

1. `ProofVerificationContext::for_settlement` derives the exact operation
   digest, settlement purpose, settlement audience/domain, nonce/challenge,
   freshness window, and replay identity from the intent and trusted process
   clock. Callers cannot supply an independent policy or context digest.
2. The canonical value-bearing path requires the exact six-proof production
   policy: server identity, user authorization, phone/device attestation, TEE
   attestation, FIDO2/WebAuthn assertion, and TPM quote. It verifies every
   independently typed envelope and rejects clock rollback. The production
   registry is intentionally unavailable, so production authorization fails
   closed before signing. Process-local proof helpers remain test-only
   containment paths.
3. Legacy rail requests retain the complete expected `ProofSetPolicy`, while
   durable proof-aware requests carry an exact `expected_proof_policy_digest()`
   commitment. `ValueBearingSignRequest::with_proof_authorization` also binds
   the constructor-controlled canonical policy digest, proof-context binding,
   and proof-set digest into the request's operation binding. A digest supplied
   only by evidence is never the source of truth.
4. The provider response can receive a proof set only after the proof set's
   verified digest, operation digest, purpose, count, and exact policy match
   the request. `RailProxy::authorize_verified_operation` then rechecks the
   canonical authorization, trusted-clock state, signer/key evidence, typed
   response binding, and manager replay authorization. Final dispatch repeats
   the policy, count, freshness, and durable replay checks before a private
   verified-operation envelope can reach a rail.
5. The legacy `ProofSetPolicy`/`VerifiedProofSet` fields remain available for
   compatibility with older serialized or provider-facing shapes, but they do
   not authorize canonical value-bearing rail dispatch. The canonical proof-set
   digest remains bound to the operation's intent, operation context, purpose,
   key identity/evidence, signature, attestation, policy, and replay
   authorization through the typed settlement envelope.

This repeated check is intentional defense in depth. A digest mismatch at any
boundary is an authorization failure, not a warning or a provider-verification
fallback.

## 5. Challenge, operation, and replay semantics

The nonce/challenge, operation digest, purpose, and replay identity are
security-relevant policy inputs and are included in the canonical policy
digest. Value-bearing settlement additionally binds the request to the
canonical intent hash and the `conxian/settlement/v1` operation domain.

The production-facing `RailProxy` replay path is durable-only. `RailProxy::new`
starts without a replay store, and its public attestation/integrity boundary
fails closed with a durable-replay-required error until a store is configured.
`RailProxy::with_replay_store` accepts only a `ReplayStore` reporting
`ReplayStoreDurability::DurableProvider`; process-local `ReplayGuard` and
unavailable stores are rejected before replay consumption. Rail reservations
use the complete `ReplayBinding` contract: rail/provider identity,
rail-attestation subject and mechanism, nonce or replay token, operation,
settlement purpose, policy digest, operation-key identity, and an attestation
or combined evidence digest. Stores retain only the resulting binding digest
and retention horizon; raw reports and secrets are not persisted.

The public `EnclaveManager::sign_value_bearing` method remains a
source-compatible fail-closed shim: it returns a durable-proof/replay-required
error before capability checks, replay checks, or provider invocation. It never
uses a process-local `ReplayGuard` as production authorization. Explicit
`ReplayGuard` adapters and in-memory durable-contract fixtures are compiled
only for crate tests; they are containment/contract tests, not distributed
replay evidence.

The additive `ReplayStore` contract and canonical `ReplayBinding` are
documented in [`TRUST_REPLAY_FOUNDATION.md`](./TRUST_REPLAY_FOUNDATION.md). The
durable proof/authorization entry points reject process-local stores, require
the exact canonical production policy, and final proof-aware signing requires
the request-side policy digest to be present and equal to the authorization
digest before consuming a replay reservation or invoking the provider. It
consumes a distinct, complete operation replay binding immediately before
provider signing; the carrier is one-shot and signer-key-bound.
Process-local replay guards and the bounded separate proof/final replay domains
described by older compatibility tests are not production authorization; they
remain test-only containment fixtures. Restart-safe, multi-replica,
provider-coordinated, or cross-region replay semantics remain **unsupported**
until specified, implemented, independently reviewed, and tested against the
deployment boundary.

## 6. Trust roots and collateral

`issuer`, `trust_identity`, and `subject_binding` are exact policy inputs, not
free-form diagnostic text. They are committed by the requirement and policy
digests and must match the verifier's independently established identity.

The repository does not currently ship or activate vendor roots, certificate
chains, revocation lists, quote collateral, TCB policy, Android status
handling, FIDO metadata validation, or provider-specific trust stores for the
listed hardware/platforms. The provider-neutral trust bundle and authenticated
digest/verifier boundary are contract foundations only; production verifier
routes remain explicitly unavailable. Research and type-level fields do not
establish those integrations. See
[`TRUST_REPLAY_FOUNDATION.md`](./TRUST_REPLAY_FOUNDATION.md) for the bounded
validation and refresh state model.

## 7. Provider extension namespaces

Provider-specific claims should use a namespaced extension identifier such as
`provider/<vendor>/<family>/<version>` and must be included in the exact
requirement/policy digest when they affect authorization. Extensions must be
length-delimited, versioned, bounded, and treated as opaque unless a registered
provider verifier validates their semantics. Unknown security-relevant
extensions fail closed; they must not be ignored or downgraded to a generic
device claim.

This namespace rule is a design requirement for provider integrations, not
evidence that a provider verifier exists today.

## 8. Fail-closed behavior

The following conditions reject value-bearing authorization:

- no expected policy or no request-derived policy digest;
- no canonical six-proof authorization at the value-bearing rail boundary;
- a policy/set/response digest mismatch or zero digest;
- a missing, duplicate, conflicting, substituted, stale, future, malformed,
  or fixture-only proof;
- an unknown or unauthenticated trust bundle, stale/expired collateral,
  revoked evidence, unacceptable TCB/measurement, sequence rollback, fixture
  promotion, or untrusted security clock;
- a policy, operation, purpose, nonce, replay, subject, issuer, trust identity,
  key, signature, or attestation binding mismatch; or
- missing provider verification, trust roots, collateral, durable replay state,
  atomic replay outcome, or exact release evidence where the deployment
  requires it.

Proof and trust validity use an exclusive expiry convention: `now >=
expires_at` rejects the item. Replay reservations use the same convention with
`retain_until`.

Errors expose bounded diagnostic text and identifiers only. Raw evidence,
secrets, credentials, private keys, and privileged operational details are not
part of the public policy surface.

## 9. Support boundaries

| Scope | Status | Meaning |
| --- | --- | --- |
| Policy digest, exact requirement digests, all-required composition | **Implemented, beta/conditional** | Repository code and negative/unit tests cover the composer and typed binding. |
| Request/response/rail/final-dispatch policy-digest checks and durable-only RailProxy replay boundary | **Implemented, beta/conditional** | The path fails closed on independently derived digest mismatch, missing durable replay configuration, process-local stores, unavailable stores, and uncertain store outcomes. |
| Provider-neutral trust bundle, authenticated digest/verifier boundary, canonical replay binding, replay-store contract, and durable final-signing boundary | **Implemented, beta/conditional** | Versioned types, bounded validation, explicit unavailable production routes, local atomic contract tests, exact-policy issuance, and durable-gated final signing exist; provider roots, a real durable backend, and deployment evidence remain open. |
| Canonical six-proof request/signing/rail/final-dispatch boundary | **Implemented, beta/conditional** | The rail requires `ProofBoundValueBearingAuthorization`; production verifier routes remain unavailable and fail closed. |
| Legacy `ProofSetPolicy`/`VerifiedProofSet` compatibility types | **Compatibility only** | Public/serialized shapes remain available, but legacy fields do not authorize canonical value-bearing rail dispatch. |
| TLS identity, WebAuthn authorization, FIDO provenance, TPM, Android, Apple, SGX, TDX, SEV-SNP, Nitro, PSA, CCA | **Research/design only** | Provider-specific verification is not implemented or production-supported. |
| Vendor roots, collateral, revocation, runtime/provider integration | **Unsupported** | No exact repository evidence chain exists. |
| Distributed replay, independent review, release artifact/provenance, production support | **Unsupported** | These gates remain open and are not inferred from local tests or documentation. |

The canonical evidence inventory is
[`capability-evidence.json`](./capability-evidence.json), and the research and
gap boundaries are recorded in
[`docs/audits/PR-237_HARDWARE_ATTESTATION_RESEARCH_2026-07-22.md`](../audits/PR-237_HARDWARE_ATTESTATION_RESEARCH_2026-07-22.md).
The trust/replay contract details and remaining gaps are recorded in
[`TRUST_REPLAY_FOUNDATION.md`](./TRUST_REPLAY_FOUNDATION.md).
