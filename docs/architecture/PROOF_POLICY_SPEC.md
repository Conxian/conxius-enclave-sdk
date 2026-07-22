# Proof Policy Specification

> **Status:** Phase A implementation for policy integrity and all-required
> composition is present. Provider verification, vendor collateral, runtime
> integration, and production support remain unsupported.

This document defines the public-safe contract for `ProofSetPolicy` and its
use at value-bearing authorization boundaries. It deliberately separates
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

This composer is intentionally distinct from the Phase A trust normalization
boundary. `SingleMechanismAttestationResult` records and replays exactly one
verified mechanism with `TrustScope::SingleMechanism`; its binding to the exact
production policy does not make it a six-factor authorization. Only
`ProofVerifierRegistry::verify_bundle` (or an equally explicit composed proof
type) can produce the complete all-required authorization used by value-bearing
paths.

**Proposed, not implemented:** an alternative/threshold composition language
could support explicit groups, cardinality, and nested policies. Such a
language must have its own versioned canonical encoding, duplicate rules,
operator semantics, and tests before it can be accepted. An omitted
requirement must never be interpreted as an alternative.

## 4. Request, authorization, and dispatch binding

The exact binding is:

1. The request carries the complete expected `ProofSetPolicy`. The request-side
   authorization boundary derives the expected policy digest from that object;
   it does not accept a digest supplied by evidence as the source of truth.
2. The provider response can receive a proof set only after the proof set's
   verified digest, operation digest, purpose, count, and exact policy match
   the request. The response stores the independently derived expected digest
   alongside the verified set.
3. Rail authorization checks the response-side expected digest and the
   `VerifiedProofSet` digest against the request-side policy digest, then checks
   the full policy binding again. `policy_id` is only a label/policy-selection
   value; it cannot satisfy this check.
4. Final dispatch rechecks the two stored policy-digest values, rejects zero or
   unequal values, and only then allows the private verified-operation envelope
   to reach the rail boundary.
5. The set digest remains bound to the operation's canonical intent, operation
   context, purpose, key binding, signature, attestation, and replay
   authorization through the existing typed settlement envelope.

This repeated check is intentional defense in depth. A digest mismatch at any
boundary is an authorization failure, not a warning or a provider-verification
fallback.

## 5. Challenge, operation, and replay semantics

The nonce/challenge, operation digest, purpose, and replay identity are
security-relevant policy inputs and are included in the canonical policy
digest. Value-bearing settlement additionally binds the request to the
canonical intent hash and the `conxian/settlement/v1` operation domain.

The current manager/rail replay authorization is process-local. It is consumed
before downstream rail execution and is not a distributed replay protocol.
Restart-safe, multi-replica, provider-coordinated, or cross-region replay
semantics are **unsupported** until specified, implemented, independently
reviewed, and tested against the deployment boundary.

## 6. Trust roots and collateral

`issuer`, `trust_identity`, and `subject_binding` are exact policy inputs, not
free-form diagnostic text. They are committed by the requirement and policy
digests and must match the verifier's independently established identity.

The repository does not currently ship or activate vendor roots, certificate
chains, revocation lists, quote collateral, TCB policy, Android status
handling, FIDO metadata validation, or provider-specific trust stores for the
listed hardware/platforms. Research and type-level fields do not establish
those integrations.

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
- a policy/set/response digest mismatch or zero digest;
- a missing, duplicate, conflicting, substituted, stale, future, malformed,
  or fixture-only proof;
- a policy, operation, purpose, nonce, replay, subject, issuer, trust identity,
  key, signature, or attestation binding mismatch; or
- missing provider verification, trust roots, collateral, replay state, or
  exact release evidence where the deployment requires it.

Errors expose bounded diagnostic text and identifiers only. Raw evidence,
secrets, credentials, private keys, and privileged operational details are not
part of the public policy surface.

## 9. Support boundaries

| Scope | Status | Meaning |
| --- | --- | --- |
| Policy digest, exact requirement digests, all-required composition | **Implemented, beta/conditional** | Repository code and negative/unit tests cover the composer and typed binding. |
| Request/response/rail/final-dispatch policy-digest checks | **Implemented, beta/conditional** | The path fails closed on independently derived digest mismatch. |
| TLS identity, WebAuthn authorization, FIDO provenance, TPM, Android, Apple, SGX, TDX, SEV-SNP, Nitro, PSA, CCA | **Research/design only** | Provider-specific verification is not implemented or production-supported. |
| Vendor roots, collateral, revocation, runtime/provider integration | **Unsupported** | No exact repository evidence chain exists. |
| Distributed replay, independent review, release artifact/provenance, production support | **Unsupported** | These gates remain open and are not inferred from local tests or documentation. |

The canonical evidence inventory is
[`capability-evidence.json`](./capability-evidence.json), and the research and
gap boundaries are recorded in
[`docs/audits/PR-237_HARDWARE_ATTESTATION_RESEARCH_2026-07-22.md`](../audits/PR-237_HARDWARE_ATTESTATION_RESEARCH_2026-07-22.md).
