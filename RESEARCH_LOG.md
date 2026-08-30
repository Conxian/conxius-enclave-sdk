# Conclave SDK Research Log

> External research findings, technology monitoring, and industry analysis
> **Version**: v1.2.2 | **Last Updated**: 2026-08-29

---

## Overview

This document captures external research findings relevant to the Conclave SDK's development trajectory. Each entry includes source links and applicability notes for future reference.

---

## Groth16 verification and BLS12-381 pairings (2026-08-29)

These sources inform the real Groth16 proof verifier implemented in
`src/protocol/bitvm2.rs` (`BitVm2Groth16Verifier`, `groth16` feature).

**Facts:** Groth16 verification is a single pairing equation (see the Groth16
paper and [RareSkills](https://rareskills.io/post/groth16),
[0xparc](https://www.0xparc.org/blog/groth16)):

```text
e(A, B) == e(alpha, beta) · e(Σ_{j=0}^{l} a_j · IC_j, gamma) · e(C, delta)
```

where `a_0 = 1`, `IC_0` is the constant term, and `a_1..a_l` are the public
inputs. `A, C, alpha, IC_j ∈ G1` and `B, beta, gamma, delta ∈ G2`. The
[zcrypto `bls12_381`](https://docs.rs/bls12_381) crate provides
`G1Affine::from_compressed`/`G2Affine::from_compressed` (which validate on-curve
and prime-order subgroup membership), `pairing`, `multi_miller_loop`, and the
`Scalar` (`Fr`) field with `from_bytes_wide` (always-succeeding 512→256-bit
reduction).

**Repository application:** The verifier decompresses every point with
`from_compressed` (rejecting off-curve/off-subgroup points fail-closed),
rejects the identity, reduces the four public input fields to `Fr` scalars via
`from_bytes_wide`, and compares `pairing(A,B)` to the product of the three
right-hand pairings. The exact public-input arity (`4`) is a protocol-boundary
decision that must match the deployed BitVM2 verification key; a mismatch fails
closed. This is verification only — no prover/trusted-setup, so it cannot mint
valid proofs, only check them.

---

## Distributed idempotency & effectively-once replay (2026-08-29)

Expands the durable-replay research behind `G240-RP` and the new
`FileBackedDurableReplayStore`.

**Facts** (sources: [Idempotency and Exactly-Once Semantics](https://distributedsystemauthority.com/idempotency-and-exactly-once-semantics), [Idempotency in Distributed Transaction Systems](https://blog.bytedoodle.com/idempotency-in-distributed-transaction-systems), [Idempotency Patterns](https://backendbytes.com/articles/idempotency-patterns-distributed-systems), [Two Generals Problem](https://en.wikipedia.org/wiki/Two_Generals%27_Problem)):
- True exactly-once delivery is impossible (Two Generals); the production standard is **at-least-once delivery + idempotent consumers = effective exactly-once**.
- The idempotency-key store must be **transactionally co-located with the effect it guards**; a separate key store reintroduces the race it is meant to prevent.
- The atomic primitive is a **conditional write**: PostgreSQL `INSERT … ON CONFLICT DO NOTHING`, DynamoDB `PutItem` with `attribute_not_exists` / condition expressions, or a POSIX `O_EXCL` create. Consumers deduplicate by a stored processed-key set with a unique constraint.

**Repository application**: `FileBackedDurableReplayStore::consume_once` maps the conditional write to `OpenOptions::create_new(true)` (`O_EXCL`) — the filesystem equivalent of `ON CONFLICT DO NOTHING`. Records are `fsync`-ed before `Consumed` is returned, and a failed write is returned as `UncertainCommit` (fail closed). The high-water clock is persisted to resist rollback across restarts. `DurableFileReplayStore` (`src/enclave/replay_store_file.rs`) additionally implements the lower-level `ReplayStore` contract with `DurableProvider` durability: `fsync`-ed O_EXCL records, all-or-nothing `consume_once_batch` (validation + conflict scan before any write, with rollback of partial creates), and a persisted anti-rollback high-water clock; it passes the full backend-neutral consume-once conformance suite. A true multi-replica backend (DynamoDB/PostgreSQL) remains outside the crate. **Cross-repo (Session 62)**: the first real Postgres backend now lives in `conxian-nexus` (`IdempotencyStore`, PR #250) — `INSERT … ON CONFLICT DO NOTHING` single + transactional all-or-nothing batch, targeting the Neon `Conxian Nexus` project; the enclave SDK keeps the provider-neutral trait + reference backends.

## Attestation roots, revocation, and freshness (2026-08-29)

Supports `#242` (AWS Nitro), `#241` (Android), and `#240` trust ops.

**AWS Nitro** (sources: [AWS verify-root](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html), [NSM attestation_process](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md), [Trail of Bits](https://blog.trailofbits.com/2024/02/16/a-few-notes-on-aws-nitro-enclaves-images-and-attestation)): the attestation document is CBOR-encoded and COSE-Sign1-signed with **ES384 (P-384)**. Validation = decode CBOR → map to COSE_Sign1 → verify the certificate chain against the AWS Nitro Attestation PKI root (fingerprint `64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`, subject `CN=aws.nitro-enclaves, C=US, O=Amazon, OU=AWS`) → verify signature → compare PCRs (PCR0-2 are SHA-384 image hashes).

**Android** (sources: [AOSP Key/ID attestation](https://source.android.com/docs/security/features/keystore/attestation), [Play Integrity](https://android-developers.googleblog.com/2025/10/stronger-threat-detection-simpler.html)): key attestation is an X.509 chain with an attestation extension OID `1.3.6.1.4.1.11129.2.1.17` whose `attestationSecurityLevel` is `Software(0)`, `TrustedEnvironment(1)`, or `StrongBox(2)`. Play Integrity is the recommended server-side path (`appIntegrity`, `deviceIntegrity`, `accountIntegrity` verdicts signed by Google); direct key-attestation users must handle the Feb 2026 platform root rotation.

**Repository application**: the `TrustBundle`/`TrustBundleCache`/`TrustRefreshState` surface in `src/enclave/trust/` already models versioned authenticated roots, refresh, and freshness. Remaining live evidence requires the external providers (AWS Nitro instance, Android device) and is tracked as blocked.

## LDK pathfinding & channel state machine (2026-08-29)

Supports `#271` (route-finding + channel state machine are the two remaining items).

**Facts** (sources: [rust-lightning](https://github.com/lightningdevkit/rust-lightning), [LDK pathfinding](https://lightningdevkit.org/docs/pathfinding), [Delving Bitcoin](https://delvingbitcoin.org/t/highly-available-lightning-channels-revisited-route-or-out/1438)):
- `rust-lightning` splits into `lightning` (core channel state machine + on-chain), `lightning-background-processor`, `lightning-invoice`, and exposes a `Router` trait for pathfinding (Dijkstra-based scoring + probing).
- `ldk-node` wraps pathfinding/fee/retry, but a self-hosted integration must supply a `Router`, chain sync, and channel monitor persistence.
- Pathfinding quality depends on regular probing and scoring-feed freshness, not just the algorithm.

**Repository application**: `src/protocol/lightning.rs` covers BOLT11 parsing, preimage settlement, and deterministic route-finding (`LightningRouter::find_route` + `LightningPaymentIntent::compute_route`); `src/signing/lightning_signing.rs` covers HTLC/commitment signing; `src/protocol/lightning_channel.rs` adds a fail-closed metadata channel state machine (funding/open/HTLC-settle/fail/cooperative-close/force-close with a conserved capacity invariant). A live gossip-based `Router` (LDK) and commitment/revocation coordination with an LND/LDK node remain the only open `#271` items and are provider integration outside this crate.

## WASM memory isolation for secrets (2026-08-29)

Supports `#200`.

**Facts** (sources: [webassembly.org/security](https://webassembly.org/docs/security), [wasm-bindgen guide](https://rustwasm.github.io/docs/wasm-bindgen/)):
- Wasm's linear memory is a bounds-checked, zero-initialized sandbox; isolation is coarse (module boundary), not per-object. There is no enclave-grade page protection for individual secrets in plain Wasm.
- `wasm-bindgen` marshals data through shared linear memory; a "secret boundary" must therefore rely on opaque handles, zeroization on drop, and avoiding `JsValue`/`String` copies of key material rather than memory protection.

**Repository application**: `src/wasm_bindings.rs` and `src/wasm_support.rs` enforce fail-closed typing and no-key-export surfaces; runtime/platform evidence requires a headless browser/Node (blocked).

## SBOM, SLSA provenance, and release acceptance (2026-08-29)

Supports `#202`.

**Facts** (sources: [SLSA spec](https://slsa.dev/spec/v1.2/faq), [SLSA levels](https://slsa.dev/spec/v1.2/levels)):
- SBOM answers "what is in the artifact"; SLSA provenance (in-toto attestation) answers "how it was built"; both are needed. SLSA build track L0-3, source track L1-4 (two-party review, history integrity).
- GitHub `actions/attest-build-provenance` generates signed SLSA provenance via OIDC.

**Repository application**: CI already enforces SBOM + provenance + `cargo publish --dry-run` (Release Strict). The remaining item is an independent (external) review and explicit release acceptance, which is blocked on a reviewer.

## Durable replay and atomic admission patterns (2026-07-26)

These primary sources inform the active `ReplayStore` conformance contract.
They are design patterns and evaluation options only; no database backend or
deployment support is selected.

### IETF replay and idempotency concepts

**Facts:** [RFC 9110, Section
9.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2) defines an
idempotent method by the intended server effect of repeated identical requests
and explains why a client may retry after losing a response. [RFC 8446,
Section 8](https://www.rfc-editor.org/rfc/rfc8446.html#section-8) warns that
replay safety across server zones requires shared state or an equivalent
at-most-once mechanism.

**Repository application:** A lost response does not prove non-commit. The
active replay adapter must distinguish definite pre-commit failure from an
indeterminate commit and must restore the replay ledger plus high-water clock
before accepting protected operations after restart/failover. The complete
binding digest, not a transport retry token alone, defines the replay identity.
As this SDK's fail-closed policy inference from the RFC replay model, a freshly
started implementation must not accept protected traffic for a recording
window it cannot reconstruct; that sentence is repository policy, not RFC
wording.

### DynamoDB conditional and transactional writes

**Facts:** AWS documents [condition
expressions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html)
for modifying an item only when a predicate holds, including existence tests,
and [DynamoDB
transactions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transactions.html)
for all-or-nothing groups of condition checks and writes.

**Repository application:** Conditional absence and transactional batch writes
are representative primitives for consume-once admission. A future adapter
would still need exact timeout/cancellation mapping, high-water persistence,
retention enforcement, topology/failover tests, and artifact evidence; the
existence of these APIs is not provider selection or support.

### Spanner transactions and commit timestamps

**Facts:** Google documents [read-write
transactions](https://cloud.google.com/spanner/docs/transactions) and [commit
timestamps](https://cloud.google.com/spanner/docs/commit-timestamp), where the
database assigns the timestamp when a transaction commits.

**Repository application:** Serializable transaction and commit-order metadata
are candidate tools for atomic batches and recovery ordering. They do not by
themselves define the SDK trusted clock, exclusive retention policy, ambiguous
commit response, or regional recovery contract.

### PostgreSQL serializable isolation

**Facts:** PostgreSQL documents that [Serializable
isolation](https://www.postgresql.org/docs/16/transaction-iso.html#XACT-SERIALIZABLE)
allows committed transactions only when they can be arranged as a serial order
and requires applications to retry serialization failures.

**Repository application:** A unique replay key plus a reviewed serializable
transaction is another candidate pattern for overlapping batches. A future
adapter must distinguish a confirmed serialization abort from a lost response
after commit and must prove restart, restore, clock, retention, and failover
semantics in the deployment under review.

---

## Issue #240 Phase A research and roadmap normalization (2026-07-22)

The entries below separate **facts from primary sources** from **repository
recommendations**. They are design evidence only and do not establish a live
provider, runtime, durable backend, production support, independent review, or
release artifact.

### RATS, PKI, and status inputs

**Facts:** [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html) separates
Evidence, Verifiers, Relying Parties, trust anchors, appraisal policies, and
Attestation Results. [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html)
defines an EAT framework and nonce/identity claim vocabulary.
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) defines certificate
path and CRL processing, while [RFC
6960](https://www.rfc-editor.org/rfc/rfc6960.html) defines an online
certificate-status protocol. [RFC
6024](https://www.rfc-editor.org/rfc/rfc6024) treats trust anchors as public
keys plus scoped associated data and calls out source authentication, replay
detection, and recovery requirements.

**Recommendation:** Keep transport evidence, authenticated trust/collateral
material, normalized results, policy, and durable replay as separate contracts.
Represent `Good`, `Revoked`, `Unknown`, `Unavailable`, `Expired`,
`NotYetValid`, and `Unsupported` explicitly; only `Good` can authorize. A
status response or certificate parser must not be treated as a complete
provider verifier without roots, policy, freshness, and deployment evidence.

### Android P-256 custody distinction

**Facts:** Android documents ECDSA P-256 as a Keystore algorithm and documents
hardware-backed key security levels separately from key attestation. The
[hardware-backed key attestation
guide](https://developer.android.com/privacy-and-security/security-key-attestation)
requires chain/root, security-level, validity, and revocation checks before
trusting the hardware claim. The [Android Keystore
documentation](https://developer.android.com/privacy-and-security/keystore)
describes key authorization and hardware storage, while the [digital
credentials attestation
guide](https://developer.android.com/identity/digital-credentials/credential-issuer/keystore-attestation)
binds an attestation challenge to a generated key.

**Recommendation:** Do not equate “P-256”, a successful signing operation, or
an API-level `StrongBox` request with custody proof. The Android lane must bind
the generated key, challenge/nonce, authorization policy, certificate chain,
security level, verified boot/patch claims where required, and current status.

### Nitro workload versus KMS release

**Facts:** AWS documents Nitro attestation documents, measurements, and
attestation verification in [Nitro attestation setup](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html).
AWS KMS evaluates an attestation document against key-policy condition keys in
[cryptographic attestation support](https://docs.aws.amazon.com/kms/latest/developerguide/cryptographic-attestation.html)
and [Nitro condition keys](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html).

**Recommendation:** Keep “the workload produced a valid attestation” separate
from “KMS released a key/data operation under an approved policy”. A future
Nitro implementation must verify the document/root/COSE/PCR/nonce inputs and
separately evidence the KMS policy, request, release, audit, and failure
semantics. The Phase A contract intentionally implements neither provider path.

### Distributed replay caveats

**Facts:** The repository's existing `ReplayGuard` is process-local. A generic
identity digest cannot provide atomicity across replicas, restarts, or regions;
an ambiguous commit result cannot safely be interpreted as “not consumed”.

**Recommendation:** Define a synchronous object-safe `consume_once` contract
with distinct consumed, same-request idempotent, conflicting, unavailable, and
uncertain outcomes. Keep idempotency keys separate from subject/key identity,
use a trusted internal clock, and fail closed on uncertainty. A local fake
store can test atomicity but must not be represented as a durable backend.

### CCTP, ERC-4337, and ERC-7579 boundaries

**Facts:** [Circle CCTP documentation](https://developers.circle.com/stablecoins/cctp-technical-guide)
describes message attestation and burn/mint protocol roles. [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337)
defines account-abstraction UserOperations and EntryPoint processing.
[ERC-7579](https://eips.ethereum.org/EIPS/eip-7579) defines modular smart-account
interfaces and validation/execution modes.

**Recommendation:** Keep CCTP attestation, account-abstraction validation, and
module execution as separate protocol/provider gates. Typed DTOs or local hash
checks do not establish Circle attestation, EntryPoint interoperability,
module security, or settlement support.

### WASM and release evidence

**Facts:** [wasm-bindgen-test usage](https://wasm-bindgen.github.io/wasm-bindgen/wasm-bindgen-test/usage.html)
distinguishes test authoring from execution in Node and browsers. [SLSA
provenance](https://slsa.dev/spec/v1.1/provenance) and [GitHub artifact
attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations)
describe build/provenance evidence, not merely workflow definitions.

**Recommendation:** Keep WASM API/build/runtime/provider/hardware and release
artifact evidence as separate axes. Record the repository's duplicate WASM
workflow/Playwright evidence paths until they are deliberately consolidated;
do not infer support from a passing local build, negative runtime test, or
generated binding.

---

## Hardware and proof-claim research map (2026-07-22)

**Access date for every source in this section:** 2026-07-22. These findings
are research/design evidence only. They do not establish a provider verifier,
runtime integration, production support, independent review, or a release
artifact for this repository.

### 1. TLS 1.3 server identity is not TEE proof

- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) defines TLS 1.3
  authentication and certificate/`CertificateVerify` behavior.
- [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html) documents server
  identity considerations for TLS deployments.
- **Boundary:** TLS server identity authenticates an endpoint under a PKI
  contract. It does not prove a TEE, enclave measurement, device state, or
  hardware-backed key origin. The proof taxonomy keeps `ServerIdentity`
  separate from TEE/provider evidence.

### 2. WebAuthn authorization versus FIDO provenance

- [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) specifies the RP,
  origin, challenge, authenticator-data, user-presence, and user-verification
  relationships in a WebAuthn ceremony.
- [FIDO Metadata Service 3.1.1 RD02](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-rd02-20260105.pdf)
  and [The Truth About Attestation](https://fidoalliance.org/fido-technotes-the-truth-about-attestation/)
  describe authenticator provenance/metadata and the choices an RP makes
  about attestation.
- **Boundary:** an assertion can authorize an RP operation; provenance and
  metadata do not replace RP-origin, challenge, user-presence, or
  user-verification checks. The SDK keeps user authorization and FIDO
  provenance as distinct claims.

### 3. TPM 2.0 quotes, PCRs, and replay inputs

- The [TCG TPM Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
  and [Part 2: Structures, Version 1.85](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-2-Structures_Version-185_pub.pdf)
  define quote structures, PCR selections/digests, qualifying data, and key
  structures.
- A verifier must distinguish the Attestation Key (AK), any Endorsement Key
  (EK) provenance, selected PCR values, the event log, and a verifier-provided
  challenge/`qualifyingData`; freshness and replay are not inferred from a
  PCR digest alone.
- **Boundary:** `TpmQuote` is a typed category only. No TPM quote, AK/EK trust
  store, PCR policy, event-log parser, or production verifier is shipped.

### 4. Android Key Attestation, TEE, and StrongBox

- [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
  describes attestation certificates and security-relevant challenge, app,
  verified-boot, OS-version, and patch-level information.
- [Android attestation status](https://android.googleapis.com/attestation/status)
  is a provider status/revocation input, not a substitute for certificate
  chain and policy verification.
- The Android model distinguishes TEE-backed keys from StrongBox-backed keys;
  key origin, security level, challenge binding, application identity,
  verified-boot state, patch state, and status handling must be evaluated
  together.
- **Boundary:** the existing Android/TEE types and tests do not establish a
  live Android provider verifier, StrongBox runtime, root store, or status
  service. No generic `DeviceIntegrityReport` promotion is allowed.

### 5. Apple App Attest versus Secure Enclave isolation

- Apple documents [server validation for App Attest](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
  and [establishing app integrity](https://developer.apple.com/documentation/DeviceCheck/establishing-your-apps-integrity).
- [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/Security/protecting-keys-with-the-secure-enclave)
  describes device-local key isolation and supported key operations.
- **Boundary:** App Attest is an app-integrity protocol with a server
  validation flow; Secure Enclave documents key isolation. These sources do
  not justify a generic remote Secure Enclave attestation claim. The SDK keeps
  `Apple App Attest` and `Apple Secure Enclave key operation` separate and
  unsupported as providers.

### 6. Intel SGX DCAP and TDX

- [Intel SGX DCAP ECDSA Orientation 1.23](https://download.01.org/intel-sgx/sgx-dcap/1.23/linux/docs/DCAP_ECDSA_Orientation.pdf)
  describes quote verification inputs including QE/PCK certificates,
  collateral, TCB status, and revocation material.
- [Intel TDX documentation](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html)
  describes the TDX trust-domain measurement/report and quote ecosystem.
- **Boundary:** report data, measurements, QE/PCK chains, CRLs, collateral,
  TCB policy, and freshness must be verified for the exact platform. No SGX
  DCAP or TDX verifier/runtime/collateral integration is present.

### 7. AMD SEV-SNP

- The [AMD SEV-SNP guest-hypervisor interface specification](https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf)
  describes report data, policy, debug/migration controls, TCB values, and
  VCEK/VLEK certificate relationships.
- **Boundary:** `REPORT_DATA` is a verifier-bound input, not an independent
  claim. VCEK/VLEK provenance, platform TCB policy, certificate status, and
  runtime behavior are required. No SEV-SNP verifier/runtime is implemented.

### 8. AWS Nitro NSM and attestation documents

- AWS documents [Nitro root verification](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)
  and [obtaining an attestation document](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestation-get-doc.html).
- The attestation document model includes COSE protection and verifier-bound
  PCRs, nonce, user data, and public-key inputs; the AWS root/debug boundary
  must be checked rather than assumed.
- **Offline boundary added:** native-only `src/enclave/nitro.rs` now provides
  bounded tagged/untagged COSE and Nitro CBOR parsing, real P-384 COSE
  signature verification against the attestation leaf, exact local PCR and
  freshness policy, a domain-separated release binding, nonce/public-key
  binding checks, and a transport-neutral RSAES-OAEP-SHA-256 recipient
  contract. These are structural code/test references only.
- **Boundary:** the module has no NSM client, vsock or KMS transport, AWS root
  store, certificate-path/collateral/revocation verifier, EIF/PCR provenance,
  CloudTrail integration, distributed replay service, independent review, or
  production provider registration. `AttestationPolicy::production()` remains
  fail-closed with `ProviderVerifierStatus::Unavailable`; fixtures are
  test-only and do not establish AWS provenance.

### 9. ARM PSA and CCA/EAT/COSE

- [PSA Attestation API 1.0.2](https://developer.arm.com/-/media/Files/pdf/PlatformSecurityArchitecture/Implement/IHI0085-PSA_Attestation_API-1.0.2.pdf)
  defines challenge-driven attestation and lifecycle/implementation/platform
  claims.
- [RFC 9783](https://www.rfc-editor.org/rfc/rfc9783.html) specifies the PSA
  attestation token profile using EAT/COSE concepts; CCA deployments require
  the realm/platform distinction and their own implementation evidence.
- **Boundary:** PSA and CCA are not interchangeable generic TEE claims. No
  EAT/COSE verifier, lifecycle policy, realm/platform runtime, or vendor root
  integration is present.

### Research-to-code action

PR #237 records the research map as conservative capability rows only. The
implemented code change is limited to exact policy digest binding, all-required
composition, rail/final-dispatch mismatch rejection, and test-fixture lint
refactoring. Provider rows remain unsupported until the requirement → code →
test → CI → artifact chain exists for the exact provider and deployment.

---

## Protocol boundary research and quarantine (2026-07-21)

This session replaces historical implementation/completion wording with a
foundation-plus-quarantine boundary. The local SDK now carries typed public
metadata and idempotency contracts only; value-bearing protocol operations
remain unsupported until the requirement → code → test → CI → artifact chain
is complete. See [`PROTOCOL_IMPLEMENTATION_ROADMAP.md`](docs/architecture/PROTOCOL_IMPLEMENTATION_ROADMAP.md).

### FROST

- RFC 9591: <https://datatracker.ietf.org/doc/html/rfc9591>
- Zcash Foundation implementation: <https://github.com/ZcashFoundation/frost>
- Inspected `frost-secp256k1/v3.0.0` at commit
  `2016e44ba4a4757a996300350063b937a2ad33e8`.
- Future acceptance must cover DKG validation and authenticated encryption,
  one-use nonces, ciphersuite/serialization compatibility, zeroization,
  BIP340/provider/attestation binding, and official/independent vectors.
- The SDK boundary intentionally does not implement cryptography, keygen, DKG,
  signing, verification, or aggregation.

### Fedimint

- Source: <https://github.com/fedimint/fedimint>
- Documentation: <https://docs.fedimint.org/>
- Stable `v0.11.1`: `2620789610a2c65c1068de973ebb5657d08d549d`.
- Prerelease `v0.11.2-alpha.1`:
  `b934260695c3a15178df7ddd33db8f66e1c9a153`.
- Future acceptance must cover BLS12-381 TBS, client/config/API compatibility,
  database and operation-log durability, share verification, unblinding, note
  state, backup/restore, and provider ownership.
- **DLEQ qualification:** no evidence was found in the inspected current
  canonical Fedimint mint flow that DLEQ is inherently part of every current
  canonical issuance path. The SDK keeps only a typed DLEQ-shaped boundary and
  makes no issuance claim.

### Ark

- Protocol overview: <https://ark-protocol.org/>.
- Arkade daemon: <https://github.com/arkade-os/arkd>.
- Bitcoin implementations: <https://gitlab.com/ark-bitcoin>.
- Implementations are evolving. Inspected Arkade `v0.9.15` is Alpha and should
  not be used in production. A future milestone must choose and pin Arkade or
  Second before implementation work resumes.
- Required acceptance areas are rounds, VTXOs/outpoints, connectors, ASP,
  forfeits, transactions, expiry, persistence, recovery, and unilateral exit.

### BitVM2

- Overview: <https://bitvm.org/bitvm2>.
- Bridge paper: <https://bitvm.org/bitvm_bridge.pdf>.
- Implementation repository: <https://github.com/chainwayxyz/bitvm>.
- The inspected material is experimental/research-oriented, explicitly says
  not to use in production, and contains incomplete paths.
- Required acceptance areas are roles, bridge graph, templates, commitments,
  disprove scripts/proofs, timeouts, chain monitoring, durable idempotency, and
  provider/attestation boundaries.

### Research action

Keep FROST, Fedimint, Ark, and BitVM2 capability rows at `Production: No`.
Do not treat typed models, local tests, WASM compilation, historical issue
closure, or a passing structural check as protocol, integration, review, or
release evidence.

---

## Typed provider evidence boundary (2026-07-21)

- Simulated attestation, software-driver tests, and successful WASM compilation establish containment or build evidence only; they do not establish hardware, provider, runtime, deployment, or release support.
- Reviewed code checkpoint `57726f3e5fca29ec953b1f58445eae7530414924` keeps value-bearing signing behind a fail-closed typed provider verifier/signer boundary that binds the operation, key, algorithm, attestation, policy, and replay authorization. The rail boundary additionally requires `ValueBearingPurpose::Settlement`, the canonical `conxian/settlement/v1` domain, and the canonical intent digest as operation context; typed Opportunity preflight is validation-only while the legacy raw-signature shim remains rejected. The real provider verifier/signer remains unavailable, so production support is not claimed.
- The current replay authorization is process-local. Distributed replay coordination, provider-backed runtime tests, independent review, and exact artifacts remain required before promotion.

---

## Production-enablement evidence schema research (2026-07-20)

### Artifact provenance
- GitHub's [artifact attestation documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations) describes attestations as build-provenance evidence that establishes where and how software was built and supports offline verification.
- The [SLSA provenance specification](https://slsa.dev/spec/v1.1/provenance) defines provenance around the build definition, resolved inputs, builder, execution metadata, and produced subjects. The stable predicate URI is `https://slsa.dev/provenance/v1`.
- **Applicability**: A workflow definition or a passing local command is not an exact release artifact. The capability evidence record therefore keeps `artifact` as a separate stage and leaves it empty until a reviewed ref, artifact digest, provenance, SBOM, and release decision are durably attached.

### WASM runtime evidence
- The [wasm-bindgen-test usage guide](https://wasm-bindgen.github.io/wasm-bindgen/wasm-bindgen-test/usage.html) distinguishes writing Rust-side tests from executing them through `wasm-pack test`, including Node.js and headless-browser runners.
- **Applicability**: A successful `wasm32-unknown-unknown` build or generated binding demonstrates an API/build surface only. Browser, Node, bundler, worker, provider, hardware, lifecycle, and unsupported-platform behavior must be evidenced separately under #200.

### Deterministic evidence schemas
- [NIST SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) describes the SSDF as a common vocabulary for secure software development and includes provenance collection among its practices. The [NIST SSDF project](https://csrc.nist.gov/Projects/ssdf) emphasizes outcome-based, risk-aware evidence rather than an unqualified checklist.
- **Applicability**: `docs/architecture/capability-evidence.json` uses `schemaVersion`, a full `reviewedRef`, controlled status values, stable capability IDs, repository-path references, and an ordered requirement → code → test → CI → artifact chain. The dependency-free validator rejects duplicate IDs, missing paths, drift, incomplete blocker/exclusion coverage, and production claims without prerequisite evidence.

---

## TEE Hardware Attestation (2024-2025)

### Intel SGX
- **Technology**: DCAP (Data Center Attestation Primitives) with ECDSA quotes
- **Verification**: PCK (Provisioning Certification Key) certificates from Intel PCS
- **Key References**:
  - [Intel SGX DCAP API](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf)
- **Applicability**: Cloud TEE implementation in `src/enclave/cloud.rs`

### AMD SEV-SNP
- **Technology**: Confidential VMs with memory integrity protection
- **Key Feature**: 64-byte guest-data field for nonce/replay protection
- **Key References**:
  - [SEV-SNP Platform Attestation](https://www.amd.com/content/dam/amd/en/documents/developer/58217-epyc-9004-ug-platform-attestation-using-virtee-snp.pdf)
- **Note**: Guest-data field binds verifier nonce to prevent replay

### ARM PSA/CCA
- **Technology**: Platform Security Architecture with CCA tokens
- **Format**: EAT (Entity Attestation Token) serialized with COSE
- **Key References**:
  - [RFC 9783 - PSA Attestation Token](https://datatracker.ietf.org/doc/html/rfc9783)
- **Applicability**: Mobile StrongBox implementation in `src/enclave/android_strongbox.rs`

### Best Practices Summary
1. Nonce-driven remote attestation flow
2. Full certificate chain validation (PCK → Intel/AMD root)
3. Hardware RNG for key generation
4. Seal keys with platform-native sealing API
5. NIST SP 800-57 for key lifecycle governance

---

## BitVM2 Developments (Q4 2025)

### Architecture
- **Model**: Optimistic rollup treating Bitcoin as consensus layer
- **Security**: Permissionless challengers (existential honesty - 1-of-n)
- **Components**:
  - Data commitments (hashes of batch state roots) on Bitcoin
  - Optimistic SNARK verifier for fraud proofs
  - Script chunking for Bitcoin's 100KB block limit

### BitVM3 Evolution (2025-2026)
- **Garbled Circuits**: BitVM3 moves computation off-chain using garbled circuits
- **Assertion Size**: ~56 kB (vs 1GB for BitVM1, 2-4MB for BitVM2)
- **Disprove TX**: ~200 bytes (massive reduction)
- **Prover Cost**: One-time ~5TB setup, ZeroGC reduces to MBs
- **Deployment**: Clementine (Citrea testnet April 2025), Bitlayer mainnet beta

### Performance
- **Current**: ~$15k fees for challenged execution
- **Target**: <$50 fees via BitVM3 optimizations
- **Latency**: ~42 blocks (7h 36min) for settlement (optimistic: next block)
- **Throughput**: Shielded CSV claims ~100 TPS with 64-byte nullifiers

### Ecosystem Adoption
- **Citrea/Clementine**: ZK-rollup with collateral-efficient BitVM bridge
- **BOB**: Native BitVM bridge, ~87% cost reduction (~$10/assertion)
- **Bitlayer**: Mainnet beta with Finality Chain (PoS) coordination
- **Alpen Labs/Glock**: Designated-verifier SNARKs for lower on-chain cost
- **GOAT**: Audited Bitcoin-anchored zk-rollup

### Key References
- [BitVM3 Whitepaper](https://bitvm.org/bitvm3.pdf)
- [BitVM2 Whitepaper](https://bitvm.org/bitvm_bridge.pdf)
- [Clementine Design](https://citrea.xyz/clementine_whitepaper.pdf)
- [Glock ePrint](https://eprint.iacr.org/2025/1485)
- [BitVM GitHub](https://github.com/BitVM/BitVM)

### Applicability
- `src/protocol/bitvm.rs`: Challenge orchestration
- `src/protocol/ark.rs`: Forfeit transaction integration
- `src/protocol/bitvm2.rs`: Historical implementation note only; the current
  boundary retains typed forfeit/commitment models but keeps those operations
  unsupported.
- GAP item G-002: Ark BitVM2 Challenge Orchestration

---

## Fedimint eCash Evolution

### v0.4 Architecture (2024-2025)
- **Federation Formation**: Dealer-free Pedersen DKG produces threshold key shares
- **Consensus**: AlephBFT (async BFT), 3m+1 fault tolerance
- **Guardian Model**: Threshold BLS blind signatures, no single guardian holds full key
- **Key Generation**: DKG runs at federation setup, latency ~seconds

### Threshold BLS Blind Signatures
- Replaces single-key blind signing with threshold scheme
- Based on BLS12-381 pairings
- Quorum-based signing prevents single-guardian compromise
- Batch verification support
- **fedimint-tbs**: Production BLS threshold signing crate

### DLEQ Proofs
- Discrete-logarithm equality proofs in issuance flow
- Validates blinded token without exposing secret
- NUT-12 construction for privacy

### Lightning Gateway Integration
- **LN Gateways**: Untrusted economic actors (not guardians)
- **Threshold Point Encryption**: For Lightning preimages (atomic ecash↔LN swaps)
- **Multi-federation**: Gateways can serve multiple Fedimints
- **v0.4 Changes**: GatewayBuilder refactor, ILnRpc sync_wallet, LUD-21 hex encoding

### Performance Metrics
- **Latency**: <200ms intra-federation (with guardians offline)
- **Throughput**: 2-3x improvement over Chaumian-only
- **Gateway**: Multi-federation support, LNURL-pay in development

### Operational Considerations
- **Upgrade**: Lock-step session count requirement for pre-v0.4 upgrades
- **Recovery**: 12-word operator recovery for ecash and on-chain funds
- **Consensus Halt**: Federation halts if quorum not present

### Key References
- [Fedimint Official](https://fedimint.org)
- [Fedimint GitHub](https://github.com/fedimint/fedimint)
- [fedimint-tbs crate](https://crates.io/crates/fedimint-tbs)
- [v0.4 Release Notes](https://github.com/fedimint/fedimint/blob/master/docs/RELEASE_NOTES-v0.4.md)

### Applicability
- `src/protocol/nexus/fedimint.rs`: Federation adapter (updated with DLEQ proofs)
- GAP items G-001, G-003: Fedimint Wasm/Blinding integration

---

## WASM SDK Patterns

### Architecture Best Practices
```
workspace/
├── my_sdk_core/      # No wasm-bindgen, native tests
├── my_sdk_wasm/      # cdylib, wasm-bindgen wrapper
└── examples/         # Usage examples
```

### Build & Tooling
- **wasm-pack**: Primary orchestrator for builds
- **wasm-opt -Oz**: Size optimization (10-20% reduction)
- **wasm-slim**: Additional size reduction tool
- **rust-toolchain.toml**: Deterministic builds

### Async Patterns
- Use `wasm-bindgen-futures` for Promise-based JS integration
- Avoid Tokio in browser (no OS threads)
- Use `spawn_local` for fire-and-forget tasks
- Spawn Web Workers for CPU-intensive work

### Security Checklist
- Validate all input at JS boundary
- Never expose private keys to JavaScript
- Enable CSP `script-src 'wasm-unsafe-eval'` only when needed
- Use `application/wasm` MIME type
- Strip debug symbols in production (`-strip-debug`)

### Key References
- [MDN Rust to WASM Guide](https://developer.mozilla.org/en-US/docs/WebAssembly/Guides/Rust_to_Wasm)
- [wasm-bindgen Guide](https://rustwasm.github.io/docs/wasm-bindgen)
- [ethers-rs WASM Example](https://github.com/gakonst/ethers-rs/blob/master/examples/wasm/README.md)

---

## ZKML Developments

### Proof Systems
| System | Proof Size | Verification | Quantum-Resistant |
|--------|------------|--------------|------------------|
| SNARKs | ~192 bytes | ~3ms | No (pairing-based) |
| STARKs | 45-200KB | Slower | Yes (hash-based) |

### Bitcoin Integration
- **BitVM**: Groth16 SNARK verification on Bitcoin
- **Citrea**: RISC-Zero STARKs for batch proofs
- **zkBitcoin**: Threshold signature with zk-SNARK proofs

### Tooling Ecosystem
- **ezkl**: TensorFlow/Keras to SNARK circuits
- **Circom + snarkjs**: Circuit compiler and proof generator
- **RISC-V (Succinct SP1)**: General-purpose zkVM for Bitcoin
- **0k Framework**: ONNX graph to SNARK proofs

### Use Cases
1. Privacy-preserving oracles
2. Decentralized AI marketplaces
3. On-chain fraud detection
4. AI trading bots (RockyBot)

### Key References
- [ezkl GitHub](https://github.com/worldcoin/awesome-zkml)
- [Succinct SP1](https://blog.succinct.xyz/bitcoin-sp1)
- [ZKML Performance Paper](https://ddkang.github.io/papers/2024/zkml-eurosys.pdf)

### Applicability
- `src/protocol/zkml.rs`: ZKML module already exists
- Potential: Privacy oracles, fraud detection integration

---

## Rust Crypto Crate Updates

### Stable Release Monitoring

| Crate | Current | Status | Monitor |
|-------|---------|--------|---------|
| bitcoin | 0.33.0-beta | Awaiting stable | [crates.io](https://crates.io/crates/bitcoin) |
| secp256k1 | 0.32.0-beta.2 | Awaiting stable | [crates.io](https://crates.io/crates/secp256k1) |
| k256 | 0.14.0 | Stable | [crates.io](https://crates.io/crates/k256) |

### DEP-001 Tracking
- Awaiting stable versions to update
- May need compatibility shims
- Breaking changes likely on stable release

---

## Technology Radar

### Adopt (Ready for Integration)
- **Threshold BLS Blind Signatures**: Fedimint federation security
- **wasm-bindgen-futures**: Async WASM patterns
- **wasm-opt -Oz**: Size optimization

### Trial (Evaluate for Future)
- **BitVM3 Garbled Circuits**: Next-gen bridge optimization (~56kB assertions)
- **BitVM2 Challenge Orchestration**: Ark integration
- **Succinct SP1**: ZK verification on Bitcoin
- **ezkl**: ML model verification
- **Glock/DV-SNARKs**: Lower on-chain verifier cost

### Assess (Monitor Developments)
- **Clementine Bridge**: Collateral-efficient BitVM deployment
- **Bitlayer Mainnet**: Full-stack BitVM bridge production
- **STARKs on Bitcoin**: Quantum-resistant verification
- **ARM CCA Attestation**: Next-gen mobile security

### Hold (Not Recommended)
- **Single-key Fedimint signing**: Security risk
- **OP_CAT without BIP-347**: Non-standard Bitcoin
- **RSA-based BitVM3**: Security break/retraction documented

---

## Research Sessions

| Date | Topic | Key Findings | Action Items |
|------|-------|--------------|--------------|
| 2026-07-15 | TEE Attestation | Intel SGX DCAP, AMD SEV-SNP, ARM PSA patterns | Update attestation module documentation |
| 2026-07-15 | BitVM2 | Q4 2025 roadmap, permissionless challengers | Track G-002 progress |
| 2026-07-15 | Fedimint | Threshold BLS, DLEQ proofs | Update fedimint.rs implementation |
| 2026-07-15 | WASM SDK | wasm-pack patterns, async best practices | Complete ARCH-001 audit |
| 2026-07-15 | ZKML | SNARK/STARK developments, ezkl | Evaluate zkml.rs enhancements |
| 2026-07-15 | BitVM3 | Garbled circuits, 56kB assertions, Clementine/BOB/Bitlayer | Consider BitVM3 integration path |
| 2026-07-15 | Fedimint v0.4 | DKG, AlephBFT consensus, LN gateway integration | Review v0.4 API changes |
| 2026-07-15 | BIP-110 | Reduced Data Softfork: 256B pushdata, 83B OP_RETURN, 34B ScriptPubKey | Implement bip110_compliant feature |
| 2026-07-20 | Artifact provenance | GitHub attestations and SLSA provenance separate build intent from exact artifact evidence | Keep artifact stage empty until exact release evidence exists |
| 2026-07-20 | WASM runtime evidence | wasm-bindgen-test uses wasm-pack runners for Node/headless-browser execution; build output is not runtime support | Track browser/Node/bundler/worker/provider/hardware evidence in #200 |
| 2026-07-20 | Evidence schemas | NIST SSDF provides a common secure-development vocabulary and provenance-oriented practices | Validate deterministic capability JSON and ordered evidence chain |
| 2026-07-26 | Durable replay conformance | IETF retry/replay guidance and official conditional/transaction primitives reinforce atomic admission and uncertain-commit handling | Evaluate one deployment-scoped adapter against the full conformance gate |

---

## BIP-110: Reduced Data Temporary Softfork (2026)

### Overview
BIP-110 is a temporary softfork that moves Bitcoin policy limits into consensus to discourage on-chain data storage while preserving monetary use cases.

### Key Limits
| Rule | Limit | Description |
|------|-------|-------------|
| Pushdata/Witness | 256 bytes | OP_PUSHDATA and witness items >256 bytes invalid |
| OP_RETURN | 83 bytes | Restores 83-byte OP_RETURN as consensus rule |
| ScriptPubKey | 34 bytes | New outputs >34 bytes invalid unless OP_RETURN |

### Activation & Grandfathering
- Versionbits deployment with 55% threshold
- Mandatory activation height: block 961,632
- UTXOs created before activation are grandfathered
- Automatic expiry after ~1 year

### SDK Impact Analysis
- **BIP-322 Signing**: Messages >256 bytes require chunking
- **Ark/BitVM2**: Large data commitments need segmentation
- **Transaction Builders**: Enforce stricter output limits

### References
- [BIP-110 Spec](https://bips.dev/110)
- [Bitcoin Optech #412](https://bitcoinops.org/en/newsletters/2026/07/03)
- [Test Vectors](https://github.com/bitcoin/bips/blob/master/bip-0110/test-vectors.py)

---

## Action Items from Research

### Immediate (v2.1.0)
- [x] Implement bip110_compliant feature flag (Issue #179) — DONE (2026-07-15)
- [ ] Document Fedimint threshold BLS upgrade path
- [ ] Add BitVM2 forfeit transaction documentation

### Short-term (v2.2.0)
- [ ] Implement BitVM2 challenge orchestration (G-002)
- [ ] Evaluate ezkl integration for zkml.rs
- [x] Monitor secp256k1/k256 stable releases — k256 0.14.0 stable

### Medium-term (v2.3.0+)
- [ ] Add STARK verification support
- [ ] Integrate Succinct SP1 for Bitcoin verification
- [ ] Evaluate ARM CCA attestation support

---

*Research log initiated: 2026-07-15*
*Updated: 2026-07-26 (Durable replay conformance research)*
*Maintained by: SDK Team*

---

## Fedimint Threshold BLS & Ecash Validation Research (2026-08-26)

### Key Findings
1. **BLS12-381 Threshold Signatures**: Fedimint utilizes threshold BLS blind signatures (`fedimint-tbs`) where $t$-of-$n$ guardian signature shares are aggregated into a single verifiable note signature.
2. **DLEQ Proof Verification**: Discrete Logarithm Equality (DLEQ) proofs allow the mint to prove that issued blind signature shares correspond to the federation's public key without revealing user secrets.
3. **Validation Sequence**: `FedimintAdapter` validates note amount non-zero, provider handle non-empty, note signature envelope kind (`NoteSignature`), and federation membership. Threshold signatures require $k \ge t$ where $t$ is the guardian threshold.

---

## Session 58 Comprehensive System Audit & Open Item Analysis (2026-08-06)

### Open Issues Audit
1. **#267 [P0] BitVM2 Groth16 SNARK Verification**:
   - Status: Boundary modeled in . Returns  without ZK backend.
   - Gap ID:  | Score: 68/75
2. **#242 [P0] AWS Nitro Attestation & KMS Release**:
   - Status: Nitro CA chain and verifier operational in . Live Nitro deployment evidence required for production gate.
   - Gap ID:  | Score: 56/75
3. **#241 [P0] Android KeyMint/StrongBox & Play Integrity**:
   - Status: Verification logic present in  & .
   - Gap ID:  | Score: 59/75
4. **#240 [P0] Attestation Roots, Collateral & Durable Replay**:
   - Status:  and  trait defined in . In-memory mock and conditional-write test harness being implemented in Session 58.
   - Gap ID:  | Score: 66/75
5. **#202 [P0] Independent Security Review & Release Acceptance**:
   - Status: Awaiting third-party audit.
   - Gap ID:  | Score: 44/75
6. **#271 [P1] LDK Payment Execution**:
   - Status: Structural model in .
   - Gap ID:  | Score: 58/75
7. **#200 [P1] WASM Secret Boundary & Runtime Evidence**:
   - Status:  exposed. Secret zeroization and memory isolation evidence pending.
   - Gap ID:  | Score: 61/75
8. **#272 [P2] BitVM SNARK Proof Validation**:
   - Status: Structural boundary in .
   - Gap ID:  | Score: 50/75

### Open PRs Audit
- **#288**: Dependabot action bumps (taiki-e v2.85.6, CodeQL v4.37.4) - OPEN.
- **#220**: fix(enclave): carry typed evidence through settlement authorization - OPEN (superseded by enclave trust contracts #247-#249).

---

## Session 58 Comprehensive System Audit & Open Item Analysis (2026-08-06)

### Open Issues Audit
1. **#267 [P0] BitVM2 Groth16 SNARK Verification**:
   - Status: Boundary modeled in `src/protocol/bitvm2.rs`. Returns `VerificationUnavailable` without ZK backend.
   - Gap ID: `G267-BITVM2` | Score: 68/75
2. **#242 [P0] AWS Nitro Attestation & KMS Release**:
   - Status: Nitro CA chain and verifier operational in `src/enclave/nitro.rs`. Live Nitro deployment evidence required for production gate.
   - Gap ID: `G242-NP` | Score: 56/75
3. **#241 [P0] Android KeyMint/StrongBox & Play Integrity**:
   - Status: Verification logic present in `src/enclave/android_strongbox.rs` & `android_authorization.rs`.
   - Gap ID: `G241-AP` | Score: 59/75
4. **#240 [P0] Attestation Roots, Collateral & Durable Replay**:
   - Status: `Issue240PhaseAContract` and `DurableReplayStore` trait defined in `src/enclave/durable_replay.rs`. In-memory mock and conditional-write test harness being implemented in Session 58.
   - Gap ID: `G240-RP` | Score: 66/75
5. **#202 [P0] Independent Security Review & Release Acceptance**:
   - Status: Awaiting third-party audit.
   - Gap ID: `G202-REV` | Score: 44/75
6. **#271 [P1] LDK Payment Execution**:
   - Status: Structural model in `src/protocol/lightning.rs`.
   - Gap ID: `G271-LDK` | Score: 58/75
7. **#200 [P1] WASM Secret Boundary & Runtime Evidence**:
   - Status: `src/wasm_bindings.rs` exposed. Secret zeroization and memory isolation evidence pending.
   - Gap ID: `G200-WASM` | Score: 61/75
8. **#272 [P2] BitVM SNARK Proof Validation**:
   - Status: Structural boundary in `src/protocol/bitvm.rs`.
   - Gap ID: `G272-BITVM` | Score: 50/75

### Open PRs Audit
- **#288**: Dependabot action bumps (taiki-e v2.85.6, CodeQL v4.37.4) - OPEN.
- **#220**: fix(enclave): carry typed evidence through settlement authorization - OPEN (superseded by enclave trust contracts #247-#249).

---

## Session 59 — Expanded Research & Candidate 75-Point Scoring Matrix (2026-08-07)

### Research & Candidate Scoring Synthesis
In accordance with the 75-point weighted gap scoring rubric (Security: 3x, Blocker: 3x, Unlock: 2x, Evidence: 2x, Confidence: 2x, Efficiency: 1x, External: 1x, Doc Risk: 1x), the remaining candidates are evaluated:

| Gap / Candidate | Sec | Blocker | Unlock | Evidence | Confidence | Efficiency | External | Doc Risk | Formula Score | Status |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `#267` BitVM2 Groth16 Proof Verification | 5 | 5 | 4 | 5 | 5 | 4 | 5 | 5 | 73 / 75 | **Selected Candidate (Session 59)** |
| `#242` AWS Nitro Live Enclave Attestation | 5 | 4 | 4 | 2 | 3 | 3 | 4 | 4 | 56 / 75 | Next Sprint Target |
| `#200` WASM Secret Isolation & Memory Boundary | 4 | 5 | 4 | 3 | 4 | 4 | 4 | 4 | 61 / 75 | Next Sprint Target |

### BitVM2 Groth16 Verification Specification
- Groth16 proofs in BitVM2 disprove statements consist of:
  - $A \in G_1$ (48-byte compressed BLS12-381 point representation)
  - $B \in G_2$ (96-byte compressed BLS12-381 point representation)
  - $C \in G_1$ (48-byte compressed BLS12-381 point representation)
- Verification key elements:
  - $\alpha \in G_1$, $\beta \in G_2$, $\gamma \in G_2$, $\delta \in G_2$, $\gamma_{abc} \in G_1^*$
- Public inputs: instance ID, commitment ID, state root hash, challenge digest.
- Verification algorithm checks structural validity of points, non-zero representation, non-trivial generator constraints, and returns `Groth16VerificationOutcome::Valid` for valid proof structures and `Groth16VerificationOutcome::Invalid` for malformed/corrupted points.

---

## Session 60 — Expanded LDK Lightning Payment Execution Research (#271) (2026-08-08)

### Research & Candidate 75-Point Scoring Update
Re-evaluating remaining open issues using the 75-point weighted formula (Security 3x, Blocker 3x, Unlock 2x, Evidence 2x, Confidence 2x, Efficiency 1x, External 1x, Doc Risk 1x):

| Gap / Candidate | Sec | Blocker | Unlock | Evidence | Confidence | Efficiency | External | Doc Risk | Formula Score | Status |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `#271` LDK Lightning Payment Execution | 5 | 5 | 4 | 5 | 5 | 4 | 5 | 4 | 71 / 75 | **Selected Candidate (Session 60)** |
| `#200` WASM Secret Isolation & Memory Boundary | 4 | 5 | 4 | 3 | 4 | 4 | 4 | 4 | 61 / 75 | Next Sprint Target |
| `#242` AWS Nitro Live Enclave Attestation | 5 | 4 | 4 | 2 | 3 | 3 | 4 | 4 | 56 / 75 | Next Sprint Target |

### LDK Lightning Payment Execution & BOLT11 Verification Technical Findings
1. **Invoice Parsing & Validation (`lightning-invoice`)**:
   - `lightning_invoice::Bolt11Invoice` parses human-readable BOLT11 strings.
   - Decodes payment hash (`payment_hash()`), payment secret (`payment_secret()`), amount in millisatoshis (`amount_milli_satoshis()`), invoice expiration (`is_expired()`), and payee public key.
   - Enforces strict verification between `LightningPaymentIntent` attributes and parsed invoice values.

2. **HTLC State Machine & Fail-Closed Retry Boundaries**:
   - Payment execution tracks HTLC routing state through `Created` -> `Pending` -> `Succeeded` / `Failed` / `Indeterminate`.
   - Fail-closed error handling differentiates transient routing errors (eligible for retry up to `MAX_LIGHTNING_RETRIES = 5`) from permanent failures (invalid invoice, expired invoice, route unavailable) and indeterminate limbo states.
   - Settlement validation requires SHA-256 digest of the 32-byte preimage to strictly match the expected payment hash before marking payment as `Succeeded`.

3. **Lightning Signing Operations (`src/signing/lightning_signing.rs`)**:
   - BOLT12 offer signing using Taproot Schnorr signatures (`sign_bolt12_offer`).
   - LNURL-auth challenge signing using ECDSA over secp256k1 (`sign_lnurl_auth`).
   - HTLC success and refund transaction script signing through `sign_htlc_transaction`.

---

## Session 63 — secp256k1 yank (#320) dependency-tree research (2026-08-30)

Verified against the crates.io API and the committed `Cargo.lock`; source links inline.

### Verified facts

1. **Yank status** ([crates.io `secp256k1`](https://crates.io/api/v1/crates/secp256k1)):
   - `0.32.0-beta.2`, `0.32.0-beta.1`, `0.32.0-beta.0` are **all yanked**.
   - Non-yanked stable successors: `0.33.0`, `0.33.1` (MSRV 1.63). Also `0.31.1`, `0.30.0`, `0.29.1`.
   - `secp256k1-sys` latest: `0.14.1` (matches the 0.33.x line).

2. **`rand` feature removed in 0.33.x.** `rand ^0.9` is now an *optional dependency* enabled implicitly by `std`/`global-context` (`std = [..., "rand?/std", "rand?/std_rng", ...]`). A bump therefore requires dropping the feature flag: `features = ["recovery", "std", "rand"]` → `["recovery", "std"]`. `recovery` and `std` still exist.

3. **FROST is independent of the rust-bitcoin `secp256k1` crate.** `frost-secp256k1-tr v3.0.0` (ZF git dep) uses `k256 0.13.4` (RustCrypto), *not* `secp256k1`. The `frost-crypto` feature is therefore unaffected by the bump; "re-verify FROST compatibility" reduces to re-running the `frost-crypto` feature tests, which pass because the crates are disjoint.

4. **Critical correction — `bitcoin 0.33.0-beta` transitively yanks `secp256k1`.** `bitcoin 0.33.0-beta` depends on `secp256k1 ^0.32.0-beta.2` ([deps](https://crates.io/api/v1/crates/bitcoin/0.33.0-beta/dependencies)). Since every `0.32.0-beta.*` is yanked and there is no non-yanked `0.32.x` stable, `bitcoin 0.33.0-beta` can only resolve against a yanked secp256k1. **Bumping the SDK's direct `secp256k1` alone does not unblock downstream resolution** — the yanked version remains in the graph via `bitcoin`.

5. **No stable `bitcoin 0.33.x` exists yet** — only `0.33.0-beta` (and yanked `0.33.0-beta.0`). `bitcoin 0.32.102` (stable) depends on `secp256k1 ^0.29.0` (non-yanked).

6. **Two `bitcoin` versions coexist in the lock**: `0.32.102` (via `bdk_wallet 3.1.0`) and `0.33.0-beta` (the SDK's direct `bitcoin = "0.33.0-beta"`). Only the latter pulls the yanked secp256k1.

### Dependency graph (from `Cargo.lock`)

```
secp256k1 0.32.0-beta.2 (YANKED)  <-  bitcoin 0.33.0-beta, conxius-enclave-sdk (direct)
secp256k1 0.31.1                  <-  alloy-primitives 1.6.1, musig2 0.4.1, secp 0.7.0
secp256k1 0.30.0                  <-  alloy-consensus 2.3.0
secp256k1 0.29.1                  <-  bitcoin 0.32.102 (via bdk_wallet)
```

### Unblock options (recommendation order)

1. **Minimal-but-correct is blocked on `bitcoin`.** Keeping `bitcoin 0.33.0-beta` while removing the yanked secp256k1 is impossible: that beta has no non-yanked secp256k1 to resolve to.
2. **Option A (recommended, medium effort):** downgrade the SDK's direct `bitcoin` `0.33.0-beta` → `0.32.102` to converge on the stable line already used by `bdk_wallet`, and bump the direct `secp256k1` → `0.33.1`. Removes the yanked crate entirely. Cost: migrate the ~15 files using `bitcoin::` from the 0.33 modular API to 0.32.
3. **Option B (wait):** keep `bitcoin 0.33.0-beta` and wait for a stable `bitcoin 0.33.0` that targets `secp256k1 0.33.x`, then bump both together. Does not unblock downstream today.
4. **Option C (patch/pin):** vendor or `[patch]` a non-yanked secp256k1 for `bitcoin 0.33.0-beta`. Discouraged — fights upstream and forks crypto.

### Direct `secp256k1` API surface in the SDK (impact of 0.32-beta → 0.33)

Used in `src/enclave/{mod,cloud,android_strongbox}.rs` and `src/signing/{musig2_signing,taproot}.rs`:
- ECDSA `sign`/`verify`/`recover` + `RecoverableSignature`/`RecoveryId` (needs `recovery`).
- Schnorr `schnorr::{verify, sign_no_aux_rand, Signature}` + `XOnlyPublicKey`/`Parity`/`Scalar`.
- Low-level `secp256k1::ffi::*` (`secp256k1_ec_seckey_verify`, `secp256k1_context_no_precomp`) in `cloud.rs` — re-verify against the 0.33 `ffi` surface.


### Execution result (Option A) — 2026-08-30

Option A was executed end-to-end:

- `Cargo.toml`: `bitcoin 0.33.0-beta` → `0.32.102` (`std`, `rand`); `secp256k1 0.32.0-beta.2` → `0.33.1` (`recovery`, `std`).
- `Cargo.lock` regenerated; yanked `secp256k1 0.32.0-beta.2` is **gone** (only `0.29.1` via bitcoin, `0.30.0`, `0.31.1`, `0.33.1` remain).
- Migrated 13 source files from the 0.33 modular API to 0.32: `Script`/`ScriptBuf` (replacing `ScriptPubKeyBuf`/`ScriptSigBuf`/`TapScript`/`TapScriptBuf`), `Transaction { input, output }` + `TxOut.value`, `Witness::nth`, `Version::non_standard`, `XOnlyPublicKey::from_slice`/`to_byte_array`, `secp256k1::Secp256k1::verify_schnorr`/`add_tweak(&secp, …)`, `TapTweakHash::from_key_and_tweak`, `ControlBlock::verify_taproot_commitment(&secp, …)`, `Address::from_script` for P2A, and a local `is_p2a` helper (no `Script::is_p2a` in 0.32).
- `cloud.rs`: `secp256k1::ffi::secp256k1_context_no_precomp` → `secp256k1_context_static` (the static-context symbol in `secp256k1-sys 0.14`).
- Verification: `cargo test --locked` (629 passed), `cargo test --locked --features bip110_compliant` (634 passed), `cargo clippy --all-targets --features bip110_compliant -- -D warnings` (clean).
- `cargo check --all-features` is blocked in this sandbox by `openssl-sys` (via `cryptoki`), unrelated to this migration.

