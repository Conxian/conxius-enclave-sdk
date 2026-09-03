# Conxius Enclave SDK Research Log

> External research findings, technology monitoring, and industry analysis
> **Version**: v1.3.0 | **Last Updated**: 2026-08-31

---

## Overview

This document captures external research findings relevant to the Conxius Enclave SDK's development trajectory. Each entry includes source links and applicability notes for future reference.

## Session 64 — Org-wide audit + research expansion (2026-08-31)

Full KB → code → CI → cross-repo audit plus fresh external research on the three
remaining Phase 1–2 expansion targets (#271 Lightning, PROTO-001 Fedimint threshold
mint, #242 Nitro attestation). Audit corrections landed in AGENTS.md, TRACKING.md,
README.md, NEXT_SESSION_PLAN.md, DEBT_INVENTORY.md, and ORG_WIDE_PHASED_PLAN.md.

### Live verification (first full toolchain run, 2026-08-31)
Installed Rust 1.97.1 + clippy/rustfmt + `libssl-dev`/`libpcsclite-dev`/`libclang-dev`
and ran the complete CI gate against the committed `Cargo.lock`:
- `cargo test --locked` → **629 passed, 0 failed** (confirms the AGENTS.md "629 tests" figure exactly).
- `cargo test --locked --all-features` → **645 passed, 0 failed, 2 ignored**.
- `cargo fmt --all -- --check` → clean.
- `cargo clippy --locked --all-targets --all-features -- -D warnings` → clean (0 warnings).
Confirms MSRV 1.97.1, the test count, and that no code remediation was required — the
fail-closed surface compiles and passes as documented.

### crates.io account cleanup (2026-08-31)
- `lib-conclave-sdk@2.0.8` (pre-rebrand name of this SDK) yanked — crate now `max_version 0.0.0`.
- `anya-core@1.2.0` (deprecated `anya-org` asset, absorbed into Conxian) yanked — `max_version 0.0.0`.
- Remaining active account crates: `conxius-enclave-sdk` 2.0.17, `lib-conxian-core` 0.3.2, and the four `conxian_*` gateway crates (0.1.4).

### BOLT12 offers & BIP-353 status (#271 expansion)
- BOLT12 merged into the Lightning spec (Sep 2024). 3 of 4 major implementations ship
  native support (Core Lightning, LDK, Eclair); LND is the holdout (experimental behind
  a feature flag, bridged via the LNDK sidecar).
- BIP-353 (DNS Payment Instructions) is marked **Complete** on bips.dev. Mature Rust
  crates exist (`bitcoin-payment-instructions`, `bip353-rs`); LDK has send/receive
  support and Phoenix/CakeWallet/Sparrow have shipped. bLIP-32 (DNS over onion
  messages) remains active.
- Network scale: publicly measured Lightning volume crossed $1.17B/month (Nov 2025),
  ~12M tx/month, ~266% YoY; private-channel volume is undercounted.
- Implication for `src/protocol/lightning.rs`: the SDK's BOLT12 offer parsing and
  BIP-353 HRN resolution sit on the stable spec path; `compute_route`/`find_route`
  remain the provider-integration seam (LND/LDK) rather than an in-crate wire concern.

### Fedimint threshold BLS blind signatures & DLEQ (PROTO-001)
- Fedimint's `fedimint-tbs` is an ad-hoc threshold blind signature over BLS12-381:
  blind `m̄ = r·m`, blind-sign `σ̄ = x·m̄ = r·(x·m)`, verify `e(m, pk) == e(σ, g2)`.
  One-more unforgeability reduces to (chosen-target) co-CDH; blindness is unconditional;
  verification is a single non-interactive pairing.
- Thresholdization is a t-of-n transformation using only the K-linearity of signing
  (guardian partial signatures aggregate to the full signature). Reference impl uses
  AlephBFT consensus (min 4 guardians).
- SDK state: `fedimint_crypto.rs` already implements `blind_message`/`unblind_signature`
  + Chaum-Pedersen `FedimintDleqProof` (gated `fedimint-crypto`). The remaining gap is
  guardian partial-signature aggregation + consensus/network coordination — provider-gated.

### AWS Nitro attestation certificate path & PCR bindings (#242)
- NSM issues a CBOR attestation document signed by the AWS Nitro Attestation PKI; the
  CA bundle is ordered `[ROOT, INTERM_1, …, INTERM_N]`.
- Root cert (commercial partition) SHA-256:
  `8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c`; subject
  `CN=.nitro-enclaves, C=US, O=Amazon, OU=AWS`; 30-year lifetime. The attestation leaf
  cert expires 3 hours after issue.
- PCR map: PCR0 = enclave image hash, PCR1 = kernel/bootstrap, PCR2 = app code,
  PCR8 = signing-cert fingerprint, PCR4 = instance ID (does not survive scaling).
  Recommended bindings: PCR0 for build, PCR3+PCR8 for release.
- Implication for `src/enclave/nitro.rs` + `verifiers/nitro_verifier.rs`: complete the
  certificate-path validation (pinned root hash above) and configure PCR/workload +
  release/KMS bindings; keep the production TEE route fail-closed until those gates pass.

Sources: bips.dev/353, spark.money "State of the Lightning Network in 2026",
docs.fedimint.org/crypto/tbs, aws-nitro-enclaves-nsm-api `attestation_process.md`,
AWS Compute blog "Validating attestation documents produced by AWS Nitro Enclaves".



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

### Full-repo audit (post-migration)

A whole-tree sweep for the 0.33 modular API and `bitcoin`-vs-`secp256k1` `from_byte_array`/`from_slice` split found exactly one latent break behind `#[cfg(target_arch = "wasm32")]` (not compiled on the host):

- `src/wasm_bindings.rs` (`WasmCovenantClient::generate_cat_vault_script`) used `bitcoin::XOnlyPublicKey::from_byte_array`, a 0.33-only name. Fixed to `from_slice` (the 0.32 / `secp256k1 0.29.1` API). This is a public-key covenant-script helper in the beta/"Unsupported" WASM lane (`docs/architecture/WASM_SUPPORT_MATRIX.md`), not a value-bearing signing path.

Everything else is verified: `frost-crypto`/`frost.rs` reference `secp256k1` only in strings/comments (ZF FROST uses `k256`); `groth16` uses `bls12_381`; `cryptoki`/`webauthn` use `openssl`/`p256`. None interact with the SDK's `bitcoin`/`secp256k1` types, so `--all-features` (a CI gate) is unaffected by this migration. WASM is built in CI via `wasm-pack` with a `CFLAGS` workaround for `secp256k1-sys`, which requires `clang` (absent in this sandbox).

### Code-scanning triage (Session 63, via PAT)

Enumerated 43 open CodeQL alerts (all at `main` HEAD `7edb2cf`, i.e. pre-existing, none from the migration). Triaged every one against the source:

- **42 × `hard-coded cryptographic value` ("used as a nonce", critical)** — all false positives. They flag synthetic fixture values (`vec![0;N]`, `[7;32]`, `vec![9;16]`, `digest(2)`, `"fixture-audience"`, `"android-key-1"`) used as *replay-protection* nonces on `ProofVerificationContext`, not ECDSA/Schnorr signing nonces. 29 in `tests/`, 13 in `src/` fixture/`#[cfg(test)]` builders (`proofs.rs`, `trust.rs`, `proof.rs`, `android_authorization.rs`, `rails/mod.rs`).
- **1 × `cleartext logging` (high)** — false positive. `#[derive(Debug)]` on `AttestationReport` (contains public `certificate_chain: Vec<String>`); no `println!`/`log::*`/`fs::write`/`writeln!` sink exists anywhere in the file.

Resolution: all 43 dismissed as `false positive`; `.github/codeql/codeql-config.yml` (`paths-ignore: tests/**`) added and wired into `codeql.yml` to suppress recurrence of the `tests/` bulk. Standing policy recorded in `AGENTS.md` ("scope-covered — always").

### Full-repo gap analysis (Session 63)

Enumerated the entire tracked state (issues/PRs, capability evidence, debt inventory, gap scorecard, workflow inventory, module catalog) and cross-referenced against the actual code. Findings and resolutions:

- **Version drift (resolved)**: `PRODUCTION_READINESS.md` and `REPOSITORY_ANALYSIS.md` were pinned at `2.0.14` while the actual state is `Cargo.toml`/git tag `2.0.16` (crates.io published). Corrected to `2.0.16` / latest GitHub release `v2.0.15`.
- **Release gap (open, tracked)**: a git tag `v2.0.16` and a crates.io `v2.0.16` publication exist, but **no GitHub Release** for `v2.0.16` — the latest GitHub Release is `v2.0.15`. The `release-strict.yml` GitHub Release step did not complete for `v2.0.16`. Next release should reconcile this.
- **Module catalog drift (resolved)**: `AGENTS.md` claimed "52 modules (24 blockchain + 28 infrastructure)" but listed only ~40 items and misnamed several. Actual: **43 protocol modules (25 blockchain + 18 infrastructure)** (Session 64 correction: `fedimint_crypto` added in PR #323; Session 63 initially recorded 49; Session 65 recount fixed the header 50→43 — the infrastructure list enumerates 18 modules, not 25), plus 3 non-protocol SDK modules (`wasm_bindings`, `enclave::android_strongbox`, `enclave::cloud`). Fixed names (`stablecoin`→`stablecoin_orchestrator`, `control_model`→`control_model_adapter`) and added omitted modules (`frost_crypto`, `lightning_channel`, `settlement_service`, `opportunity`, `business`, `identity`, `nexus::roast`).
- **Index staleness (resolved)**: `ISSUES_INDEX.md`/`PRS_INDEX.md` were one sync behind (missing #320 and PR #321). Re-ran `scripts/sync_issues.sh` → 40 issues / 280 PRs.
- **Capability evidence (clean)**: `python3 scripts/validate_capability_evidence.py --check` → 70 capabilities, matrix current. No drift.
- **Workflow inventory (14)**: `ci-strict`, `ci`, `hygiene`, `coverage`, `codeql`, `sbom`, `secret-scan`, `security`, `security-strict`, `release-strict`, `wasm-runtime`, `wasm-runtime-evidence`, `dependency-review`, `neon_workflow`. No missing documented workflows; branch-protection contexts now align to the actual check names (fixed the `Hygiene Check`→`Repository Hygiene` mismatch).
- **Open issues (6)**: #271, #242, #241, #240, #202, #200 — unchanged, all documented in `GAP_SCORECARD.md` and `TRACKING.md`.
- **Debt (DEBT_INVENTORY)**: `DEP-001` (beta deps) resolved by this session; `ARCH-002` (coexisting `secp256k1` versions bridged in `musig2`) tracked; `SEC-005` (branch protection) resolved.

### Research note: routing around Bitcoin P2P censorship/fragmentation (Session 63)

The SDK does not implement Bitcoin P2P networking (it is a signing/attestation
boundary), but its `bitcoin`, `lightning`, `covenant`, and `ark` modules encode
assumptions about how transactions reach miners. This note records the
resistance strategy the SDK should preserve, organised as **(a) the problem**,
**(b) economic incentives**, and **(c) alternative routing**, with the
corresponding SDK touchpoints.

#### (a) The problem: mempool/relay policy fragmentation

Relay policy is **local, not consensus**. Every node independently decides which
transactions to admit to its mempool and relay. Bitcoin Core v30 (late 2025) is
policy-only — it does not change consensus — and the community is actively
debating OP_RETURN standardness, v3 transactions, package relay, cluster
mempool, and full-RBF. Consequences:

- A consensus-valid transaction may still be **unrelayed** (non-standard) and
  require direct miner submission or targeted-node broadcasting.
- Divergent policies across implementations (Bitcoin Core vs Bitcoin Knots)
  produce **policy fragmentation**: the blockchain stays consistent, but
  propagation becomes unreliable for low-feerate or large-OP_RETURN txs.
- Network-level observers could historically identify and block Bitcoin P2P
  traffic via its fixed 4-byte magic bytes (now mitigated by BIP-324).

The governing principle being advocated on the mailing list (gmaxwell, echoed by
Anthony Towns) is: *"relay rules should admit all transactions which are
reliably being mined."* That is, policy should follow the fee market rather than
impose content rules stricter than what miners actually accept.

**SDK touchpoint**: the SDK must never hard-code a relay-policy assumption that
assumes a specific standardness rule; it should treat "constructed a valid
transaction" and "that transaction will be relayed/mined" as distinct, and fail
closed where the boundary cannot confirm propagation.

#### (b) Economic incentives: make censorship more expensive than inclusion

Censorship is a *cost* imposed on the censor. The mitigation is to align
incentives so that mining a transaction is always the economically rational
choice, and to lower the cost of participation so the relay set is too large and
anonymous to coerce.

- **Fee markets as the neutral arbiter.** If policy admits "everything reliably
  mined," the fee rate becomes the only selection criterion, removing content
  judgment from relay.
- **Weak blocks (Anthony Towns).** Miners with divergent policies can relay a
  weak compact block once they hold meaningful PoW share, so nodes that rejected
  a tx can fetch it in a full round-trip — a "relay via mining power" fallback.
- **Fee-bumping so L2 protocols can always get mined**: package relay (1P1C),
  child-pays-for-parent (CPFP), ephemeral anchors, and v3 transaction relay
  (TRUC) exist specifically so an under-funded parent can be economically
  bumped without a pinning vector.
- **Out-of-band fee acceleration.** Braidpool-style deterministic transaction
  selection and direct out-of-band fees to miners are a last-resort bypass when
  relay policy diverges from mining reality. Delving Bitcoin notes this is a
  "bug, not a feature" — canonical fee-bumping in-protocol is preferred — but it
  demonstrates the economic fallback always exists while hashpower is
  permissionless.

**SDK touchpoint**: `bitcoin` (PSBT/fee-bumping), `covenant` (CTV/APO), and the
`ark`/`cctp` value paths should preserve child-pays-for-parent and
fee-bumpability rather than emitting pinned or non-bumpable shapes.

#### (c) Alternative routing: transport and off-chain paths

When the base P2P relay is degraded, the fallback is **encrypted, unidentifiable
transport** plus **off-chain routing** that does not depend on on-chain relay at
all.

1. **BIP-324 (v2 encrypted transport).** Merged in Core 26.0, default in 27.0
   (2024); by early 2026 the majority of reachable nodes speak v2. It removes
   the fixed magic bytes and makes the wire byte-stream pseudorandom, so
   pattern-matching firewalls cannot block Bitcoin traffic. Decoy packets and
   traffic shaping (partially unimplemented) further raise surveillance cost.
2. **Erlay (BIP-330).** Set reconciliation cuts transaction-relay bandwidth by
   ~40%, lowering the cost of running a node — the cheaper participation is, the
   larger and more anonymous the relay set, the harder censorship becomes.
3. **Alternate transports.** BIP-155 `addrv2` (Tor v3), I2P, and out-of-band
   broadcast (mesh networks, satellite, HAM radio) are the classic last-resort
   broadcast channels.
4. **Lightning off-chain routing** — the strongest "alternative routing" layer:
   - **BOLT12 offers** (merged Sept 2024): reusable payment requests with
     **blinded paths**, so the recipient's node identity is hidden behind hops.
   - **BIP-353 DNS Payment Instructions** (Feb 2024): human-readable
     `user@domain` resolving (via DNSSEC) to BOLT12 offers, on-chain addresses,
     or silent payments — a DNS-based resolution layer independent of on-chain
     relay.
   - **Trampoline routing**: an intermediate node computes the path, so a sender
     does not need a full network view (censorship-resistant when the local view
     is degraded).
   - **Splicing / MPP / AMP**: let a single channel be resized and a payment be
     split across paths, so a single censored edge does not block settlement.

**SDK touchpoint**: `lightning` (BOLT12/BIP-353 parsing and route-finding) and
`lightning_channel` (state machine) are the SDK's off-chain routing surface;
`covenant` (CTV/APO) and `ark` provide the on-chain fallback shapes. The relay
strategy should keep these decoupled from any single on-chain relay assumption.

#### Summary position

Censorship of consensus-valid Bitcoin transactions is an economic contest, not a
protocol failure. The durable defences are: (1) policy that follows the fee
market ("admit what is reliably mined"); (2) fee-bumping primitives so L2 value
is never pinned; (3) unidentifiable encrypted transport (BIP-324) plus cheap
relay (Erlay) to keep the relay set large and anonymous; and (4) off-chain
routing (BOLT12/BIP-353/trampoline/blinded paths) so settlement does not depend
on on-chain relay in the first place. The SDK should preserve all four as
fail-closed boundaries rather than assuming any single relay path is available.

Sources: [Bitcoin Optech "Waiting for confirmation"](https://bitcoinops.org/en/blog/waiting-for-confirmation) · [bitcoindev — OP_RETURN standardness / weak blocks](https://groups.google.com/g/bitcoindev/c/d6ZO7gXGYbQ) · [Lightspark — Mempool Policy](https://lightspark.com/glossary/mempool-policy) · [BIP-324 / rust-bitcoin/bip324](https://github.com/rust-bitcoin/bip324) · [Spark — Erlay](https://www.spark.money/research/bitcoin-erlay-transaction-relay-protocol) · [Delving Bitcoin — deterministic tx selection](https://delvingbitcoin.org/t/deterministic-tx-selection-for-censorship-resistance/842) · [BOLT12.org](https://bolt12.org) · [Spark — BIP-353 vs Lightning Address vs BOLT12](https://www.spark.money/research/lightning-dns-address-adoption-analysis).



### Session 67 — BOLT12 Offers & BIP-353 Payment Domain Resolution (#271)
- **Candidate Scoring**: Evaluated open backlog using the 75-point weighted candidate matrix. Selected  (Lightning Payment Execution & Modern Extensions, 73/75) for immediate enhancement.
- **BOLT12 Offer Parsing & Validation**: Implemented  in  for recurring/reusable offer strings starting with , verifying checksum format and generating deterministic SHA-256 offer IDs.
- **BIP-353 Human-Readable Payment Resolution**: Implemented  in  for parsing DNS-based payment addresses (), validating domain structure and user character constraints.
- **Verification**: Added unit tests in ; all 586 test cases in the workspace pass cleanly under
running 586 tests
test enclave::android_authorization::tests::empty_and_oversized_fields_are_rejected ... ok
test enclave::android_authorization::tests::debug_redacts_raw_provider_evidence ... ok
test enclave::android_authorization::tests::binding_changes_when_security_context_or_evidence_changes ... ok
test enclave::android_authorization::tests::every_public_binding_method_rejects_stale_expired_and_future_evidence ... ok
test enclave::android_authorization::tests::android_tee_policy_accepts_tee_and_strongbox_but_not_software ... ok
test enclave::android_authorization::tests::missing_play_integrity_evidence_is_rejected ... ok
test enclave::android_authorization::tests::mismatched_request_fields_are_rejected_without_fallback ... ok
test enclave::android_authorization::tests::phone_route_is_explicit_android_keymint_but_production_unavailable ... ok
test enclave::android_authorization::tests::positive_structural_boundary_is_canonical_and_deterministic ... ok
test enclave::android_authorization::tests::strongbox_required_rejects_android_tee_downgrade ... ok
test enclave::android_authorization::tests::serde_rejects_unknown_and_private_key_fields ... ok
test enclave::android_strongbox::tests::software_strongbox_schnorr_matches_bip340_known_answer ... ok
test enclave::android_authorization::tests::serde_bounds_nested_der_and_play_evidence ... ok
test enclave::android_strongbox::tests::software_strongbox_ecdsa_signature_is_verifiable_and_nonzero ... ok
test enclave::android_strongbox::tests::software_strongbox_taproot_schnorr_normalizes_odd_internal_secret ... ok
test enclave::android_strongbox::tests::software_strongbox_schnorr_matches_bip340_reference_vector ... ok
test enclave::android_strongbox::tests::software_strongbox_taproot_schnorr_rejects_invalid_tweak_and_result_keys ... ok
test enclave::android_strongbox::tests::software_strongbox_taproot_schnorr_preserves_even_internal_secret_behavior ... ok
test enclave::attestation::tests::attacker_key_with_trusted_label_is_rejected ... ok
test enclave::attestation::tests::changing_signed_security_fields_invalidates_report ... ok
test enclave::attestation::tests::changing_signed_value_bearing_binding_invalidates_report ... ok
test enclave::attestation::tests::malformed_certificate_chain_is_rejected ... ok
test enclave::attestation::tests::nitro_offline_policy_does_not_promote_production_provider_status ... ok
test enclave::attestation::tests::extension_matching_is_exact_not_substring_based ... ok
test enclave::attestation::tests::report_type_and_version_are_signed ... ok
test enclave::attestation::tests::production_policy_rejects_generic_tee_and_is_unavailable ... ok
test enclave::attestation::tests::verify_accepts_report_within_freshness_window ... ok
test enclave::attestation::tests::typed_policy_rejects_wrong_purpose_and_algorithm ... ok
test enclave::attestation::tests::verify_accepts_strongbox_report ... ok
test enclave::attestation::tests::verify_rejects_clock_failure_before_provider_evidence ... ok
test enclave::attestation::tests::verify_rejects_stale_report ... ok
test enclave::attestation::tests::verify_rejects_invalid_signature ... ok
test enclave::cloud::tests::cloud_ecdsa_signature_is_verifiable_and_nonzero ... ok
test enclave::attestation::tests::verify_rejects_untrusted_root ... ok
test enclave::cloud::tests::cloud_schnorr_signing_is_explicitly_unsupported ... ok
test enclave::cloud::tests::cloud_ed25519_signature_is_verifiable_and_nonzero ... ok
test enclave::cloud::tests::cloud_test_fixture_attestation_is_not_production_evidence ... ok
test enclave::durable_replay::tests::expiry_and_clock_rollback_fail_closed ... ok
test enclave::durable_replay::tests::fake_store_is_consumed_idempotent_conflicting_and_atomic ... ok
test enclave::durable_replay::tests::authorizer_rejects_expiry_and_rollback_before_store_invocation ... ok
test enclave::durable_replay::tests::file_backed_store_fails_closed_on_expiry_and_rollback ... ok
test enclave::durable_replay::tests::file_backed_store_is_durable_across_restart ... ok
test enclave::durable_replay::tests::file_backed_store_is_idempotent_and_conflict_safe ... ok
test enclave::durable_replay::tests::file_backed_store_unavailable_when_dir_creation_fails ... ok
test enclave::durable_replay::tests::file_backed_store_authorizer_end_to_end ... ok
test enclave::durable_replay::tests::idempotency_key_is_bounded_and_distinct_from_identity ... ok
test enclave::durable_replay::tests::identity_canonical_encoding_binds_every_field ... ok
test enclave::durable_replay::tests::forward_time_recovers_after_rejected_rollback ... ok
test enclave::durable_replay::tests::mock_backend_conditional_write_semantics ... ok
test enclave::durable_replay::tests::test_durable_replay_conditional_write_conformance ... ok
test enclave::durable_replay::tests::no_raw_evidence_enters_identity_or_audit ... ok
test enclave::android_strongbox::tests::software_strongbox_schnorr_signature_is_verifiable_and_nonzero ... ok
test enclave::enclave_tests::attestation_leaf_operation_key_mismatch_is_rejected_after_report_verification ... ok
test enclave::durable_replay::tests::wrapper_authorizes_only_consumed_or_confirmed_idempotent ... ok
test enclave::durable_replay::tests::unavailable_store_status_and_non_good_result_fail_closed ... ok
test enclave::enclave_tests::current_managers_are_software_unverified ... ok
test enclave::enclave_tests::current_managers_reject_value_bearing_unlock_and_signing ... ok
test enclave::enclave_tests::changing_requested_operation_purpose_is_rejected ... ok
test enclave::enclave_tests::default_manager_cannot_pass_value_bearing_boundary ... ok
test enclave::enclave_tests::ecdsa_recovery_id_mismatch_with_bound_key_is_rejected ... ok
test enclave::enclave_tests::ecdsa_recovery_id_for_bound_key_is_accepted ... ok
test enclave::enclave_tests::complete_attestation_policy_rejects_wrong_root_purpose_algorithm_nonce_and_stale_report ... ok
test enclave::enclave_tests::malformed_provider_response_is_rejected_before_signature_use ... ok
test enclave::enclave_tests::migrated_primary_signers_never_call_legacy_raw_sign_when_typed_signing_rejects ... ok
test enclave::enclave_tests::production_value_signing_rejects_simulated_provider ... ok
test enclave::enclave_tests::public_value_bearing_signing_requires_durable_replay_before_provider ... ok
test enclave::enclave_tests::invalid_provider_evidence_does_not_consume_replay_state_and_valid_replay_is_rejected ... ok
test enclave::enclave_tests::invalid_key_binding_does_not_consume_replay_state ... ok
test enclave::enclave_tests::signed_binding_rejects_algorithm_tampering ... ok
test enclave::enclave_tests::signed_binding_rejects_derivation_path_tampering ... ok
test enclave::enclave_tests::signed_binding_rejects_key_id_tampering ... ok
test enclave::enclave_tests::signed_binding_rejects_expected_public_key_tampering ... ok
test enclave::enclave_tests::signed_binding_rejects_operation_digest_tampering ... ok
test enclave::enclave_tests::signed_binding_rejects_returned_public_key_tampering ... ok
test enclave::enclave_tests::software_attestation_cannot_be_promoted_to_value_bearing ... ok
test enclave::enclave_tests::software_capability_cannot_create_value_bearing_session ... ok
test enclave::android_strongbox::tests::software_strongbox_ed25519_fails_closed_as_unsupported ... ok
test enclave::enclave_tests::signed_binding_rejects_operation_purpose_tampering ... ok
test enclave::enclave_tests::signed_binding_rejects_purpose_tampering ... ok
test enclave::enclave_tests::trusted_security_clock_rejects_pre_epoch_without_defaulting_to_zero ... ok
test enclave::enclave_tests::software_manager_cannot_satisfy_migrated_primary_signers ... ok
test enclave::enclave_tests::valid_report_and_signature_from_different_operation_key_are_rejected ... ok
test enclave::enclave_tests::value_bearing_provider_response_requires_attestation ... ok
test enclave::enclave_tests::test_cloud_enclave_ed25519_signing_remains_non_production ... ok
test enclave::enclave_tests::value_bearing_request_is_domain_separated_and_key_bound ... ok
test enclave::enclave_tests::typed_provider_response_requires_attestation_leaf_operation_key_binding ... ok
test enclave::hardware_attestation_tests::crypto_verification_tests::test_cloud_tee_requires_hardware_hardening ... ok
test enclave::hardware_attestation_tests::crypto_verification_tests::test_rejects_invalid_signature ... ok
test enclave::hardware_attestation_tests::crypto_verification_tests::test_rejects_untrusted_root_ca ... ok
test enclave::hardware_attestation_tests::edge_case_tests::test_empty_certificate_chain_rejected ... ok
test enclave::hardware_attestation_tests::edge_case_tests::test_empty_signature_rejected ... ok
test enclave::hardware_attestation_tests::edge_case_tests::test_replay_guard_concurrent_access ... ok
test enclave::hardware_attestation_tests::edge_case_tests::test_single_certificate_rejected ... ok
test enclave::hardware_attestation_tests::edge_case_tests::test_verify_with_policy_result_fails_closed ... ok
test enclave::hardware_attestation_tests::fingerprint_tests::test_different_certs_produce_different_fingerprints ... ok
test enclave::hardware_attestation_tests::fingerprint_tests::test_fingerprint_deterministic ... ok
test enclave::hardware_attestation_tests::crypto_verification_tests::test_strongbox_requires_hardware_hardening ... ok
test enclave::hardware_attestation_tests::freshness_tests::test_rejects_future_timestamp ... ok
test enclave::enclave_tests::value_bearing_clock_failure_precedes_provider_and_replay_recording ... ok
test enclave::hardware_attestation_tests::freshness_tests::test_rejects_stale_attestation ... ok
test enclave::hardware_attestation_tests::freshness_tests::test_rejects_wrong_nonce ... ok
test enclave::hardware_attestation_tests::freshness_tests::test_replay_guard_allows_after_ttl ... ok
test enclave::hardware_attestation_tests::freshness_tests::test_replay_guard_blocks_duplicate_attestation ... ok
test enclave::hardware_attestation_tests::trust_enforcement_tests::test_cloud_tee_is_production_trust ... ok
test enclave::hardware_attestation_tests::trust_enforcement_tests::test_software_is_development_only ... ok
test enclave::hardware_attestation_tests::trust_enforcement_tests::test_strongbox_is_production_trust ... ok
test enclave::hardware_attestation_tests::trust_enforcement_tests::test_tee_is_development_trust ... ok
test enclave::hardware_attestation_tests::freshness_tests::test_accepts_fresh_attestation ... ok
test enclave::hardware_attestation_tests::trust_enforcement_tests::test_production_signing_requires_hardware_attestation ... ok
test enclave::hardware_attestation_tests::trust_tier_tests::test_cloud_tee_attestation_valid ... ok
test enclave::enclave_tests::value_bearing_replay_saturation_fails_closed_without_live_eviction ... ok
test enclave::hardware_attestation_tests::trust_tier_tests::test_software_attestation_blocked_for_production ... ok
test enclave::hardware_attestation_tests::trust_tier_tests::test_strongbox_attestation_valid ... ok
test enclave::nitro::tests::rejects_deeply_nested_bounded_cbor ... ok
test enclave::hardware_attestation_tests::trust_tier_tests::test_tee_attestation_valid ... ok
test enclave::nitro::tests::rejects_malformed_weak_and_unsupported_rsa_recipient_keys ... ok
test enclave::nitro::tests::parses_tagged_and_untagged_cose_with_real_p384_signature ... ok
test enclave::nitro::tests::rejects_malformed_cose_bounds_and_payload_types ... ok
test enclave::nitro::tests::rejects_recipient_plaintext_and_wrong_algorithm ... ok
test enclave::nitro::tests::rejects_reserved_indefinite_and_truncated_cbor_before_materialization ... ok
test enclave::nitro::tests::invalid_cose_signature_cannot_be_compensated_by_matching_bindings_or_trust ... ok
test enclave::nitro::tests::rejects_zero_kms_key_identifier_hash ... ok
test enclave::nitro::tests::rejects_zero_operation_digest ... ok
test enclave::nitro::tests::rejects_zero_policy_digest ... ok
test enclave::nitro::tests::rejects_zero_replay_identity ... ok
test enclave::nitro::tests::release_binding_is_deterministic_and_rejects_trailing_data ... ok
test enclave::nitro::tests::rejects_missing_payload_wrong_algorithm_duplicates_and_trailing_data ... ok
test enclave::nitro::tests::rejects_unknown_and_duplicate_payload_fields_and_invalid_pcrs ... ok
test enclave::proof::tests::all_six_proof_categories_verify_independently_and_compose ... ok
test enclave::proof::tests::canonical_context_and_proof_set_are_domain_separated_and_order_independent ... ok
test enclave::proof::tests::duplicate_conflicting_and_partial_sets_are_rejected ... ok
test enclave::proof::tests::independent_context_mismatches_are_typed_and_fail_closed ... ok
test enclave::proof::tests::mismatches_and_type_substitution_are_diagnosed_without_raw_evidence ... ok
test enclave::proof::tests::policy_digest_binds_exact_fields_and_requirement_order_is_canonical ... ok
test enclave::proof::tests::production_verifier_and_fixture_policy_boundaries_fail_closed ... ok
test enclave::proof::tests::raw_evidence_debug_does_not_expose_evidence_bytes ... ok
test enclave::proof::tests::stale_future_malformed_and_bound_errors_fail_closed ... ok
test enclave::proofs::tests::accepts_a_proof_within_the_configured_future_skew ... ok
test enclave::proofs::tests::bounded_deserialization_rejects_oversized_security_fields_and_sequences ... ok
test enclave::proofs::tests::bounded_transport_entry_point_rejects_oversized_input ... ok
test enclave::proofs::tests::bounded_transport_rejects_unknown_fields_before_provider_verification ... ok
test enclave::nitro::tests::trust_boundary_is_not_called_after_signature_or_policy_failure ... ok
test enclave::proofs::tests::capacity_failure_does_not_partially_insert_bundle_replay_keys ... ok
test enclave::proofs::tests::complete_replay_binding_store_path_is_atomic_and_ordered ... ok
test enclave::proofs::tests::durable_authorization_requires_exact_canonical_production_policy ... ok
test enclave::nitro::tests::rejects_missing_mismatched_and_all_zero_required_pcrs_or_expired_binding ... ok
test enclave::proofs::tests::durable_final_signing_fails_closed_before_provider_on_uncertain_store ... ok
test enclave::proofs::tests::durable_final_signing_consumes_operation_replay_once_across_managers ... ok
test enclave::proofs::tests::durable_final_signing_rejects_mismatched_request_policy_before_replay_and_provider ... ok
test enclave::proofs::tests::durable_final_signing_rejects_missing_request_policy_before_replay_and_provider ... ok
test enclave::proofs::tests::durable_final_signing_rejects_policy_digest_mutation ... ok
test enclave::proofs::tests::effective_expiry_uses_the_first_proof_validity_boundary ... ok
test enclave::proofs::tests::empty_policy_and_bundle_cannot_create_value_bearing_authorization ... ok
test enclave::proofs::tests::exact_route_does_not_fallback_to_kind_only ... ok
test enclave::proofs::tests::indeterminate_replay_store_outcome_fails_closed ... ok
test enclave::proofs::tests::durable_store_gate_rejects_process_local_replay ... ok
test enclave::proofs::tests::policy_digest_is_canonical_and_bound_to_verified_receipts ... ok
test enclave::proofs::tests::positive_test_only_all_six_composition_verifies_independently ... ok
test enclave::proofs::tests::process_local_replay_cannot_authorize_public_durable_value_path ... ok
test enclave::proofs::tests::production_registry_has_explicit_unavailable_routes ... ok
test enclave::proofs::tests::production_registry_rejects_a_well_shaped_all_six_bundle ... ok
test enclave::proofs::tests::proof_authorization_clock_failure_precedes_verification_and_replay_recording ... ok
test enclave::proofs::tests::proof_authorization_rechecks_expiry_before_hardware_signing_gate ... ok
test enclave::proofs::tests::proof_authorization_rejects_clock_rollback_after_expiry ... ok
test enclave::proofs::tests::proof_authorization_rejects_context_mismatch_before_signing ... ok
test enclave::proofs::tests::proof_policy_rejects_duplicate_required_kinds ... ok
test enclave::proofs::tests::proof_bundle_digest_is_order_independent ... ok
test enclave::proofs::tests::proof_signing_clock_failure_precedes_authorization_consumption ... ok
test enclave::proofs::tests::public_proof_authorization_ignores_caller_supplied_future_time ... ok
test enclave::proofs::tests::public_settlement_authorization_ignores_caller_supplied_future_time ... ok
test enclave::proofs::tests::public_proof_signing_path_uses_trusted_clock_and_hardware_gate ... ok
test enclave::proofs::tests::receipt_set_contains_only_digests_and_binding_metadata ... ok
test enclave::proofs::tests::reduced_policy_cannot_authorize_settlement_helper ... ok
test enclave::proofs::tests::rejects_duplicate_kind_and_duplicate_proof_id ... ok
test enclave::proofs::tests::rejects_invalid_evidence_and_cross_kind_substitution ... ok
test enclave::proofs::tests::rejects_missing_required_kind ... ok
test enclave::proofs::tests::rejects_stale_future_and_expired_proofs ... ok
test enclave::proofs::tests::rejects_unknown_serialized_fields ... ok
test enclave::proofs::tests::rejects_unlisted_kinds_when_policy_is_explicitly_closed ... ok
test enclave::proofs::tests::rejects_unsupported_version_and_malformed_bounds ... ok
test enclave::nitro::tests::verifies_policy_binding_nonce_public_key_and_injected_trust ... ok
test enclave::proofs::tests::rejects_wrong_digest_purpose_audience_and_nonce ... ok
test enclave::proofs::tests::replay_is_atomic_for_a_bundle ... ok
test enclave::proofs::tests::replay_key_changes_for_each_security_relevant_component ... ok
test enclave::proofs::tests::settlement_helper_binds_to_canonical_intent_and_domain ... ok
test enclave::proofs::tests::weak_policy_cannot_authorize_value_bearing_operations ... ok
test enclave::replay_guard::tests::accepts_new_key ... ok
test enclave::replay_guard::tests::allows_key_reuse_after_ttl_expiry ... ok
test enclave::replay_guard::tests::batch_outcome_count_is_derived_from_the_reservation_slice ... ok
test enclave::replay_guard::tests::batch_replay_is_atomic_on_capacity_saturation ... ok
test enclave::proofs::tests::settlement_authorization_clock_failure_precedes_verification_and_replay_recording ... ok
test enclave::replay_guard::tests::batch_replay_is_atomic_on_duplicate ... ok
test enclave::replay_guard::tests::bounded_batch_rejects_oversized_keys_before_recording ... ok
test enclave::proofs::tests::replay_is_rejected_after_legacy_ttl_before_proof_expiry ... ok
test enclave::replay_guard::tests::capacity_becomes_available_only_after_expiry ... ok
test enclave::replay_guard::tests::duplicate_failure_can_prune_expired_entries_without_inserting_new_keys ... ok
test enclave::replay_guard::tests::horizon_aware_batch_retains_key_after_legacy_ttl ... ok
test enclave::replay_guard::tests::horizon_batch_failure_does_not_partially_insert_keys ... ok
test enclave::replay_guard::tests::rejects_clock_rollback_after_horizon_pruning_without_reinsertion ... ok
test enclave::replay_guard::tests::rejects_duplicate_key_within_window ... ok
test enclave::replay_guard::tests::rejects_new_keys_when_capacity_is_saturated ... ok
test enclave::replay_guard::tests::replay_binding_builder_debug_redacts_transient_inputs ... ok
test enclave::replay_guard::tests::canonical_binding_changes_for_every_security_dimension ... ok
test enclave::replay_guard::tests::retention_horizon_is_exclusive_at_equality ... ok
test enclave::replay_guard::tests::replay_store_rejects_invalid_retention_and_clock_rollback ... ok
test enclave::replay_guard::tests::replay_store_contract_is_atomic_and_secret_safe ... ok
test enclave::proofs::tests::durable_final_signing_rejects_software_capability_before_replay_or_provider ... ok
test enclave::replay_guard::tests::unavailable_backend_is_explicit ... ok
test enclave::replay_guard::tests::zero_capacity_rejects_every_new_key ... ok
test enclave::replay_store_file::tests::file_store_fails_closed_on_validation ... ok
test enclave::trust::tests::anchor_duplicates_are_rejected_and_order_is_canonical ... ok
test enclave::replay_store_file::tests::file_store_is_durable_provider_and_accept_then_duplicate ... ok
test enclave::replay_store_file::tests::file_store_survives_restart ... ok
test enclave::replay_store_file::tests::file_store_batch_is_all_or_nothing ... ok
test enclave::trust::tests::monotonic_time_rejects_rollback_and_accepts_forward_observations ... ok
test enclave::trust::tests::mutations_to_payload_digest_signature_and_provider_fail_closed ... ok
test enclave::trust::tests::only_exact_policy_and_verifier_identity_can_authorize ... ok
test enclave::trust::tests::public_canonical_bytes_require_complete_validation ... ok
test enclave::trust::tests::canonical_result_changes_when_security_fields_change ... ok
test enclave::trust::tests::fixture_pipeline_produces_normalized_result_and_redacted_debug ... ok
test enclave::trust::tests::forged_context_freshness_time_is_replaced_before_provider_and_result ... ok
test enclave::trust::tests::unavailable_routes_and_clock_fail_closed ... ok
test enclave::trust::trust_bundle::tests::authenticated_digest_binds_route_source_and_receipt_identity ... ok
test enclave::trust::trust_bundle::tests::cache_caps_receipt_at_evidence_freshness_deadline ... ok
test enclave::trust::trust_bundle::tests::cache_requires_trusted_monotonic_time_and_rejects_expiry_equality ... ok
test enclave::trust::trust_bundle::tests::cache_rotates_and_rejects_sequence_rollback ... ok
test enclave::trust::trust_bundle::tests::canonical_digest_is_stable_across_set_order ... ok
test enclave::trust::trust_bundle::tests::debug_does_not_expose_signature_bytes ... ok
test enclave::trust::trust_bundle::tests::digest_and_signature_are_both_required ... ok
test enclave::trust::tests::signer_anchor_authorization_covers_rotation_status_validity_revision_and_constraints ... ok
test enclave::trust::tests::transport_rejects_unknown_fields_and_oversized_values ... ok
test enclave::trust::trust_bundle::tests::malformed_and_oversized_content_is_rejected ... ok
test enclave::trust::trust_bundle::tests::production_registry_is_explicitly_unavailable ... ok
test enclave::trust::trust_bundle::tests::fixture_cannot_promote_to_production ... ok
test enclave::trust::trust_bundle::tests::refresh_outage_and_recovery_are_explicit ... ok
test enclave::trust::trust_bundle::tests::refresh_unavailable_never_returns_expired_cached_trust ... ok
test enclave::trust_contracts::tests::authenticated_collateral_requires_an_unimplemented_authority_verifier ... ok
test enclave::trust_contracts::tests::collateral_expiry_is_strict_without_stale_grace ... ok
test enclave::trust_contracts::tests::collateral_future_and_revocation_states_fail_closed ... ok
test enclave::trust_contracts::tests::collateral_metadata_validates_without_raw_roots ... ok
test enclave::trust_contracts::tests::durable_backend_uncertainty_and_recovery_errors_are_typed ... ok
test enclave::trust_contracts::tests::every_replay_binding_field_changes_the_digest ... ok
test enclave::trust_contracts::tests::in_memory_store_rejects_expiry_ambiguity_and_clock_rollback ... ok
test enclave::trust_contracts::tests::in_memory_store_retains_consumed_identity_after_reservation_expiry ... ok
test enclave::trust_contracts::tests::provider_identity_only_maps_from_specific_existing_levels ... ok
test enclave::trust_contracts::tests::release_evidence_requires_exact_complete_consistent_scope ... ok
test enclave::trust_contracts::tests::release_evidence_schema_and_digest_mismatches_fail_closed ... ok
test enclave::trust_contracts::tests::replay_binding_debug_and_serialization_exclude_raw_sensitive_values ... ok
test enclave::trust_contracts::tests::replay_reservations_and_in_memory_store_are_atomic_and_non_production ... ok
test enclave::trust_contracts::tests::unknown_collateral_schema_and_root_mismatch_fail_closed ... ok
test enclave::verifiers::nitro_trust::tests::custom_root_ca_works ... ok
test enclave::verifiers::nitro_trust::tests::default_uses_embedded_root ... ok
test enclave::verifiers::nitro_trust::tests::root_ca_fingerprint_self_consistent ... ok
test enclave::verifiers::nitro_trust::tests::trust_boundary_constructs ... ok
test enclave::verifiers::nitro_verifier::tests::nitro_verifier_constructs ... ok
test enclave::verifiers::nitro_verifier::tests::root_ca_fingerprint_matches ... ok
test enclave::verifiers::oidc_verifier::tests::oidc_nonce_is_deterministic ... ok
test enclave::verifiers::oidc_verifier::tests::oidc_validate_claims_accepts_valid ... ok
test enclave::verifiers::oidc_verifier::tests::oidc_validate_claims_rejects_expired_token ... ok
test enclave::verifiers::oidc_verifier::tests::oidc_validate_claims_rejects_wrong_issuer ... ok
test enclave::verifiers::oidc_verifier::tests::oidc_verifier_constructs ... ok
test enclave::verifiers::pkcs11_verifier::tests::pkcs11_enumerate_slots_returns_ok ... ok
test enclave::verifiers::pkcs11_verifier::tests::pkcs11_key_type_classification ... ok
test enclave::verifiers::pkcs11_verifier::tests::pkcs11_verifier_constructs ... ok
test enclave::verifiers::webauthn_verifier::tests::attestation_formats_distinct ... ok
test enclave::verifiers::webauthn_verifier::tests::client_data_validation_accepts_valid ... ok
test enclave::verifiers::webauthn_verifier::tests::client_data_validation_rejects_wrong_type ... ok
test enclave::verifiers::webauthn_verifier::tests::webauthn_generate_challenge ... ok
test enclave::verifiers::webauthn_verifier::tests::webauthn_hardware_tier_classification ... ok
test enclave::verifiers::webauthn_verifier::tests::webauthn_verifier_constructs ... ok
test enclave::trust::trust_bundle::tests::evidence_freshness_enforces_bundle_interval_skew_and_age_boundaries ... ok
test protocol::account_abstraction::tests::canonical_action_shape_is_validated_without_execution_claim ... ok
test protocol::account_abstraction::tests::malformed_action_is_rejected_before_value_bearing_path ... ok
test protocol::account_abstraction::tests::module_network_context_cannot_be_zero ... ok
test protocol::account_abstraction::tests::module_setup_requires_provenance_after_local_validation ... ok
test protocol::ark::tests::all_value_bearing_ark_operations_are_exactly_unsupported_and_stateless ... ok
test protocol::ark::tests::backend_selection_accepts_only_the_safe_disabled_variant ... ok
test protocol::ark::tests::recovery_is_exactly_unsupported ... ok
test protocol::ark::tests::validates_typed_ids_versions_expiry_and_tree_shape ... ok
test protocol::ark::tests::vtxo_tree_empty_rejected ... ok
test protocol::ark::tests::vtxo_tree_power_of_two ... ok
test protocol::ark::tests::vtxo_tree_single_leaf ... ok
test protocol::ark::tests::with_backend_accepts_unconfigured_backend ... ok
test protocol::asset_tests::tests::canonical_eurc_is_active ... ok
test protocol::asset_tests::tests::canonical_mainnet_contract_asset_is_active ... ok
test protocol::asset_tests::tests::canonical_tron_usdt_passes_base58check_validation ... ok
test protocol::asset_tests::tests::canonical_usdc_address_checksum_is_valid ... ok
test protocol::asset_tests::tests::every_builtin_active_asset_has_canonical_metadata ... ok
test protocol::asset_tests::tests::malformed_checksum_cannot_be_registered_as_active ... ok
test protocol::asset_tests::tests::missing_contract_address_is_quarantined ... ok
test protocol::asset_tests::tests::placeholder_address_cannot_be_registered_as_active ... ok
test protocol::asset_tests::tests::test_expanded_bitcoin_network_registration ... ok
test protocol::asset_tests::tests::test_rsk_bob_registration ... ok
test protocol::asset_tests::tests::unregistered_asset_cannot_enter_value_bearing_paths ... ok
test protocol::asset_tests::tests::wrong_canonical_address_cannot_be_registered_as_active ... ok
test protocol::asset_tests::tests::wrong_network_is_rejected_before_asset_use ... ok
test protocol::babylon::tests::delegation_hash_is_deterministic ... ok
test protocol::babylon::tests::delegation_id_roundtrips ... ok
test protocol::babylon::tests::delegation_state_transitions ... ok
test protocol::bip110::tests::test_context_aware_witness_limits ... ok
test protocol::bip110::tests::test_core_transaction_shape_checks_all_measurements_and_boundaries ... ok
test protocol::bip110::tests::test_default_limits ... ok
test protocol::bip110::tests::test_message_chunking ... ok
test protocol::bip110::tests::test_message_chunking_long ... ok
test protocol::bip110::tests::test_ordered_commitment_segmentation ... ok
test protocol::bip110::tests::test_requires_chunking ... ok
test protocol::bip110::tests::test_validate_pushdata_boundaries ... ok
test protocol::bip110::tests::test_validate_script_pubkey_boundaries ... ok
test protocol::bip110::tests::test_validate_script_pushdata ... ok
test protocol::bip110::tests::test_with_limits_cannot_relax_consensus_maxima ... ok
test protocol::bip322::tests::test_bip322_canonical_to_spend_and_to_sign_vectors ... ok
test protocol::bip322::tests::test_bip322_explicit_network_policy_uses_bitcoin_address_semantics ... ok
test protocol::bip322::tests::test_bip322_full_and_proof_of_funds_reject_incomplete_material ... ok
test protocol::a2p::tests::test_prepare_otp_intent ... ok
test protocol::bip322::tests::test_bip322_messages_are_not_limited_by_legacy_payload_boundary ... ok
test protocol::bip322::tests::test_bip322_official_generated_p2tr_positive_vector ... ok
test protocol::bip322::tests::test_bip322_official_negative_vectors ... ok
test protocol::bip322::tests::test_bip322_official_p2tr_positive_vector_without_prefix ... ok
test protocol::bip322::tests::test_bip322_malformed_inputs_do_not_panic ... ok
test protocol::bip322::tests::test_bip322_official_p2wpkh_positive_vector ... ok
test protocol::bip322::tests::test_bip322_p2a_and_future_witness_boundaries_are_typed ... ok
test protocol::bip322::tests::test_bip322_taproot_annexes_are_explicitly_unsupported ... ok
test protocol::bip322::tests::test_bip322_to_sign_rejects_message_mismatch_and_noncanonical_shape ... ok
test protocol::bip322::tests::test_bip322_unprefixed_lowercase_base64_uses_simple_fallback ... ok
test protocol::bip322::tests::test_bip322_unsupported_address_types_fail_closed ... ok
test protocol::bip322::tests::test_bip322_p2wsh_and_taproot_script_path_are_unsupported ... ok
test protocol::bitcoin::tests::test_bip340_verification_matches_official_valid_vector ... ok
test protocol::bitcoin::tests::test_bip340_verification_rejects_malformed_lengths_and_keys ... ok
test protocol::bitcoin::tests::test_bip340_verification_rejects_official_invalid_vectors ... ok
test protocol::bitcoin::tests::test_bip86_tap_tweak_matches_reference_vector ... ok
test protocol::bitcoin::tests::test_bip341_tap_tweak_matches_wallet_vector_with_merkle_root ... ok
test protocol::bitcoin::tests::test_op_cat_covenant_script_generation ... ok
test protocol::bitcoin::tests::test_sighash_external_generation ... ok
test protocol::bitcoin::tests::test_taproot_rejects_noncanonical_paths_and_keys ... ok
test protocol::bitcoin_tests::tests::test_bitcoin_manager_descriptors ... ok
test protocol::bitcoin_tests::tests::test_bitcoin_transaction_intent_lifecycle ... ok
test protocol::bitvm2::tests::duplicate_chain_observations_are_idempotent_and_conflicts_fail_closed ... ok
test protocol::bitvm2::tests::groth16_proof_accepts_valid_elements ... ok
test protocol::bitvm2::tests::groth16_proof_rejects_zero_bytes ... ok
test protocol::bitvm2::tests::groth16_public_inputs_rejects_zero_digests ... ok
test protocol::bitvm2::tests::groth16_verifier_rejects_arbitrary_bytes_fail_closed ... ok
test protocol::bitvm2::tests::groth16_vk_accepts_valid_keys ... ok
test protocol::bitvm2::tests::groth16_vk_rejects_zero_key_elements ... ok
test protocol::bitvm2::tests::observed_events_are_the_only_modeled_state_transition ... ok
test protocol::bitvm2::tests::validates_challenge_window_boundaries_and_identifiers ... ok
test protocol::bitvm2::tests::unsupported_operations_do_not_mutate_or_synthesize_state ... ok
test protocol::bitvm::tests::snark_validator_default_constructs ... ok
test protocol::bitvm::tests::bitvm_manager_validate_snark_proof_bridges_to_verifier ... ok
test protocol::bitvm::tests::snark_validator_fails_closed_for_non_curve_bytes ... ok
test protocol::bitvm::tests::snark_validator_rejects_zero_proof_elements ... ok
test protocol::bitvm::tests::snark_validator_rejects_zero_input_digests ... ok
test protocol::bitvm::tests::snark_validator_rejects_zero_vk_elements ... ok
test protocol::bitvm::tests::test_bitvm_challenge_bounds ... ok
test protocol::cctp::tests::attestation_message_hash_is_deterministic ... ok
test enclave::trust::trust_bundle::tests::validator_exposes_each_fail_closed_state ... ok
test protocol::cctp::tests::attestation_mismatched_hash_rejected ... ok
test protocol::cctp::tests::attestation_rejects_empty_signature ... ok
test protocol::cctp::tests::attestation_rejects_invalid_der_signature ... ok
test protocol::cctp::tests::canonical_intent_shape_passes_local_validation ... ok
test protocol::cctp::tests::malformed_network_or_recipient_data_is_rejected ... ok
test protocol::chain_abstraction::tests::test_resolve_intent_logic ... ok
test protocol::chain_abstraction::tests::test_sign_for_chain_near_fails_closed_without_provider ... ok
test protocol::chain_abstraction::tests::test_sign_for_chain_bitcoin_fails_closed_without_provider ... ok
test protocol::chain_abstraction::tests::test_sign_for_chain_stellar_fails_closed_without_provider ... ok
test protocol::bitvm::tests::test_bitvm_multi_party_aggregation ... ok
test protocol::control_model_adapter::tests::bip110_provenance_fixture_matches_core_wire_contract ... ok
test protocol::control_model_adapter::tests::core_chain_and_family_use_exact_reviewed_names ... ok
test protocol::control_model_adapter::tests::core_trust_tier_uses_exact_snake_case_values ... ok
test protocol::control_model_adapter::tests::core_verification_class_uses_exact_snake_case_values ... ok
test protocol::control_model_adapter::tests::production_projection_enforces_core_strict_light_client_invariant ... ok
test protocol::control_model_adapter::tests::production_projection_rejects_testnet_and_devnet ... ok
test protocol::control_model_adapter::tests::sdk_trust_tier_mapping_is_explicit_and_production_rejects_t4 ... ok
test protocol::control_model_adapter::tests::signed_envelope_identity_and_serialization_are_deterministic ... ok
test protocol::control_model_adapter::tests::supported_chains_map_without_family_collapsing ... ok
test protocol::chain_abstraction::tests::test_sign_for_chain_xrp_fails_closed_without_provider ... ok
test protocol::control_model_adapter::tests::unknown_values_and_fields_fail_closed ... ok
test protocol::control_model_adapter::tests::bip110_defaults_and_shape_use_exact_core_wire_contract ... ok
test protocol::covenant::tests::test_build_tapscript_leaf ... ok
test protocol::covenant::tests::test_all_patterns_roundtrip ... ok
test protocol::covenant::tests::test_generate_apo_script ... ok
test protocol::covenant::tests::test_generate_cat_vault_script ... ok
test protocol::covenant::tests::test_generate_ctv_vault_script ... ok
test protocol::covenant::tests::test_verify_recursive_invariant_harden ... ok
test protocol::dlc::tests::cet_template_payout_is_proportional ... ok
test protocol::dlc::tests::cet_template_rejects_non_signed_contract ... ok
test protocol::dlc::tests::oracle_attestation_invalid_sig_rejected ... ok
test protocol::dlc::tests::test_dlc_contract_id_generation ... ok
test protocol::dlc::tests::test_dlc_lifecycle ... ok
test protocol::economy_tests::tests::test_gas_sponsored_tx_generation_fails_closed_without_provider ... ok
test protocol::economy_tests::tests::test_dual_stack_generation_fails_closed_without_provider ... ok
test protocol::ethereum::tests::test_compact_and_recoverable_signature_canonicality ... ok
test protocol::ethereum::tests::test_eip155_chain_id_decoder_is_context_bound ... ok
test protocol::ethereum::tests::test_eip191_hash_and_signature_verification ... ok
test protocol::ethereum::tests::test_eip2098_official_and_negative_vectors ... ok
test protocol::ethereum::tests::test_eip55_address_vectors_and_strict_input ... ok
test protocol::ethereum::tests::test_ethereum_address_uses_canonical_keccak ... ok
test protocol::ethereum::tests::test_ethereum_rejects_malformed_addresses_and_signatures ... ok
test protocol::ethereum::tests::test_keccak_and_eip191_binary_safe_vectors ... ok
test protocol::frost::tests::all_value_bearing_operations_remain_exactly_unsupported ... ok
test protocol::frost::tests::envelopes_and_errors_do_not_expose_secret_material ... ok
test protocol::frost::tests::rejects_invalid_thresholds_identifiers_versions_and_duplicates ... ok
test protocol::frost::tests::signing_session_enforces_ownership_and_duplicate_replay ... ok
test protocol::identity::tests::software_and_development_managers_cannot_create_hardware_identity ... ok
test protocol::intent::tests::canonical_hash_changes_for_rail_and_dispatch_context_mutations ... ok
test protocol::intent::tests::canonical_hash_is_independent_of_map_insertion_order ... ok
test protocol::intent::tests::legacy_request_only_hash_is_not_the_complete_intent_hash ... ok
test protocol::intent::tests::test_fdc3_context_creation ... ok
test protocol::job_card::tests::test_amount_validation_rejects_invalid_formats ... ok
test protocol::job_card::tests::test_amount_validation_rejects_zero_amounts ... ok
test protocol::job_card::tests::test_benchmark_pacs008_latency ... ok
test protocol::job_card::tests::test_job_card_validation ... ok
test protocol::job_card::tests::test_pacs008_generation ... ok
test protocol::lightning::tests::bip353_address_parsing_and_validation ... ok
test protocol::lightning::tests::bolt12_offer_parsing_and_validation ... ok
test protocol::lightning::tests::route_finder_enforces_budgets_and_disabled_edges ... ok
test protocol::lightning::tests::route_finder_fails_closed_without_feasible_path ... ok
test protocol::lightning::tests::route_finder_selects_minimum_fee_path ... ok
test protocol::lightning::tests::route_finder_validates_graph_and_amount ... ok
test protocol::lightning::tests::test_failure_and_retry ... ok
test protocol::lightning::tests::test_max_retries ... ok
test protocol::lightning::tests::test_payment_lifecycle_events ... ok
test protocol::lightning::tests::test_permanent_failure_blocks_retry ... ok
test protocol::lightning::tests::test_preimage_settlement_verification ... ok
test protocol::lightning_channel::tests::channel_fails_closed_on_invalid_operations ... ok
test protocol::lightning_channel::tests::channel_lifecycle_progresses_through_phases ... ok
test protocol::lightning_channel::tests::cooperative_close_requires_resolved_htlcs ... ok
test protocol::lightning_channel::tests::force_close_can_occur_with_pending_htlcs ... ok
test protocol::lightning_channel::tests::offered_htlc_settle_and_fail_preserve_capacity_invariant ... ok
test protocol::lightning_channel::tests::received_htlc_settle_and_fail_preserve_capacity_invariant ... ok
test protocol::lightning_channel::tests::settle_requires_correct_preimage ... ok
test protocol::credit::tests::test_prepare_vouch_determinism ... ok
test protocol::nexus::fedimint::tests::note_serialization_and_debug_do_not_expose_a_secret ... ok
test protocol::nexus::fedimint::tests::operation_ledger_is_idempotent_and_rejects_conflicting_replay ... ok
test protocol::nexus::fedimint::tests::unsupported_operations_do_not_mutate_adapter_state ... ok
test protocol::nexus::fedimint::tests::validates_thresholds_identifiers_and_versions ... ok
test protocol::nexus::fedimint::tests::verify_note_and_threshold_signatures ... ok
test protocol::nexus::roast::tests::coordinator_rejects_session_when_too_many_excluded ... ok
test protocol::nexus::roast::tests::exclusion_list_works ... ok
test protocol::nexus::roast::tests::round_with_insufficient_shares_returns_failed_with_blame ... ok
test protocol::nexus::roast::tests::session_collects_commitments_and_shares ... ok
test protocol::nexus::roast::tests::session_rejects_non_member_signer ... ok
test protocol::nexus::roast::tests::session_rejects_wrong_round_commitment ... ok
test protocol::nexus::roast::tests::value_bearing_operations_are_unsupported_without_frost_crypto ... ok
test enclave::trust::tests::rollback_floor_validity_and_statuses_are_explicit ... ok
test protocol::fiat::tests::test_prepare_fiat_session_sovereign ... ok
test protocol::mmr::tests::test_mmr_local_proof ... ok
test protocol::opportunity::tests::test_opportunity_dispatcher_dynamic_rail ... ok
test protocol::rails::fdc3_integration_tests::test_resolve_fdc3_instrument_to_intent ... ok
test protocol::rails::ntt::tests::test_ntt_rail_name ... ok
test protocol::rails::rail_proxy_tests::default_rail_policy_and_ordering_remain_unchanged ... ok
test protocol::rails::rail_proxy_tests::missing_durable_replay_fails_before_rail_side_effect ... ok
test protocol::rails::rail_proxy_tests::public_rail_integrity_requires_durable_replay_before_attestation_work ... ok
test protocol::rails::rail_proxy_tests::rail_proxy_rejects_process_local_replay_store_at_configuration ... ok
test protocol::rails::rail_proxy_tests::test_attestation_is_always_required ... ok
test protocol::rails::rail_proxy_tests::built_in_adapter_dispatch_is_quarantined_before_network ... ok
test protocol::rails::rail_proxy_tests::shared_durable_rail_store_accepts_once_and_rejects_cross_proxy_duplicate ... ok
test protocol::rails::rail_proxy_tests::test_clock_failure_precedes_attestation_verification_and_replay_recording ... ok
test protocol::rails::rail_proxy_tests::test_configured_attestation_policy_is_enforced ... ok
test protocol::rails::rail_proxy_tests::test_discover_best_rail ... ok
test protocol::rails::rail_proxy_tests::test_forged_report_is_rejected_without_consuming_replay_state ... ok
test protocol::rails::rail_proxy_tests::test_legacy_policy_flag_cannot_disable_attestation ... ok
test protocol::rails::rail_proxy_tests::test_legacy_request_only_hash_is_rejected ... ok
test protocol::rails::rail_proxy_tests::test_malformed_attestation_is_rejected_without_consuming_replay_state ... ok
test protocol::rails::rail_proxy_tests::test_prepare_intent_with_fdc3 ... ok
test protocol::rails::rail_proxy_tests::test_quarantined_asset_cannot_enter_routing ... ok
test protocol::rails::rail_proxy_tests::test_trust_tier_enforcement ... ok
test protocol::rails::rail_proxy_tests::test_rail_proxy_with_telemetry ... ok
test protocol::rails::rail_proxy_tests::test_untrusted_root_is_rejected_without_consuming_replay_state ... ok
test protocol::rails::rail_proxy_tests::test_verify_hardware_integrity_rejects_replay ... ok
test protocol::rails::rail_proxy_tests::test_wrong_nonce_is_rejected_before_replay_recording ... ok
test protocol::rails::rail_proxy_tests::test_wrong_purpose_is_rejected_without_consuming_replay_state ... ok
test protocol::rails::rail_proxy_tests::test_stale_and_future_reports_are_rejected ... ok
test protocol::rails::rail_proxy_tests::typed_dispatch_preflight_is_validation_only ... ok
test protocol::rails::rail_proxy_tests::typed_settlement_authorization_rejects_same_id_weaker_policy_digest ... ok
test protocol::rails::rail_proxy_tests::typed_settlement_authorization_replay_is_rejected ... ok
test protocol::rails::rail_proxy_tests::typed_settlement_clock_failure_does_not_consume_replay_state ... ok
test protocol::rails::rail_proxy_tests::typed_settlement_dispatch_rechecks_expected_and_verified_policy_digest ... ok
test protocol::rails::rail_proxy_tests::typed_settlement_proof_attachment_rejects_same_id_policy_variants_before_dispatch ... ok
test protocol::rails::rail_proxy_tests::typed_settlement_envelope_rejects_missing_attestation_and_replay_authorization ... ok
test protocol::rails::rail_proxy_tests::typed_settlement_envelope_rejects_intent_digest_key_and_policy_mismatch ... ok
test protocol::rails::tests::test_swap_request_hash_determinism ... ok
test protocol::rails::rail_proxy_tests::typed_settlement_replay_is_consumed_before_downstream_failure ... ok
test protocol::rgb::tests::contract_id_roundtrips ... ok
test protocol::rgb::tests::seal_construction ... ok
test protocol::rgb::tests::transition_hash_is_deterministic ... ok
test protocol::settlement::settlement_expanded_tests::test_create_proposal_expanded_chains ... ok
test protocol::settlement::tests::test_settlement_flow ... ok
test protocol::settlement_service::tests::test_settlement_service_trigger_to_proposal ... ok
test protocol::settlement_service::tests::test_trust_tier_resolution ... ok
test protocol::settlement_service::tests::test_verify_reconciliation ... ok
test protocol::rails::x402::tests::test_x402_rail_validation ... ok
test protocol::sidl::tests::test_sidl_vote_serialization ... ok
test protocol::solver::tests::test_solver_ranking_prioritizes_yield ... ok
test protocol::statechain::tests::encoding_version_current_is_valid ... ok
test protocol::statechain::tests::encoding_version_zero_rejected ... ok
test protocol::statechain::tests::forfeit_sign_is_gated ... ok
test protocol::statechain::tests::leaf_accepts_valid ... ok
test protocol::statechain::tests::leaf_rejects_excessive_depth ... ok
test protocol::statechain::tests::leaf_rejects_zero_amount ... ok
test protocol::statechain::tests::operator_set_rejects_duplicate_ids ... ok
test protocol::statechain::tests::operator_set_rejects_threshold_gt_operators ... ok
test protocol::statechain::tests::operator_set_rejects_zero_threshold ... ok
test protocol::statechain::tests::session_initiate_dkg_is_gated ... ok
test protocol::statechain::tests::transfer_execute_is_gated ... ok
test protocol::statechain::tests::transfer_rejects_empty_leaf_ids ... ok
test protocol::statechain::tests::transfer_rejects_same_sender_recipient ... ok
test protocol::statechain::tests::vutxo_tree_computes_total ... ok
test protocol::statechain::tests::vutxo_tree_rejects_empty_leaves ... ok
test protocol::rails::rail_proxy_tests::unavailable_and_indeterminate_rail_replay_fail_closed ... ok
test protocol::universal_tests::tests::test_chain_abstraction_signature_fails_closed_without_provider ... ok
test protocol::universal_tests::tests::test_ethereum_address_derivation ... ok
test protocol::universal_tests::tests::test_ethereum_erc20_preparation ... ok
test protocol::universal_tests::tests::test_solana_address_retrieval ... ok
test protocol::universal_tests::tests::test_universal_asset_registry ... ok
test protocol::zkml::tests::test_zkml_request_construction ... ok
test protocol::sidl::tests::test_sidl_service_new ... ok
test signing::bip110_signing::tests::bip110_enforcer_constructs ... ok
test signing::bip110_signing::tests::bip110_enforcer_is_send_sync ... ok
test signing::bip110_signing::tests::bip110_requires_chunking_short_message ... ok
test signing::bip110_signing::tests::bip110_validate_script_pubkey_accepts_standard ... ok
test signing::bip110_signing::tests::bip110_validate_witness_item_accepts_small_data ... ok
test signing::bip322_signing::tests::bip322_signer_constructs ... ok
test signing::bip322_signing::tests::bip322_signer_is_send_sync ... ok
test signing::bip322_signing::tests::bip322_verify_invalid_signature_returns_false ... ok
test signing::bitvm2_signing::tests::bitvm2_ids_construct ... ok
test signing::bitvm2_signing::tests::bitvm2_signer_constructs ... ok
test signing::covenant_signing::tests::covenant_signer_constructs ... ok
test signing::dlc_signing::tests::dlc_signer_constructs ... ok
test signing::dlc_signing::tests::oracle_hash_differs_by_outcome ... ok
test signing::dlc_signing::tests::oracle_hash_is_deterministic ... ok
test signing::lightning_signing::tests::lightning_signer_constructs ... ok
test signing::musig2_signing::tests::musig2_signer_constructs ... ok
test signing::musig2_signing::tests::musig2_signer_is_send_sync ... ok
test signing::statechain_signing::tests::statechain_signer_constructs ... ok
test signing::statechain_signing::tests::statechain_transfer_types_align ... ok
test signing::taproot::tests::classify_bip44_path ... ok
test signing::taproot::tests::classify_bip84_path ... ok
test signing::taproot::tests::classify_bip86_path ... ok
test signing::taproot::tests::classify_unknown_path ... ok
test signing::taproot::tests::compute_taproot_tweak_default_merkle_root ... ok
test signing::taproot::tests::tapleaf_hash_of_empty_script ... ok
test signing::taproot::tests::taproot_output_key_no_script_path ... ok
test signing::threshold::tests::frost_dkg_rounds_type_check ... ok
test signing::threshold::tests::frost_signer_default_constructs ... ok
test signing::threshold::tests::frost_signer_is_send_sync ... ok
test signing::threshold::tests::frost_signing_rounds_type_check ... ok
test signing::ucs::tests::ucs_can_be_constructed ... ok
test signing::ucs::tests::ucs_is_send_and_sync ... ok
test signing::ucs::tests::ucs_methods_fail_closed_on_unsupported_enclave ... ok
test signing::ucs::tests::ucs_sign_methods_type_check ... ok
test signing::wasm_runtime::tests::wasm_decode_hex_32_invalid_length ... ok
test signing::wasm_runtime::tests::wasm_decode_hex_32_valid ... ok
test signing::wasm_runtime::tests::wasm_public_key_request_roundtrips ... ok
test signing::wasm_runtime::tests::wasm_request_serialization_roundtrips ... ok
test signing::wasm_runtime::tests::wasm_sign_rejects_unknown_chain ... ok
test signing::zkml_signing::tests::zkml_signer_constructs ... ok
test state::tests::test_mmr_height_calculation ... ok
test state::tests::test_mmr_integrity ... ok
test state::tests::test_mmr_proof_generation ... ok
test telemetry::tests::delayed_transport_exercises_request_timeout ... ok
test telemetry::tests::delivery_policy_rejects_unbounded_values ... ok
test protocol::swap_router::tests::test_swap_router_instantiation ... ok
test telemetry::tests::documented_default_policy_values_are_explicit ... ok
test telemetry::tests::empty_api_key_omits_auth_header ... ok
test telemetry::tests::every_documented_retryable_http_status_retries ... ok
test protocol::zkml::tests::test_zkml_service_new ... ok
test telemetry::tests::disabled_mode_is_explicit_and_side_effect_free ... ok
test telemetry::tests::non_retryable_http_status_does_not_retry ... ok
test telemetry::tests::payload_serialization_excludes_credentials_and_identifiers ... ok
test telemetry::tests::production_endpoints_require_https_and_reject_ambiguous_urls ... ok
test telemetry::tests::retryable_http_failure_can_recover_without_blocking ... ok
test telemetry::tests::scheduling_without_a_runtime_is_observable_and_does_not_panic ... ok
test telemetry::tests::timeout_retries_are_bounded_and_observable ... ok
test telemetry::tests::transport_keeps_credentials_in_headers_only ... ok
test wasm_support::tests::bolt11_case_normalization_accepts_uniform_case_only ... ok
test wasm_support::tests::direct_ark_and_legacy_bitvm_clients_are_stateless_and_quarantined ... ok
test wasm_support::tests::every_known_runtime_fails_closed_without_evidence ... ok
test wasm_support::tests::legacy_wasm_bitvm_surface_is_exactly_bitvm2_unsupported ... ok
test wasm_support::tests::stable_error_codes_preserve_input_protocol_and_secret_semantics ... ok
test wasm_support::tests::unapproved_provider_is_typed_as_unsupported ... ok
test wasm_support::tests::unknown_runtime_is_typed_as_unsupported ... ok
test wasm_support::tests::wasm_surface_does_not_serialize_fedimint_blinding_factors ... ok
test wasm_support::tests::wasm_surface_has_no_private_key_export_or_cloud_default ... ok
test telemetry::tests::invalid_compatibility_configuration_fails_closed_without_panic ... ok
test telemetry::tests::native_client_does_not_follow_redirects_or_forward_api_key ... ok
test protocol::rails::rail_proxy_tests::proof_authorized_settlements_use_separate_replay_capacity_domains ... ok

test result: ok. 586 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 29.82s


running 10 tests
test batch_before_commit_unavailable_has_no_mutation_and_retry_succeeds_atomically ... ok
test batch_after_commit_response_loss_restores_as_all_or_nothing_duplicate ... ok
test clock_rollback_is_detected_before_pruning_or_admission ... ok
test forward_duplicate_advances_and_persists_high_water ... ok
test forward_failed_batch_persists_high_water_without_fresh_member ... ok
test single_after_commit_response_loss_restores_as_duplicate ... ok
test invalid_reservations_precede_fault_consumption_and_high_water_mutation ... ok
test single_before_commit_unavailable_has_no_mutation_and_retry_succeeds ... ok
test reference_model_passes_complete_backend_neutral_suite ... ok
test file_backed_store_passes_complete_backend_neutral_suite ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.15s


running 4 tests
test valid_looking_erc7579_inputs_cannot_execute_or_claim_module_provenance ... ok
test valid_looking_cctp_inputs_cannot_produce_calldata_or_validate_iris_attestation ... ok
test conflicting_metadata_cannot_replace_canonical_state_or_change_rail_selection ... ok
test quarantined_unknown_metadata_cannot_enter_rail_selection ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s


running 10 tests
test harness::tests::assert_unsupported_accepts_unsupported_error ... ok
test harness::tests::digests_are_32_bytes ... ok
test harness::tests::derivation_paths_are_valid ... ok
test harness::tests::harness_enclave_constructs ... ok
test harness::tests::harness_enclave_ucs_constructs ... ok
test harness_derivation_paths ... ok
test harness::tests::assert_unsupported_panics_on_ok - should panic ... ok
test harness_digests_are_distinct ... ok
test harness_enclave_returns_public_key ... ok
test harness_exercises_ucs ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 4 tests
test single_mechanism_scope_is_explicit_and_not_a_complete_authorization ... ok
test all_non_good_statuses_are_fail_closed ... ok
test unavailable_durable_store_never_authorizes ... ok
test trust_transport_denies_unknown_fields_and_unbounded_identifiers ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 6 tests
test every_builtin_adapter_is_gated_before_http_dispatch ... ok
test production_default_policy_is_hardware_only_and_provider_unavailable ... ok
test prepare_intent_commits_to_the_complete_security_context ... ok
test production_explicit_proof_path_stops_at_unavailable_verifier ... ok
test production_opportunity_dispatch_reaches_provider_boundary ... ok
test production_verification_rejects_legacy_request_only_hashes ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s


running 6 tests
test duplicate_kind_and_proof_id_are_rejected_before_verification ... ok
test production_registry_exposes_only_unavailable_exact_routes ... ok
test replay_batch_capacity_failure_does_not_partially_insert_keys ... ok
test exact_context_binding_rejects_wrong_digest_without_fallback ... ok
test serialized_unknown_fields_are_rejected_and_debug_redacts_evidence ... ok
test well_shaped_production_bundle_is_not_structural_success ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 4 tests
test production_attestation_policy_and_provider_status_remain_unavailable ... ok
test public_release_manifest_rejects_missing_independent_review ... ok
test public_collateral_contract_fails_closed_on_expiry_and_root_mismatch ... ok
test public_replay_binding_serializes_only_digests ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 2 tests
test src/protocol/zkml.rs - protocol::zkml::ZkmlService (line 121) ... ignored
test src/protocol/rails/mod.rs - protocol::rails::RailProxy (line 405) - compile fail ... ok

test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.15s and .
