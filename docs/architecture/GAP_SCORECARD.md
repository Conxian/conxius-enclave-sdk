# Conclave SDK: Research & Implementation Gap Scorecard (v2.0.13)

## Overview
This document tracks the resolution of production-path logic, architectural gaps, and research requirements for the Conclave SDK.

The [machine-readable capability evidence](./capability-evidence.json) and generated [capability matrix](./CAPABILITY_MATRIX.md) are authoritative for the distinction between API presence, implementation, integration, independent review, and production support. A completed structural/API task below does not promote a capability to production support.

## Normalized 2026-07-22 shortlist

The scored shortlist below is a prioritization aid, not an evidence grade or
support decision. Scores preserve the 75-point planning scale used for issue
#240 and its follow-on lanes.

| Gap ID | Scope | Score | Dependency phase |
| --- | --- | ---: | --- |
| `G240-TC` | Provider-neutral trust/collateral contract | 73 | Phase A — contract and negative evidence |
| `G240-RP` | Durable replay contract and uncertainty semantics | 66 | Phase A — contract; backend selection follows |
| `G-DOC` | Canonical documentation and evidence normalization | 65 | Phase A — current residual gates |
| `G200-WASM` | WASM secret boundary and runtime/platform evidence | 61 | Phase B — provider/runtime evidence |
| `G241-AP` | Android KeyMint/StrongBox authorization and Play Integrity | 59 | Phase B — Android provider lane |
| `G198-AM` | Asset metadata and account-model containment | 57 | Phase B — protocol/provider lane |
| `G242-NP` | AWS Nitro attestation and KMS release boundary | 56 | Phase B — Nitro provider lane |
| `G199-REL` | Reproducible release, SBOM, and provenance evidence | 54 | Phase C — exact artifact gate |
| `G198-AA` | Account abstraction boundary | 53 | Phase B — protocol/provider lane |
| `G198-CCTP` | CCTP attestation and cross-chain authorization | 52 | Phase B — protocol/provider lane |
| `G-live-AP` | Live Android/Nitro runtime evidence | 45 | Phase B — provider/runtime evidence |
| `G202-REV` | Independent review and release acceptance | 44 | Phase C — reviewed artifact gate |

## Exact weighted scoring formula and rubric

The shortlist score is reproducible from eight integer dimension values on a
1–5 scale. The exact formula is:

```text
score = 3×security
      + 3×production blocker
      + 2×dependency unlock
      + 2×evidence availability
      + 2×implementation confidence
      + 1×effort efficiency
      + 1×external dependency burden
      + 1×documentation contradiction risk
```

The weights sum to 15, so the maximum score is 75. A value of 5 means the
dimension is strongest for prioritization; a value of 1 means weakest. The
dimensions use this rubric:

- **Security**: 5 is a direct trust, authorization, or secret-boundary risk;
  1 is advisory or low-impact.
- **Production blocker**: 5 blocks a production gate or value-bearing path;
  1 does not block a release decision.
- **Dependency unlock**: 5 unlocks several downstream lanes; 1 is mostly
  isolated.
- **Evidence availability**: 5 has local deterministic code/tests/docs
  evidence; 1 requires unavailable external evidence.
- **Implementation confidence**: 5 has a precise bounded design and direct
  regression coverage; 1 is exploratory.
- **Effort efficiency**: 5 is low effort with high leverage; 1 is expensive
  or narrowly useful.
- **External dependency burden**: 5 is local/software-only and reproducible;
  1 depends on external providers, hardware, deployment, or unavailable
  services.
- **Documentation contradiction risk**: 5 has a high risk that stale claims
  could misstate support or authorization; 1 has little contradiction risk.

The following dimension values produce every score in the table above. The
last column shows the formula result and is the source for the displayed
score, rather than an informal ranking:

| Gap ID | Sec | Blocker | Unlock | Evidence | Confidence | Efficiency | External (5=local/software) | Doc risk | Formula result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `G240-TC` | 5 | 5 | 5 | 5 | 5 | 3 | 5 | 5 | 73 |
| `G240-RP` | 5 | 5 | 4 | 4 | 4 | 4 | 4 | 4 | 66 |
| `G-DOC` | 4 | 4 | 4 | 5 | 5 | 4 | 4 | 5 | 65 |
| `G200-WASM` | 4 | 5 | 4 | 3 | 4 | 4 | 4 | 4 | 61 |
| `G241-AP` | 5 | 4 | 4 | 2 | 4 | 4 | 4 | 4 | 59 |
| `G198-AM` | 4 | 4 | 4 | 3 | 4 | 3 | 4 | 4 | 57 |
| `G242-NP` | 5 | 4 | 4 | 2 | 3 | 3 | 4 | 4 | 56 |
| `G199-REL` | 4 | 4 | 3 | 4 | 3 | 3 | 3 | 4 | 54 |
| `G198-AA` | 4 | 4 | 4 | 2 | 3 | 4 | 3 | 4 | 53 |
| `G198-CCTP` | 4 | 4 | 4 | 2 | 3 | 3 | 3 | 4 | 52 |
| `G-live-AP` | 5 | 4 | 2 | 1 | 2 | 2 | 2 | 4 | 45 |
| `G202-REV` | 4 | 4 | 3 | 1 | 2 | 3 | 2 | 3 | 44 |

Phase A closes only the provider-neutral contract slice represented by
`G240-TC`, `G240-RP`, and the documentation portion of `G-DOC`. It does not
close provider, runtime, backend, independent-review, release, or production
support gates. The dependency order is **contract → provider/runtime → durable
deployment → exact artifact/review → scoped support decision**.

> **2026-07-21 status correction:** Entries below that describe FROST,
> Fedimint, Ark, or BitVM2 work as implemented or complete are historical
> structural/API records. They are superseded for current support decisions by
> the typed foundation-plus-quarantine boundary and
> [`PROTOCOL_IMPLEMENTATION_ROADMAP.md`](./PROTOCOL_IMPLEMENTATION_ROADMAP.md).
> All four protocol capabilities remain `Production: No`.

## Scorecard Criteria
- **Criticality**: [High, Medium, Low]
- **Complexity**: [High, Medium, Low]
- **Status**: [Completed, In Progress, Backlog]

## Technical Resolutions (2026-07-22, PR #237)

### 1. Proof-policy integrity and provider research boundary
- **Resolution**: Added a versioned, domain-separated digest for the complete exact proof policy; carried the request-derived expected digest through response, rail authorization, and final dispatch; refactored test fixtures to satisfy locked clippy; and added public-safe provider research/specification artifacts plus conservative capability rows.
- **Status**: Composer and typed-boundary containment evidence is implemented and tested. TLS, WebAuthn/FIDO, TPM, Android, Apple, Intel, AMD, AWS, ARM, collateral/revocation, provider/runtime, distributed replay, independent review, and release-artifact evidence remain unsupported; see [`PROOF_POLICY_SPEC.md`](./PROOF_POLICY_SPEC.md) and [`PR-237_HARDWARE_ATTESTATION_RESEARCH_2026-07-22.md`](../audits/PR-237_HARDWARE_ATTESTATION_RESEARCH_2026-07-22.md).

## Technical Resolutions (2026-07-22, CON-1543 / GitHub #240)

### Provider-neutral collateral, replay, and release-evidence seams
- **Resolution**: Added typed provider identity and digest-only collateral metadata with strict time, root-set, schema, verifier, and revocation validation; added a canonical secret-free replay binding covering provider, subject, mechanism, nonce, operation, purpose, policy, key, and evidence; defined an atomic durable-replay store contract with a clearly non-production in-memory adapter; and added exact-scope release-evidence manifest validation.
- **Status**: Structural contracts and focused fail-closed tests are implemented. No provider roots, provider authenticator, collateral authority, durable backend, replay owner, promotion authority, independent review, release artifact, or production-support decision is established. Existing `ReplayGuard` remains process-local and is not replaced. See [`TRUST_REPLAY_RELEASE_CONTRACTS.md`](./TRUST_REPLAY_RELEASE_CONTRACTS.md).

### G240-TC final-head review closure
- **Resolution**: Separated Phase A single-mechanism trust normalization and durable replay from complete proof-bundle authorization with `TrustScope::SingleMechanism`, scoped result/identity/authorization types, no public provider-extension seam, and a trusted-clock context copy before provider observation and canonicalization. Added scope and forged future/past caller-time regressions.
- **Status**: The provider-neutral contract, negative tests, and fail-closed composition boundary remain separate from canonical all-required authorization. This does not provide provider, hardware, backend, independent-review, release-artifact, or production-support evidence.

## Technical Resolutions (v2.0.13)

### 1. BIP-110: Compliance & Alignment (Issue #179)
- **Resolution**: Fully implemented the `bip110_compliant` feature flag, integrated BIP-110 validation rules into the BIP-322 construct-to-sign flow, hardened serialization with standard compact size (VarInt) encoding to prevent raw truncation hazards, and added compliance tests verifying Ark/BitVM2 commitment segmentation.
- **Status**: API/structural implementation recorded (v2.0.13); canonical Bitcoin verification, integration, review, and artifact evidence remain open in #196 and #202.

## Technical Resolutions (v2.0.12)

### 1. BitVM2: Static Tree Root Helper
- **Resolution**: Made `calculate_tree_root` method static since it doesn't use `self`, improving code clarity and enabling static dispatch optimization.
- **Status**: Structural code cleanup completed (v2.0.12); this is not BitVM2 protocol, proof, integration, or production evidence.

## Technical Resolutions (v2.0.11)

### 1. Hardware Attestation Comprehensive Test Suite
- **Resolution**: Added comprehensive 25-test suite in `src/enclave/hardware_attestation_tests.rs` covering:
  - Trust Tier Verification (CloudTEE, StrongBox, TEE, Software blocking)
  - Freshness & Replay Protection (stale attestation, nonce validation, replay guard)
  - Cryptographic Verification (invalid signatures, untrusted roots, hardware hardening)
  - Trust Enforcement (production vs development trust classification)
  - Edge Cases (empty signatures, chain validation, concurrent access)
- **Status**: Simulation/unit evidence completed (v2.0.11); vendor-backed integration and production caller enforcement remain open in #195 and #202.

### 2. CI/CD: Node.js 24 Compliance
- **Resolution**: Updated all GitHub Actions to Node.js 24 compatible versions (v4/v5):
  - `actions/checkout@v4`
  - `actions/upload-artifact@v5`
  - `actions/download-artifact@v5`
  - `actions/attest-build-provenance@v4.1.1`
- **Status**: Historical workflow maintenance completed (v2.0.11); reproducible toolchain, release, scan, SBOM, provenance, and exact-artifact evidence remains open in #199.

### 3. WASM: Arc<RefCell> for BitVm2Orchestrator
- **Resolution**: Fixed WASM mutable borrow errors in `WasmBitVm2Orchestrator` using `Arc<RefCell<>>`
- **Status**: Build/structural fix completed (v2.0.11); runtime, platform, secret-boundary, and hardware evidence remains open in #200.

### 4. Documentation: Version Alignment
- **Resolution**: Fixed version staleness across AGENTS.md, README.md, TRACKING.md, REPOSITORY_ANALYSIS.md, and GAP_SCORECARD.md
- **Status**: Completed (v2.0.11)

## Technical Resolutions (v2.0.8)

### 1. FROST: DKG status correction
- **Resolution**: `src/protocol/frost.rs` currently provides structural/hash placeholder checks only. It is not production FROST cryptography and does not provide RFC 9591-compatible DKG, secure share storage, or real signature aggregation. See [`docs/guides/FROST_TREASURY_INTEGRATION.md`](../guides/FROST_TREASURY_INTEGRATION.md) for the implementation and acceptance plan.
- **Status**: Open — design/runbook published; implementation and independent audit required

## Technical Resolutions (v2.0.7)

### 2. Fedimint: Invite Code & Wasm Readiness
- **Resolution**: Implemented the `join_federation` API via invite code and aligned primitives for the existing WASM surface.
- **Status**: API/structural completion only (v2.0.7); real threshold blinding, provider interoperability, independent review, and production support remain open in #197 and #202.

### 3. Ark: vTXO Tree Construction
- **Resolution**: Implemented binary transaction tree logic in `ArkManager` for multi-party exit API paths.
- **Status**: Structural/API completion only (v2.0.7); live Ark interoperability, settlement evidence, and independent review remain open in #197 and #202.

## Technical Resolutions (v2.0.6)

The Ark, Fedimint, and related BitVM entries below record API/structural implementation history only. They do not close the protocol-conformance, live integration, independent-review, or production-support gates in the capability evidence record.

### 4. OP_CAT: Recursive Vault Verification
- **Resolution**: Implemented structural verification for BIP-347 recursive invariants in `CovenantManager`.
- **Status**: Completed (v2.0.6)

### 5. Fedimint: Multi-Federation Support
- **Resolution**: Refactored `FedimintAdapter` to support a registry of active federations and validated note signatures across multiple origins.
- **Status**: Completed (v2.0.6)

### 6. Ark: Hardened Recovery Scan
- **Resolution**: Implemented safety boundaries, gap limit validation, and improved error handling for stateless V-UTXO scans in `ArkManager`.
- **Status**: Completed (v2.0.6)

## Active Gaps & Research (v2.0.13+ Roadmap)

### 7. Fedimint: Direct fedimint-client-wasm crate integration
- **Gaps**: Adding the actual crate dependency and bridging the Wasm client to the Nexus adapter.
- **Research Note**: Fedimint now uses threshold BLS blind signatures (BLS12-381) replacing single-key signing. DLEQ proofs provide additional privacy guarantees.
- **Criticality**: Medium
- **Complexity**: High
- **Status**: Backlog

### 8. Ark: BitVM2 Challenge Orchestration
- **Gaps**: Integration of Ark forfeit transactions with the BitVM2 optimistic challenge-response tree.
- **Research Note**: BitVM2 uses permissionless challengers with existential honesty (1-of-n). Q4 2025 roadmap targets <$50 fees via BitVM3 optimizations. Ecosystem adoption by Citrea, BOB, Bitlayer, Botanix.
- **Criticality**: High
- **Complexity**: Urgent
- **Status**: Backlog

### 9. Fedimint: Cryptographic Blinding Integration
- **Gaps**: Integrating real cryptographic blinding and unblinding of e-cash notes in the Fedimint client adapter.
- **Research Note**: Modern Fedimint uses threshold BLS with DLEQ proofs for issuance validation.
- **Criticality**: Medium
- **Complexity**: High
- **Status**: Backlog

### 10. WASM API coverage versus runtime evidence
- **API coverage**: The required WASM sub-client API rows are explicit in [`capability-evidence.json`](./capability-evidence.json), including Lightning, Settlement Service, Solver, Swap Router, ZKML, DLC, Stablecoin, Job Card/ISO20022, MMR, Opportunity, Business, and A2P.
- **Runtime/platform evidence**: Browser, Node, bundler, worker, provider, hardware, secret-boundary, and unsupported-platform evidence is not established by compilation or binding presence; track it in [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200).
- **Security boundary**: WASM private-key export and default localhost/software construction are removed; hardware mocks and build-only lanes must not satisfy production trust requirements; the current status remains Beta / conditional.
- **Research Note**: Modern WASM SDK patterns favor a core crate plus a `cdylib` wrapper, but architecture guidance is not runtime or production evidence.
- **Criticality**: Medium
- **Complexity**: Medium
- **Status**: API inventory and fail-closed secret-boundary policy recorded; runtime/platform/provider/hardware evidence remains open (#200)

### 11. ZKML Module Enhancement (NEW)
- **Gaps**: `zkml.rs` exists but may need integration with modern tooling.
- **Research Note**: ezkl supports TensorFlow/Keras to SNARK circuits. Succinct SP1 enables general-purpose zkVM for Bitcoin. SNARKs: ~192 bytes, 3ms verify. STARKs: 45-200KB, quantum-resistant.
- **Criticality**: Low
- **Complexity**: High
- **Status**: Backlog (Monitor)

## Research Archive
- **BIP-347 OP_CAT**: Script primitives verified in `src/protocol/covenant.rs`.
- **vTXO Trees**: Binary tree structure for Ark exits implemented in `src/protocol/ark.rs`.
- **TEE Attestation**: Intel SGX DCAP, AMD SEV-SNP, ARM PSA patterns documented in `RESEARCH_LOG.md`.
- **BitVM2**: Permissionless challenger model, optimistic rollup architecture documented in `RESEARCH_LOG.md`.
- **Fedimint Evolution**: Threshold BLS blind signatures, DLEQ proofs documented in `RESEARCH_LOG.md`.
