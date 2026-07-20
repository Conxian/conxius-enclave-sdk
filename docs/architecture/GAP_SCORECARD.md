# Conclave SDK: Research & Implementation Gap Scorecard (v2.0.13)

## Overview
This document tracks the resolution of production-path logic, architectural gaps, and research requirements for the Conclave SDK.

The [machine-readable capability evidence](./capability-evidence.json) and generated [capability matrix](./CAPABILITY_MATRIX.md) are authoritative for the distinction between API presence, implementation, integration, independent review, and production support. A completed structural/API task below does not promote a capability to production support.

## Scorecard Criteria
- **Criticality**: [High, Medium, Low]
- **Complexity**: [High, Medium, Low]
- **Status**: [Completed, In Progress, Backlog]

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
- **Security boundary**: Hardware mocks and build-only lanes must not satisfy production trust requirements; the current status remains Beta / conditional.
- **Research Note**: Modern WASM SDK patterns favor a core crate plus a `cdylib` wrapper, but architecture guidance is not runtime or production evidence.
- **Criticality**: Medium
- **Complexity**: Medium
- **Status**: API inventory recorded; runtime/platform/secret-boundary evidence open (#200)

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
