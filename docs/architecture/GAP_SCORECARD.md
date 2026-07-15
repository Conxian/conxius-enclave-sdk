# Conclave SDK: Research & Implementation Gap Scorecard (v2.0.9)

## Overview
This document tracks the resolution of production-path logic, architectural gaps, and research requirements for the Conclave SDK.

## Scorecard Criteria
- **Criticality**: [High, Medium, Low]
- **Complexity**: [High, Medium, Low]
- **Status**: [Completed, In Progress, Backlog]

## Technical Resolutions (v2.0.9)

### 1. Hardware Attestation Comprehensive Test Suite
- **Resolution**: Added comprehensive 25-test suite in `src/enclave/hardware_attestation_tests.rs` covering:
  - Trust Tier Verification (CloudTEE, StrongBox, TEE, Software blocking)
  - Freshness & Replay Protection (stale attestation, nonce validation, replay guard)
  - Cryptographic Verification (invalid signatures, untrusted roots, hardware hardening)
  - Trust Enforcement (production vs development trust classification)
  - Edge Cases (empty signatures, chain validation, concurrent access)
- **Status**: Completed (v2.0.9)

## Technical Resolutions (v2.0.8)

### 1. FROST: Distributed Key Gen (DKG) Round 2 Verification Hardening
- **Resolution**: Hardened the FROST implementation in `src/protocol/frost.rs` by implementing robust validation of received DKG shares against polynomial commitments and validating matching participant identifiers.
- **Status**: Completed (v2.0.8)

## Technical Resolutions (v2.0.7)

### 2. Fedimint: Invite Code & Wasm Readiness
- **Resolution**: Implemented `join_federation` via invite code and aligned Secp256k1 primitives for `fedimint-client-wasm` compatibility.
- **Status**: Completed (v2.0.7)

### 3. Ark: vTXO Tree Construction
- **Resolution**: Implemented binary transaction tree logic in `ArkManager` for multi-party exits.
- **Status**: Completed (v2.0.7)

## Technical Resolutions (v2.0.6)

### 4. OP_CAT: Recursive Vault Verification
- **Resolution**: Implemented structural verification for BIP-347 recursive invariants in `CovenantManager`.
- **Status**: Completed (v2.0.6)

### 5. Fedimint: Multi-Federation Support
- **Resolution**: Refactored `FedimintAdapter` to support a registry of active federations and validated note signatures across multiple origins.
- **Status**: Completed (v2.0.6)

### 6. Ark: Hardened Recovery Scan
- **Resolution**: Implemented safety boundaries, gap limit validation, and improved error handling for stateless V-UTXO scans in `ArkManager`.
- **Status**: Completed (v2.0.6)

## Active Gaps & Research (v2.0.9+ Roadmap)

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

### 10. WASM Bindings Completeness Audit (NEW)
- **Gaps**: 12+ modules lack WASM bindings despite being public APIs.
- **Missing Modules**: Lightning, Settlement Service, Solver, Swap Router, ZKML, DLC, Stablecoin Orchestrator, Job Card (ISO20022), MMR, Opportunity, Business logic
- **Research Note**: Modern WASM SDK patterns favor core crate (no wasm-bindgen) + cdylib wrapper. Use wasm-bindgen-futures for async, wasm-opt -Oz for optimization.
- **Criticality**: Medium
- **Complexity**: Medium
- **Status**: Backlog

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
