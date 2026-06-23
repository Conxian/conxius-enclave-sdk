# Conclave SDK: Research & Implementation Gap Scorecard (v0.2.5)

## Overview
This document tracks missing production-path logic, architectural gaps, and research requirements for the Conclave SDK v0.2.5 "Universal Settlement" release.

## Scorecard Criteria
- **Criticality**: [High, Medium, Low]
- **Complexity**: [High, Medium, Low]
- **Status**: [Pending, Researching, Implementation, Completed]

## Technical Gaps

### 1. Swap Opportunity Execution
- **File**: `src/protocol/opportunity.rs`
- **Gap**: `OpportunityPayload::Swap` returns a `RailError` placeholder.
- **Requirement**: Integrate with `RailProxy` to select a modular rail (e.g., x402) and execute the swap.
- **Criticality**: High
- **Complexity**: Medium
- **Status**: Implementation
- **Owner**: Jules

### 2. Exact-Out Quote Routing
- **File**: `src/protocol/swap_router.rs`
- **Gap**: `get_exact_out_quote` for Solana and EVM chains is unimplemented.
- **Requirement**: Implement routing to Conxian Gateway `/v1/quotes/exact-out` endpoint.
- **Criticality**: High
- **Complexity**: Medium
- **Status**: Implementation
- **Owner**: Jules

### 3. FDC3 Corporate Treasury Handshake
- **File**: `src/protocol/intent.rs`
- **Gap**: Native FDC3 context resolver is present but not yet integrated into the `RailProxy` intent flow.
- **Requirement**: Allow `RailProxy` to accept `Fdc3Context` for automated treasury mapping.
- **Criticality**: Medium
- **Complexity**: Low
- **Status**: Researching
- **Owner**: Jules

### 4. Hardware Attestation for Non-EVM Chains
- **File**: `src/enclave/android_strongbox.rs`, `src/enclave/cloud.rs`
- **Gap**: Ed25519 signing is implemented, but specific attestation certificate chain verification for Solana/NEAR is missing.
- **Requirement**: Implement TEE-backed Ed25519 attestation proof generation.
- **Criticality**: High
- **Complexity**: High
- **Status**: Researching
- **Owner**: Enclave Team

## Research Backlog

| Topic | Description | Priority |
|-------|-------------|----------|
| **BitVM2 Aggregation** | Multi-party taproot tree aggregation for recursive SNARK verification. | High |
| **Ark Stateless Recovery** | Blake2s-based V-UTXO derivation for recovery without local state. | High |
| **ERC-7683 Solver Selection** | Competitive bidding algorithms for atomic solver fulfillment. | Medium |
| **Zero-Knowledge Compliance** | ZK-proofs for OFAC/AML compliance without exposing PII. | Medium |
