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
- **Gap**: `OpportunityPayload::Swap` is functional but requires hardening for multi-rail selection.
- **Requirement**: Implement dynamic rail selection based on liquidity and fees.
- **Criticality**: High
- **Complexity**: Medium
- **Status**: Implementation
- **Owner**: Jules

### 2. Exact-Out Quote Routing
- **File**: `src/protocol/swap_router.rs`
- **Gap**: Initial implementation complete.
- **Requirement**: Add caching and retry logic for volatile quote endpoints.
- **Criticality**: High
- **Complexity**: Low
- **Status**: Completed
- **Owner**: Jules

### 3. FDC3 Corporate Treasury Handshake
- **File**: `src/protocol/intent.rs`, `src/protocol/rails/mod.rs`
- **Gap**: Native FDC3 context resolver is present but not yet integrated into the `RailProxy` intent flow.
- **Requirement**: Allow `RailProxy` to accept `Fdc3Context` for automated treasury mapping.
- **Criticality**: Medium
- **Complexity**: Low
- **Status**: Researching
- **Owner**: Jules

### 4. Hardware Attestation for Non-EVM Chains
- **File**: `src/enclave/android_strongbox.rs`, `src/enclave/cloud.rs`
- **Gap**: Ed25519 signing is implemented, but specific attestation certificate chain verification for Solana/NEAR is missing.
- **Requirement**: Implement TEE-backed Ed25519 attestation proof generation and verification.
- **Criticality**: High
- **Complexity**: High
- **Status**: Researching
- **Owner**: Enclave Team

### 5. Universal Address Derivation
- **File**: `src/protocol/chain_abstraction.rs`
- **Gap**: Initial implementation complete for BTC, EVM, and SOL.
- **Requirement**: Add support for Cosmos Hub (ATOM) and Stacks address derivation.
- **Criticality**: Medium
- **Complexity**: Medium
- **Status**: Completed
- **Owner**: Jules

## Research Backlog

| Topic | Description | Priority | Score |
|-------|-------------|----------|-------|
| **BitVM2 Aggregation** | Multi-party taproot tree aggregation for recursive SNARK verification. | High | 85 |
| **Ark Stateless Recovery** | Blake2s-based V-UTXO derivation for recovery without local state. | High | 90 |
| **ERC-7683 Solver Selection** | Competitive bidding algorithms for atomic solver fulfillment. | Medium | 70 |
| **FDC3 Treasury Mapping** | Standardizing corporate intents for cross-chain settlement. | Medium | 75 |
