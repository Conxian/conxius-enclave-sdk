# Conclave SDK: Research & Implementation Gap Scorecard (v0.2.6)

## Overview
This document tracks missing production-path logic, architectural gaps, and research requirements for the Conclave SDK v0.2.6 "Universal Settlement" release.

## Scorecard Criteria
- **Criticality**: [High, Medium, Low]
- **Complexity**: [High, Medium, Low]
- **Status**: [Pending, Researching, Implementation, Completed]

## Technical Gaps

### 1. Swap Opportunity Execution (Dynamic Rail Selection)
- **File**: `src/protocol/opportunity.rs`
- **Gap**: `OpportunityPayload::Swap` requires a hardcoded rail.
- **Requirement**: Implement dynamic rail selection based on trust tier, fees, and liquidity discovery.
- **Criticality**: High
- **Complexity**: Medium
- **Status**: Completed
- **Owner**: Jules

### 2. FDC3 Corporate Treasury Handshake Integration
- **File**: `src/protocol/rails/mod.rs`, `src/protocol/intent.rs`
- **Gap**: `Fdc3Context` exists but is not consumed by `RailProxy`.
- **Requirement**: Integrate `Fdc3Context` into the intent preparation flow to support corporate treasury workflows.
- **Criticality**: Medium
- **Complexity**: Low
- **Status**: Completed
- **Owner**: Jules

### 3. Solana/NEAR Hardware Attestation Verification
- **File**: `src/enclave/attestation.rs`
- **Gap**: Certificate chain verification is simulated for Ed25519-based chains.
- **Requirement**: Implement actual Ed25519 attestation proof verification for Solana and NEAR.
- **Criticality**: High
- **Complexity**: High
- **Status**: Researching
- **Owner**: Enclave Team

### 4. Stacks & Cosmos Address Derivation
- **File**: `src/protocol/chain_abstraction.rs`
- **Gap**: Derivation logic for Stacks and Cosmos Hub (ATOM) falls back to placeholder addresses.
- **Requirement**: Implement canonical address derivation for Stacks (c32) and Cosmos (bech32).
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
| **FDC3 Treasury Mapping** | Standardizing corporate intents for cross-chain settlement. | High | 80 |
| **P2P Settlement Hooks** | Integrating Bisq/Boltz hooks for direct P2P liquidity paths. | Medium | 65 |
