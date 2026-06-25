# Conclave SDK: Research & Implementation Gap Scorecard (v0.2.7)

## Overview
This document tracks missing production-path logic, architectural gaps, and research requirements for the Conclave SDK v0.2.7 "Universal Settlement" release.

## Scorecard Criteria
- **Criticality**: [High, Medium, Low]
- **Complexity**: [High, Medium, Low]
- **Status**: [Pending, Researching, Implementation, Completed]

## Technical Gaps

### 1. Solana/NEAR Hardware Attestation Verification
- **File**: `src/enclave/attestation.rs`
- **Gap**: Certificate chain verification was simulated for Ed25519-based chains.
- **Requirement**: Implement actual Ed25519 attestation proof verification for Solana and NEAR using hardware-specific roots.
- **Criticality**: High
- **Complexity**: High
- **Status**: Completed
- **Owner**: Jules

### 2. Universal Chain Support: XRP & Stellar
- **File**: `src/protocol/chain_abstraction.rs`
- **Gap**: Address derivation and signing logic for XRP (XRP Ledger) and Stellar (XLM) were missing.
- **Requirement**: Implement canonical address derivation for XRP (Base58Check) and Stellar (StrKey/ED25519).
- **Criticality**: High
- **Complexity**: Medium
- **Status**: Completed
- **Owner**: Jules

### 3. BitVM2 Multi-Party Aggregation
- **File**: `src/protocol/bitvm.rs`
- **Gap**: Current BitVM manager only handles individual challenge signing.
- **Requirement**: Implement MuSig2-based Taproot tree aggregation for multi-party verification.
- **Criticality**: High
- **Complexity**: High
- **Status**: Researching
- **Owner**: Jules

### 4. Ark Stateless Recovery Scan
- **File**: `src/protocol/ark.rs`
- **Gap**: V-UTXO derivation exists, but the recovery scan logic is missing.
- **Requirement**: Implement a multi-threaded recovery scanner that re-derives keys and checks with the Ark ASP.
- **Criticality**: High
- **Complexity**: Medium
- **Status**: Pending
- **Owner**: Jules

### 5. ERC-7683 Solver Selection Algorithm
- **File**: `src/protocol/rails/mod.rs`
- **Gap**: `discover_best_rail` uses simple trust tier filtering.
- **Requirement**: Implement a competitive bidding/ranking algorithm for solver selection based on speed and yield.
- **Criticality**: Medium
- **Complexity**: Medium
- **Status**: Pending
- **Owner**: Jules

## Research Backlog

| Topic | Description | Priority | Score |
|-------|-------------|----------|-------|
| **BitVM2 Aggregation** | Multi-party taproot tree aggregation for recursive SNARK verification. | High | 90 |
| **Ark Stateless Recovery** | Blake2s-based V-UTXO derivation for recovery without local state. | High | 95 |
| **ERC-7683 Solver Selection** | Competitive bidding algorithms for atomic solver fulfillment. | Medium | 75 |
| **OP_CAT Covenants** | Researching recursive covenants for L2 vault logic (CON-1303). | High | 85 |
| **FROST Threshold** | Implement research-backed threshold signatures (CON-1302). | High | 80 |
