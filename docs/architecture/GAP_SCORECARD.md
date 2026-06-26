# Conclave SDK: Research & Implementation Gap Scorecard (v0.2.8)

## Overview
This document tracks missing production-path logic, architectural gaps, and research requirements for the Conclave SDK v0.2.8 "Universal Settlement" release.

## Scorecard Criteria
- **Criticality**: [High, Medium, Low]
- **Complexity**: [High, Medium, Low]
- **Status**: [Pending, Researching, Implementation, Completed]

## Technical Gaps

### 1. BitVM2 Multi-Party Aggregation
- **File**: `src/protocol/bitvm.rs`
- **Gap**: Current BitVM manager only handles individual challenge signing.
- **Requirement**: Implement MuSig2-based Taproot tree aggregation for multi-party verification.
- **Reference**: [BitVM2: Bridging Bitcoin to Everywhere](https://bitvm.org/bitvm2.pdf)
- **Criticality**: High
- **Complexity**: High
- **Status**: Completed
- **Owner**: Jules

### 2. Ark Stateless Recovery Scan
- **File**: `src/protocol/ark.rs`
- **Gap**: V-UTXO derivation exists, but the recovery scan logic is missing.
- **Requirement**: Implement a multi-threaded recovery scanner that re-derives keys and checks with the Ark ASP.
- **Reference**: [Ark Protocol Specification](https://ark-protocol.org/)
- **Criticality**: High
- **Complexity**: Medium
- **Status**: Implementation
- **Owner**: Jules

### 3. ERC-7683 Solver Selection Algorithm
- **File**: `src/protocol/rails/mod.rs`
- **Gap**: `discover_best_rail` uses simple trust tier filtering.
- **Requirement**: Implement a competitive bidding/ranking algorithm for solver selection based on speed and yield.
- **Reference**: [ERC-7683: Cross-Chain Intent Standard](https://erc7683.org/)
- **Criticality**: Medium
- **Complexity**: Medium
- **Status**: Completed
- **Owner**: Jules

### 4. OP_CAT Recursive Covenants (CON-1303)
- **File**: `src/protocol/bitcoin.rs`
- **Gap**: Missing primitives for OP_CAT-based covenant construction.
- **Requirement**: Research and implement helpers for recursive covenants using OP_CAT.
- **Reference**: [BIP-347: OP_CAT in Tapscript](https://github.com/bitcoin/bips/blob/master/bip-0347.mediawiki)
- **Criticality**: High
- **Complexity**: High
- **Status**: Completed
- **Owner**: Jules

### 5. FROST Threshold Signatures (CON-1302)
- **File**: `src/protocol/musig2.rs` (or new file)
- **Gap**: Only MuSig2 is implemented; FROST is required for non-interactive threshold signing.
- **Requirement**: Implement FROST threshold signature manager.
- **Reference**: [IETF RFC 9591: FROST](https://datatracker.ietf.org/doc/rfc9591/)
- **Criticality**: High
- **Complexity**: High
- **Status**: Researching
- **Owner**: Jules

### 6. Fedimint Community Liquidity Adapter (CON-1304)
- **File**: `src/protocol/nexus/fedimint.rs` (New)
- **Gap**: Missing integration with Fedimint federated mints.
- **Requirement**: Research fedimint-sdk and implement an adapter for community-governed liquidity.
- **Reference**: [Fedimint Developer Docs](https://developers.fedimint.org/)
- **Criticality**: Medium
- **Complexity**: High
- **Status**: Researching
- **Owner**: Botshelo Mokoka

## Research Backlog

| Topic | Description | Priority | Score | Reference |
|-------|-------------|----------|-------|-----------|
| **Ark Stateless Recovery** | Blake2s-based V-UTXO derivation and recovery scan for stateless wallets. | High | 98 | Ark Protocol |
| **BitVM2 Aggregation** | Multi-party taproot tree aggregation for recursive SNARK verification. | High | 92 | BitVM2 Whitepaper |
| **OP_CAT Covenants** | Recursive covenants for advanced L2 scaling and vaults. | High | 88 | BIP-347 |
| **FROST Threshold** | Institutional-grade multi-sig with standard Schnorr outputs. | High | 85 | RFC 9591 |
| **Fedimint Integration** | Community-governed liquidity pools via federated mints. | Medium | 75 | Fedimint SDK |
| **ERC-7683 Solver Selection** | Competitive bidding algorithms for cross-chain intent fulfillment. | Medium | 78 | ERC-7683 |

## Completed Gaps (v0.2.7 Archive)
- **Solana/NEAR Hardware Attestation Verification**: Implemented Ed25519-based cert chain verification.
- **Universal Chain Support: XRP & Stellar**: Implemented address derivation and signing for XRP and Stellar.
