# Conclave SDK: Research & Implementation Gap Scorecard (v2.0.6)

## Overview
This document tracks the resolution of production-path logic, architectural gaps, and research requirements for the Conclave SDK v2.0.6.

## Scorecard Criteria
- **Criticality**: [High, Medium, Low]
- **Complexity**: [High, Medium, Low]
- **Status**: [Completed, In Progress, Backlog]

## Technical Resolutions (v2.0.6)

### 1. OP_CAT: Recursive Vault Verification
- **Resolution**: Implemented structural verification for BIP-347 recursive invariants in `CovenantManager`.
- **Status**: Completed (v2.0.6)

### 2. Fedimint: Multi-Federation Support
- **Resolution**: Refactored `FedimintAdapter` to support a registry of active federations and validated note signatures across multiple origins.
- **Status**: Completed (v2.0.6)

### 3. Ark: Hardened Recovery Scan
- **Resolution**: Implemented safety boundaries, gap limit validation, and improved error handling for stateless V-UTXO scans in `ArkManager`.
- **Status**: Completed (v2.0.6)

## Technical Resolutions (v2.0.5)

### 4. FROST Round 3 (Signature Aggregation)
- **Resolution**: Implemented hardened structural signature share aggregation in `FrostManager`.
- **Status**: Completed (v2.0.5)

### 5. Fedimint: Hardened Cryptographic Blinding
- **Resolution**: Implemented real Secp256k1-based Chaumian blinding and unblinding in `FedimintAdapter`.
- **Status**: Completed (v2.0.5)

## Active Gaps & Research (v2.0.7 Roadmap)

### 6. Fedimint: fedimint-client-wasm Integration
- **Gaps**: Direct integration with the upstream Fedimint Wasm client for real-world federation interaction.
- **Criticality**: Medium
- **Complexity**: High
- **Status**: Backlog

### 7. Ark: Round 2 (vTXO tree construction)
- **Gaps**: Implementation of virtual TXO tree construction for multi-party exits.
- **Criticality**: Medium
- **Complexity**: High
- **Status**: Backlog

## Research Archive
- **BIP-347 OP_CAT**: Script primitives verified in `src/protocol/covenant.rs`.
- **Universal Chain Support**: Address derivation for XRP, Stellar, and NEAR verified.
