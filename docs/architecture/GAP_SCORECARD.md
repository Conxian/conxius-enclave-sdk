# Conclave SDK: Research & Implementation Gap Scorecard (v2.0.8)

## Overview
This document tracks the resolution of production-path logic, architectural gaps, and research requirements for the Conclave SDK.

## Scorecard Criteria
- **Criticality**: [High, Medium, Low]
- **Complexity**: [High, Medium, Low]
- **Status**: [Completed, In Progress, Backlog]

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

## Active Gaps & Research (v2.0.8 Roadmap)

### 7. Fedimint: Direct fedimint-client-wasm crate integration
- **Gaps**: Adding the actual crate dependency and bridging the Wasm client to the Nexus adapter.
- **Criticality**: Medium
- **Complexity**: High
- **Status**: Backlog

### 8. Ark: BitVM2 Challenge Orchestration
- **Gaps**: Integration of Ark forfeit transactions with the BitVM2 optimistic challenge-response tree.
- **Criticality**: High
- **Complexity**: Urgent
- **Status**: Backlog

### 9. Fedimint: Cryptographic Blinding Integration
- **Gaps**: Integrating real cryptographic blinding and unblinding of e-cash notes in the Fedimint client adapter.
- **Criticality**: Medium
- **Complexity**: High
- **Status**: Backlog

## Research Archive
- **BIP-347 OP_CAT**: Script primitives verified in `src/protocol/covenant.rs`.
- **vTXO Trees**: Binary tree structure for Ark exits implemented in `src/protocol/ark.rs`.
