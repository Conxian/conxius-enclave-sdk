# Conclave SDK: Research & Implementation Gap Scorecard (v2.0.5)

## Overview
This document tracks the resolution of production-path logic, architectural gaps, and research requirements for the Conclave SDK v2.0.5.

## Scorecard Criteria
- **Criticality**: [High, Medium, Low]
- **Complexity**: [High, Medium, Low]
- **Status**: [Completed, In Progress, Backlog]

## Technical Resolutions (v2.0.5)

### 1. FROST Round 3 (Signature Aggregation)
- **Resolution**: Implemented hardened structural signature share aggregation in `FrostManager`.
- **Status**: Completed (v2.0.5)

### 2. Fedimint: Hardened Cryptographic Blinding
- **Resolution**: Implemented real Secp256k1-based Chaumian blinding and unblinding in `FedimintAdapter`.
- **Status**: Completed (v2.0.5)

### 3. Ark: Hardened Stateless Recovery
- **Resolution**: Hardened the V-UTXO discovery and scan logic in `ArkManager`.
- **Status**: Completed (v2.0.5)

## Technical Resolutions (v2.0.4)

### 4. Hardware Attestation: X.509 DER Parsing
- **Resolution**: Integrated `x509-cert` for structural certificate chain verification and raw pubkey extraction.
- **Status**: Completed (v2.0.4)

### 5. FDC3 Treasury Handshake: Intent Resolution
- **Resolution**: Deeply integrated `fdc3.instrument` context into `RailProxy`'s intent resolution path and verified with integration tests.
- **Status**: Completed (v2.0.4)

## Technical Resolutions (v2.0.3)

### 6. Hardened BIP-322 Verification (Full Support)
- **Resolution**: Implemented legacy (P2PKH, P2SH) and SegWit/Taproot proof-of-ownership verification.
- **Status**: Completed (v2.0.3)

## Active Gaps & Research (v2.0.6 Roadmap)

### 7. Fedimint: fedimint-client-wasm Integration
- **Gaps**: Direct integration with the upstream Fedimint Wasm client for real-world federation interaction.
- **Criticality**: Medium
- **Complexity**: High
- **Status**: Backlog

### 8. OP_CAT: Recursive Vault Verification
- **Gaps**: Full validation of script execution traces for OP_CAT-based covenants.
- **Criticality**: High
- **Complexity**: High
- **Status**: Backlog

## Research Archive
- **BIP-347 OP_CAT**: Script primitives verified in `src/protocol/covenant.rs`.
- **Universal Chain Support**: Address derivation for XRP, Stellar, and NEAR verified.
