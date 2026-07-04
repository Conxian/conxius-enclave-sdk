# Conclave SDK: Research & Implementation Gap Scorecard (v2.0.4)

## Overview
This document tracks the resolution of production-path logic, architectural gaps, and research requirements for the Conclave SDK v2.0.4.

## Scorecard Criteria
- **Criticality**: [High, Medium, Low]
- **Complexity**: [High, Medium, Low]
- **Status**: [Completed, In Progress, Backlog]

## Technical Resolutions (v2.0.4)

### 1. FROST Round 2 (Secret Share Distribution)
- **Resolution**: Implemented encrypted secret share generation and structural verification in `FrostManager`.
- **Status**: Completed (v2.0.4)

### 2. Hardware Attestation: X.509 DER Parsing
- **Resolution**: Integrated `x509-cert` for structural certificate chain verification and raw pubkey extraction.
- **Status**: Completed (v2.0.4)

### 3. Fedimint: Hardened Cryptographic Blinding
- **Resolution**: Transitioned to SHA-256 bound blinding factors and expanded e-cash note model for unblinded signatures.
- **Status**: Completed (v2.0.4)

### 4. FDC3 Treasury Handshake: Intent Resolution
- **Resolution**: Deeply integrated `fdc3.instrument` context into `RailProxy`'s intent resolution path and verified with integration tests.
- **Status**: Completed (v2.0.4)

## Technical Resolutions (v2.0.3)

### 5. Hardened BIP-322 Verification (Full Support)
- **Resolution**: Implemented legacy (P2PKH, P2SH) and SegWit/Taproot proof-of-ownership verification.
- **Status**: Completed (v2.0.3)

### 6. FROST DKG Round 1 Implementation
- **Resolution**: Implemented RFC 9591 Round 1 commitment and proof-of-knowledge generation.
- **Status**: Completed (v2.0.2)

### 7. Hardened Fedimint OPR
- **Resolution**: Implemented local blinding and structural Oblivious Proof of Reserve (OPR) verification.
- **Status**: Completed (v2.0.2)

### 8. Hardened Hardware Attestation
- **Resolution**: Enforced root-of-trust verification and hardware-backed signaling for TEE/StrongBox reports.
- **Status**: Completed (v2.0.2)

## Active Gaps & Research (v2.0.5 Roadmap)

### 9. FROST Round 3 (Signature Aggregation)
- **Gaps**: Final signature aggregation and verification against group public key.
- **Criticality**: High
- **Complexity**: High
- **Status**: Backlog

### 10. Fedimint: fedimint-client-wasm Integration
- **Gaps**: Direct integration with the upstream Fedimint Wasm client for real-world federation interaction.
- **Criticality**: Medium
- **Complexity**: High
- **Status**: Backlog

## Research Archive
- **BIP-347 OP_CAT**: Script primitives verified in `src/protocol/covenant.rs`.
- **Universal Chain Support**: Address derivation for XRP, Stellar, and NEAR verified.
