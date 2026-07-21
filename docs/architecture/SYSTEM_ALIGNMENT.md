# Conclave SDK System Alignment Report (v2.0.3)

## Status: Beta / conditional; scoped canonical verification evidence only

### Universal Orchestration Architecture
1. **Multi-Chain Execution**: High-performance Rust engines using Alloy-rs and BDK for EVM and Bitcoin.
2. **Intent-Based Settlement**: ERC-7683 compliant solver selection prioritizing yield and speed.
3. **Hardware-Secure Handshake**: Mandatory TEE/StrongBox attestation for production trust tiers.
4. **Sovereign Attribution**: Business-grade cryptographic attribution and telemetry.

### Advanced Bitcoin Primitives
- **Scoped BIP-322 Simple Verification**: Native P2WPKH and native P2TR key-path cryptographic verification only. P2WSH, Taproot script-path/annex, legacy, P2SH, P2A, and future witness-version paths remain inconclusive or unsupported; Full and Proof-of-Funds verification are unsupported, and no Script/Tapscript interpreter is included.
- **FROST DKG Round 1**: Typed boundary/quarantine validation only; production RFC 9591-compatible DKG, signing, secure share storage, and aggregation are not implemented.
- **Hardened Fedimint OPR**: local blinding and structural OPR (Oblivious Proof of Reserve) for community mints.
- **BitVM2 Aggregation**: MuSig2-based Taproot tree aggregation for 364-tap verification floor.
- **Ark Stateless Recovery**: Blake2s PRF-based V-UTXO restoration from master seed.
- **OP_CAT Covenants**: BIP-347 script generation for recursive vaults.

### Universal Asset Support
- **Registry**: 30+ chains supported including Bitcoin (L1/L2), EVM, Solana, Cosmos, XRP, and Stellar.
- **Hardened Attestation**: Root-of-trust verification and mandatory hardware signaling for Solana/NEAR.
- **Institutional Handshake**: FDC3 support for treasury desk integration.

### Observability & Security
- **Telemetry**: Nexus-compatible signature hash tracking.
- **Replay Protection**: Hardware-backed replay guard for all signed intents.
- **Fail-Closed Policy**: Automated rejection of bypass-mode in production paths.

## Release Metadata
- **Canonical Name**: conxius-enclave-sdk
- **Branding**: Conclave SDK
- **Maturity**: Beta / conditional; production support is not established.
