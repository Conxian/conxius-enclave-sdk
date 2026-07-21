# Conclave SDK: Improvement Proposals (v2.0.7)

> **Historical proposal archive:** The protocol implementation statements below
> describe earlier structural work. Current FROST, Fedimint, Ark, and BitVM2
> status is the typed foundation-plus-quarantine boundary in
> [`PROTOCOL_IMPLEMENTATION_ROADMAP.md`](./PROTOCOL_IMPLEMENTATION_ROADMAP.md);
> value-bearing operations remain unsupported.

## 1. Fedimint: Invite Code & Wasm Readiness (Hardened)
**Context**: `FedimintAdapter` (v2.0.7) implements federation joining via invite codes.
**Improvements**:
- Implemented `join_federation` to derive federation state from standard invite codes.
- Hardened Secp256k1 cryptographic operations for production-grade blinding.
**Next Steps**:
- Fully integrate the `fedimint-client-wasm` crate for real-world Peer-to-Peer interaction.
- Support OOB (Out-of-Band) note parsing in the Nexus adapter.

## 2. Ark: vTXO Tree Construction (v2.0.7)
**Context**: `ArkManager` (v2.0.7) supports binary transaction tree construction.
**Improvements**:
- Implemented `construct_vtxo_tree` for multi-party exit path verification.
- Updated recovery scan semantics for better reliability.
**Next Steps**:
- Integrate with BitVM2 optimistic challenge-response orchestrator.
- Implement ASP-side proof generation for vTXO tree inclusions.

## 3. BitVM2: Multi-Party Aggregation (Hardened)
**Context**: `BitVmManager` (v2.0.6) supports signature aggregation for the 364-tap verification floor.
**Improvements**:
- Integrated MuSig2 for non-interactive partial signature aggregation over Taproot trees.
- Hardened tap boundary validation for "Fail-Closed" security.
**Next Steps**:
- Implement automated script chunking for Groth16 proof verification on Bitcoin.
- Support recursive SNARK aggregation for L2 state compression.

## 4. Universal Chain Support (v2.0.6 Hardened)
**Context**: `ChainAbstractionService` supports production-grade address derivation for BTC, ETH, SOL, STX, COSMOS, XRP, and STELLAR.
**Improvements**:
- Verified hardware-secure signing paths for Ed25519-based chains.
- Hardened asset registry with universal regional stablecoins.
**Next Steps**:
- Expand support to NEAR, Aptos, and Sui.
- Implement cross-chain fee estimation via Conxian Gateway.

## 5. Hardware Attestation (X.509 Hardened)
**Context**: `DeviceIntegrityReport` (v2.0.4) enforces structural X.509 verification.
**Improvements**:
- Integrated `x509-cert` crate for DER parsing.
- Implemented raw public key extraction from certificates.
**Next Steps**:
- Implement full certificate path validation (signatures).
- Integrate with external Attestation Services (e.g., Android Key Attestation).
