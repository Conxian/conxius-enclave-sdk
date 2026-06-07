# Conclave SDK (lib-conclave-sdk)

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](SECURITY.md)

**Hardware-backed Bitcoin Application Infrastructure.**

The Conclave SDK provides a high-integrity root-of-trust for the autonomous Bitcoin economy. It binds hardware security modules (Android StrongBox, Apple Secure Enclave, Cloud TEE) to Bitcoin L1, L2, and Lightning rails.

## Our Vision: The Sovereign Bridge

We are building the infrastructure to transition the world from **Legacy Rails** (Visa, Mastercard, Centralized Banks) to **Sovereign Rails** (Bitcoin, sBTC, Lightning). The Conclave SDK acts as the secure bridge, ensuring that even when liquidity enters from a traditional source, it is immediately secured by hardware-backed policies and cryptographic proofs.

## Key Primitives

### 1. Hardware-Isolated Signing & Attestation
- Native ECDSA and Schnorr signing within hardware enclaves.
- Mandatory **DeviceIntegrityReport** for high-value operations.
- **Zero Secret Egress**: Private keys never leave the hardware.

### 2. The Sovereign Handshake
A two-phase coordination protocol (Prepare -> Sign -> Broadcast) that ensures user intent is verified by hardware before a transaction is committed to any rail.

### 3. Aligned Financial Primitives
- **Sovereign Fiat**: Privacy-preserving and hardware-attested fiat-to-bitcoin on-ramps.
- **Industrial Intent (x402)**: Autonomous, machine-to-machine payments for B2B and ERP systems.
- **Ubuntu Credit**: Hardware-attested social trust and group vouching, replacing legacy credit scores.

## Status

**Version 0.2.0 (Bleeding Edge)**.
Utilizing a modern stack: `bitcoin 0.33.0-beta`, `bdk_wallet 3.0.0`, `secp256k1 0.32.0-beta.2`.

### Driver and attestation status

- The repository currently includes software-backed development drivers for local integration and interface validation.
- Software-backed drivers are **not** production hardware drivers and must not be presented as StrongBox-, Secure Enclave-, or CloudTEE-enforced security.
- Production deployments must use hardware-bound drivers that emit hardened attestation levels such as `TEE`, `StrongBox`, or `CloudTEE`.
- High-value flows should treat software attestation as non-production and fail closed unless a hardened driver is in use.

## Development

```bash
cargo build
cargo test
wasm-pack build
```

## Support

- Support: [support@conxian-labs.com](mailto:support@conxian-labs.com)
- Security: [security@conxian-labs.com](mailto:security@conxian-labs.com)

## License

MIT
