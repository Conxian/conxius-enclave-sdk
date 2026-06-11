# Conclave SDK

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](SECURITY.md)

**Hardware-backed Bitcoin application security primitives for the Conxian ecosystem.**

The Conclave SDK provides a high-integrity root of trust for security-sensitive wallet, signing, attestation, and policy flows. It is intended to bind hardware security modules such as Android StrongBox, Apple Secure Enclave, and cloud TEEs to Bitcoin L1, L2, and Lightning-aligned systems.

## Purpose

Provide reusable enclave-facing primitives for signing, attestation, device trust, and hardened key handling across Conxian-aligned applications and services.

## Status

**Active development.** This repository contains both security-oriented implementation work and software-backed development paths used for local integration and interface validation.

There are currently **no published GitHub releases** for this repository. Until the first formal release is published, operators and integrators should treat the codebase as evolving implementation work rather than a stable production SDK.

## Scope

This repository focuses on:

- enclave and keystore abstractions
- attestation and trust reporting interfaces
- signing primitives and key lifecycle controls
- reusable SDK surfaces for higher-level Conxian components

This repository does **not** act as a complete wallet, protocol governance surface, or public operations system.

## Relationship to the Conxian stack

- `Conxian` is the protocol and public ecosystem layer.
- `conxius-wallet` is the sovereign wallet and reference client.
- `conxian-gateway` and `conxian-nexus` provide middleware and service-side integration surfaces.
- `lib-conxian-core` provides broader shared primitives across the stack.

## Our vision: the sovereign bridge

The long-term goal is to support a transition from legacy rails to sovereign rails by making hardware-backed intent verification and protected signing reusable across higher-level products and integrations.

## Key primitives

### 1. Hardware-isolated signing and attestation
- Native ECDSA and Schnorr signing within hardware enclaves.
- Mandatory **DeviceIntegrityReport** for high-value operations.
- **Zero Secret Egress**: private keys never leave the hardware boundary.

### 2. The sovereign handshake
A two-phase coordination protocol (Prepare -> Sign -> Broadcast) intended to ensure user intent is verified by hardware before a transaction is committed to any rail.

### 3. Aligned financial primitives
- **Sovereign Fiat**: privacy-preserving and hardware-attested fiat-to-bitcoin on-ramps.
- **Industrial Intent (x402)**: autonomous machine-to-machine payments for B2B and ERP systems.
- **Ubuntu Credit**: hardware-attested social trust and group vouching, positioned as an alternative to legacy credit scoring models.

## Driver and attestation status

- The repository currently includes software-backed development drivers for local integration and interface validation.
- Software-backed drivers are **not** production hardware drivers and must not be presented as StrongBox-, Secure Enclave-, or CloudTEE-enforced security.
- Production deployments must use hardware-bound drivers that emit hardened attestation levels such as `TEE`, `StrongBox`, or `CloudTEE`.
- High-value flows should treat software attestation as non-production and fail closed unless a hardened driver is in use.

## Release discipline

- Use Semantic Versioning for formal releases.
- Publish GitHub releases with annotated tags in the form `vX.Y.Z`.
- Record release-facing changes in [CHANGELOG.md](./CHANGELOG.md).
- Follow the workflow in [RELEASING.md](./RELEASING.md).
- Keep README status language aligned with the latest release and actual driver maturity.

## Development

```bash
cargo build
cargo test
wasm-pack build
```

## Policies

- [CHANGELOG.md](./CHANGELOG.md)
- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [SECURITY.md](./SECURITY.md)
- [CODEOWNERS](./CODEOWNERS)
- [RELEASING.md](./RELEASING.md)
- [REPO_OWNERSHIP.md](./REPO_OWNERSHIP.md)
- [LICENSE](./LICENSE)

## Support

- Support: [support@conxian-labs.com](mailto:support@conxian-labs.com)
- Security: [security@conxian-labs.com](mailto:security@conxian-labs.com)

## License

MIT
