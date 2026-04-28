# Conclave SDK (`lib-conclave-sdk`)

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](SECURITY.md)
[![CI Status](https://github.com/Conxian/lib-conclave-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/Conxian/lib-conclave-sdk/actions/workflows/ci.yml)
[![v1.9.2 Aligned](https://img.shields.io/badge/Mainnet--Readiness-v1.9.2--Aligned-green.svg)](docs/SYSTEM_ALIGNMENT.md)

The canonical hardware security interface for the Conxian ecosystem.

## Purpose

The **Conclave SDK** provides a high-integrity integration surface for hardware-backed security. It abstracts complex hardware enclave operations (Android StrongBox, Apple Secure Enclave, Cloud TEE) into a unified API for key management, attestation, and cross-chain signing.

## Status & Categorization

- **Portfolio Category**: Security Infrastructure / SDK
- **Product State**: Beta / Active Development (`0.x`)
- **Mainnet Readiness**: v1.9.2 Aligned. (See [REMEDIATION.md](docs/REMEDIATION.md) for details)

## Key Features

- **Hardware-Backed Security**: Standardized interface for key generation and signing within secure hardware.
- **Hardware Attestation**: Cryptographic proof of device integrity, required for high-value rail operations.
- **Sovereign Handshake**: Non-custodial signing protocol ensuring **Zero Secret Egress** for all cross-chain swaps.
- **Business Management**: Hardware-backed identity and cryptographic attribution for partners.
- **Asset Registry**: Centralized metadata and validation for cross-chain assets (BTC, ETH, STX, etc.).
- **Multi-Chain Support**: Native support for ECDSA (EVM, Bitcoin, Stacks) and Schnorr (Taproot, RGB, BitVM).
- **WebAssembly Bindings**: Fully compatible with WASM for browser and mobile integrations.

## Architecture

The SDK is organized into three main layers:

1. **Enclave Layer** (`src/enclave`): Hardware abstractions (`EnclaveManager`).
2. **Protocol Layer** (`src/protocol`): Multi-chain logic, Business Management, and Sovereign Rails.
3. **Binding Layer** (`src/wasm_bindings.rs`): High-level JavaScript/TypeScript interfaces.

## Usage (WASM)

```typescript
import { ConclaveWasmClient } from 'lib-conclave-sdk';

const client = new ConclaveWasmClient();
// ... configuration and usage ...
```

## Development

Requires Rust 1.94+ (Edition 2024).

```bash
# Build core Rust SDK
cargo build

# Run unit tests
cargo test

# Build WASM bindings (requires wasm-pack)
wasm-pack build
```

## Governance & Support

- **Ownership**: Managed by [Conxian-Labs](https://github.com/Conxian).
- **Guidelines**: See [GOVERNANCE.md](GOVERNANCE.md) for architectural boundaries and release discipline.
- **Security**: Report vulnerabilities to `security@conxian.com`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
