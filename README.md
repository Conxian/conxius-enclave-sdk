# Conclave SDK (`lib-conclave-sdk`)

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](SECURITY.md)
[![CI Status](https://github.com/Conxian/lib-conclave-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/Conxian/lib-conclave-sdk/actions/workflows/ci.yml)
[![v1.9.2 Aligned](https://img.shields.io/badge/Mainnet--Readiness-v1.9.2--Aligned-green.svg)](docs/SYSTEM_ALIGNMENT.md)
[![SDK Version](https://img.shields.io/badge/SDK--Version-v0.2.0-blue.svg)](CHANGELOG.md)

**Conxian builds native application infrastructure for Bitcoin.**

> [!NOTE]
> **Versioning & Alignment**: This SDK follows [Semantic Versioning](https://semver.org/). The "v1.9.2 Aligned" status refers to its compatibility with the broader Conxian protocol and mainnet readiness standards. Current SDK version is **0.2.0**.

## Purpose

The **Conclave SDK** is the core infrastructure for building native, hardware-secure applications on Bitcoin. It provides a high-integrity interface for hardware-backed signing, policy enforcement, and transaction coordination, binding cryptographic trust anchors directly to existing Bitcoin layers (L1, Lightning, Taproot).

## Status & Categorization

- **Portfolio Category**: Security Infrastructure / SDK
- **Product State**: Beta / Active Development (`0.x`)
- **Mainnet Readiness**: v1.9.2 Aligned. (See [REMEDIATION.md](docs/REMEDIATION.md) for details)

## Architecture Position

As part of the Unified Vault SDK Pivot, the Conclave SDK is the **primary sellable primitive**. Other components in the Conxian ecosystem are positioned as supporting infrastructure:

- **conxius-wallet**: A minimal **Reference Application** used to validate SDK UX and the Sovereign Handshake. It is not intended as a retail product.
- **conxian-gateway**: **Supporting Infrastructure** for settlement orchestration and liquidity rail integration.
- **lib-conxian-core**: Home for shared protocol schemas (ISO 20022) and business registries.

## Key Features

- **Hardware-Backed Security**: Standardized interface for key generation and signing within secure hardware.
- **Hardware Attestation**: Cryptographic proof of device integrity, required for high-value rail operations.
- **Sovereign Handshake**: Native coordination protocol ensuring **Zero Secret Egress** for all cross-chain swaps.
- **Business Management**: Hardware-backed identity and cryptographic attribution for partners.
- **Asset Registry**: Centralized metadata and validation for cross-chain assets (BTC, ETH, STX, etc.).
- **Multi-Chain Support**: Native support for ECDSA (EVM, Bitcoin, Stacks) and Schnorr (Taproot, RGB, BitVM).
- **WebAssembly Bindings**: Fully compatible with WASM for browser and mobile integrations.

> [!WARNING]
> **Simulation Notice**: The default enclave drivers (`CoreEnclaveManager` and `CloudEnclave`) in this repository are software-based simulations. They report `AttestationLevel::Software` and are intended for development only. Production use requires hardware-bound drivers.

## Architecture

The SDK is organized into three main layers:

1. **Enclave Layer** (`src/enclave`): Hardware abstractions (`EnclaveManager`).
2. **Protocol Layer** (`src/protocol`): Multi-chain logic, Business Management, and Sovereign Rails.
3. **Binding Layer** (`src/wasm_bindings.rs`): High-level JavaScript/TypeScript interfaces.

## Usage

### WebAssembly (WASM)

For browser and mobile environments:

```typescript
import { ConclaveWasmClient } from 'lib-conclave-sdk';

const client = new ConclaveWasmClient(
  {
    network: "Mainnet",
    track: "Lts",
    gateway_url: "https://gateway.conxian-labs.com",
    api_key: "your-api-key"
  },
  "https://vault.conxian-labs.com", // kms_endpoint (optional)
  "https://nexus.conxian-labs.com"  // nexus_url (optional)
);

// Unlock the enclave before use
await client.unlock_enclave("user-secret", "user-salt-hex");

// Create a personal identity
const identity = await client.create_personal_identity();
console.log('Identity created:', identity.id);
```

### Rust

Add to your `Cargo.toml`:

```toml
[dependencies]
lib-conclave-sdk = { git = "https://github.com/Conxian/lib-conclave-sdk.git", branch = "master" }
tokio = { version = "1.0", features = ["full"] }
```

Basic usage:

```rust
use lib_conclave_sdk::enclave::cloud::CloudEnclave;
use lib_conclave_sdk::protocol::identity::IdentityManager;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize Cloud Enclave
    let enclave = CloudEnclave::new("https://vault.conxian-labs.com".to_string())?;

    // Initialize Identity Manager
    let identity_mgr = IdentityManager::new(Arc::new(enclave));

    // Create a new hardware-backed identity
    let profile = identity_mgr.create_identity()?;
    println!("Created identity: {}", profile.id);

    Ok(())
}
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
- **Support**: For bugs and feature requests, see [SUPPORT.md](SUPPORT.md).
- **Contributing**: We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for details on our bounty workflow.
- **Security**: Report vulnerabilities to `security@conxian-labs.com` as per our [Security Policy](SECURITY.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
