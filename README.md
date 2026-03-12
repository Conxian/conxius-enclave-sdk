# lib-conclave-sdk

The core Rust SDK for Conclave, providing cross-platform hardware enclave abstractions for Android StrongBox, Apple Secure Enclave, and Cloud TEE environments.

## Features

- **Hardware-Backed Security**: Interfaces with secure hardware (StrongBox/TEE) for key generation and signing.
- **Hardware Attestation**: Cryptographic proof of device integrity (StrongBox/TEE/CloudTEE) mandatory for high-value rail operations.
- **Sovereign Handshake**: Non-custodial signing protocol ensuring "Zero Secret Egress" for all cross-chain swaps.
- **Business Management**: Lifecycle and cryptographic identity for partners and affiliates with secure attribution.
- **Asset Registry**: Structured registry and validation for cross-chain assets (BTC, ETH, STX, USDT, etc.).
- **Multi-Chain Support**: Native support for ECDSA (EVM, Bitcoin, Stacks) and Schnorr (Taproot, RGB, BitVM).
- **Superior Taproot Support**: Native BIP341 tweak calculation and signing within the secure enclave.
- **MuSig2 Orchestration**: Simplified API for M-of-N multi-signature protocols.
- **Stacks Support**: Specialized handlers for Stacks message signing and transaction payload formatting.
- **WebAssembly Bindings**: Fully compatible with WASM for browser-based secure key management.

## Architecture

The SDK is organized into three main layers:

1.  **Enclave Layer** (`src/enclave`): Abstracted hardware interfaces (`EnclaveManager`). Includes `CoreEnclaveManager` (Headless/Android) and `CloudEnclave`.
2.  **Protocol Layer** (`src/protocol`): Multi-chain and multi-sig logic, Business Management, Asset Registry, and Sovereign Rails.
3.  **Binding Layer** (`src/wasm_bindings.rs`): Clean JavaScript/TypeScript interfaces for high-level integration.

## Usage (WASM)

```typescript
import { ConclaveWasmClient } from 'lib-conclave-sdk';

const client = new ConclaveWasmClient();
client.set_session_key("my_pin", "salt_hex_value");

// Register a partner
client.register_business("partner_01", "Partner Name", "0x...");

// Execute a swap with full Sovereign Handshake
const response = await client.execute_swap(
    "Changelly",
    "BTC", "BTC",
    "ETH", "ETH",
    100000,
    "0xRecipient...",
    "partner_01"
);
```

## Development

Requires Rust 1.81+ (Edition 2024).

```bash
cargo build
cargo test
```
