# lib-conclave-sdk

The core Rust SDK for Conclave, providing cross-platform hardware enclave abstractions for Android StrongBox, Apple Secure Enclave, and Headless (WASM) environments.

## Features

- **Hardware-Backed Security**: Interfaces with secure hardware (StrongBox/TEE) for key generation and signing.
- **Multi-Chain Support**: Native support for ECDSA (EVM, Bitcoin, Stacks) and Schnorr (Taproot, RGB, BitVM).
- **MuSig2 Orchestration**: Simplified API for M-of-N multi-signature protocols.
- **Stacks Support**: Specialized handlers for Stacks message signing and transaction payload formatting.
- **WebAssembly Bindings**: Fully compatible with WASM for browser-based secure key management.

## Architecture

The SDK is organized into three main layers:

1.  **Enclave Layer** (`src/enclave`): Abstracted hardware interfaces. The `CoreEnclaveManager` provides a deterministic headless implementation for WASM.
2.  **Protocol Layer** (`src/protocol`): Multi-chain and multi-sig logic (MuSig2, Stacks).
3.  **Binding Layer** (`src/wasm_bindings.rs`): Clean JavaScript/TypeScript interfaces for high-level integration.

## Usage (WASM)

```typescript
import { ConclaveWasmClient } from 'lib-conclave-sdk';

const client = new ConclaveWasmClient();
client.set_session_key("my_pin", "salt_hex_value");

const signature = client.sign_payload(
    "message_hash_hex",
    "m/44'/5757'/0'/0/0",
    "key_id"
);
```

## Development

Requires Rust 1.81+ (Edition 2024).

```bash
cargo build
cargo test
```
