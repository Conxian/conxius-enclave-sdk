# Conclave SDK Examples

This directory contains example code demonstrating how to use the Conclave SDK.

## Running Examples

```bash
# Run all examples
cargo run --example basic_signing
cargo run --example attestation_verification

# WASM examples require wasm-pack
wasm-pack build --target web
```

## Examples

| Example | Description |
|---------|-------------|
| `basic_signing.rs` | Basic Bitcoin transaction signing |
| `attestation_verification.rs` | Hardware attestation verification |
| `ark_vutxo_derivation.rs` | Ark vTXO key derivation |
| `fedimint_federation.rs` | Fedimint federation operations |
| `multi_chain_signing.rs` | Multi-chain signing examples |
| `wasm_integration.rs` | WASM bindings usage |

## Dependencies

Examples depend on the local SDK. Ensure you're in the workspace root.

---

*Part of Conclave SDK v2.0.9*
