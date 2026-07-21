# Conclave SDK Examples

This directory contains example code demonstrating how to use the Conclave SDK.

## Running Examples

```bash
# Run all examples
cargo run --example basic_signing
cargo run --example attestation_verification
cargo run --example ark_vutxo_derivation
cargo run --example fedimint_federation
cargo run --example multi_chain_signing
cargo run --example wasm_integration

# WASM examples require wasm-pack
wasm-pack build --release --target bundler
```

## Examples

| Example | Description |
|---------|-------------|
| `basic_signing.rs` | Basic Bitcoin transaction signing |
| `attestation_verification.rs` | Hardware attestation verification |
| `ark_vutxo_derivation.rs` | Ark typed boundary and fail-closed quarantine |
| `fedimint_federation.rs` | Fedimint typed boundary and secret-safe quarantine |
| `multi_chain_signing.rs` | Multi-chain signing examples |
| `wasm_integration.rs` | WASM bindings usage |

## Dependencies

Examples depend on the local SDK. Ensure you're in the workspace root.

## WASM Clients Available

The SDK provides WASM bindings for:
- **Ark**: Typed vTXO/exit boundary; value-bearing operations return `ProtocolUnsupported`
- **BitVM2**: Typed observation/commitment boundary; posting and challenge operations return `ProtocolUnsupported`
- **Fedimint**: Typed federation/note boundary; raw secrets never cross the API and value-bearing operations return `ProtocolUnsupported`
- **Ethereum**: ERC-20 transfers
- **Solana**: SPL transfers
- **Lightning**: LND operations
- **ZKML**: Zero-knowledge proof generation
- **DLC**: Discreet Log Contracts
- **Settlement**: Multi-chain settlement service
- **Stablecoin**: Orchestrator for stablecoins

---

*Part of Conclave SDK v2.0.12*
