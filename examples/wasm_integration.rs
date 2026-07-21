//! WASM Integration Example
//!
//! This example demonstrates how to use the Conclave SDK from JavaScript/WebAssembly.

fn main() {
    println!("=== Conclave SDK: WASM Integration ===\n");

    // Available WASM Clients
    println!("WASM boundary clients (API presence is not support):");
    println!("  • ConclaveWasmClient (main entry; provider-gated)");
    println!("  • ark() - typed Ark boundary; value-bearing methods fail closed");
    println!("  • bitvm() - existing BitVM boundary; evidence remains required");
    println!("  • bitvm2() - constructor/provider-gated; operations fail closed");
    println!("  • fedimint() - secret-safe boundary; value-bearing methods fail closed");
    println!("  ✓ ethereum() - ERC-20 transfers");
    println!("  ✓ solana() - SPL transfers");
    println!("  ✓ lightning() - LND operations");
    println!("  ✓ solver() - Intent resolution");
    println!("  ✓ zkml() - ZK proofs");
    println!("  ✓ dlc() - DLC contracts");
    println!("  ✓ mmr() - Merkle Mountain Range");
    println!("  ✓ settlement() - Settlement service");
    println!("  ✓ stablecoin() - Stablecoin orchestrator\n");

    // JavaScript Usage
    println!("JavaScript Usage:");
    println!("  // The legacy URL constructor now fails closed; it never creates CloudEnclave.");
    println!("  // Use check_runtime_support() before loading a provider-backed artifact.");
    println!("  ConclaveWasmClient.check_runtime_support('browser');");
    println!();
    println!("  // Ark operations remain quarantined and return a typed unsupported error.");
    println!("  // No seed, note secret, synthetic tree, or signature is returned.");
    println!("  arkClient.derive_vutxo_public_key(0); // ProtocolUnsupported");
    println!();
    println!("  // BitVM2 construction is provider-gated and challenge methods fail closed.");
    println!("  client.bitvm2(); // Unsupported provider until exact evidence exists\n");

    // Build Instructions
    println!("Build Instructions:");
    println!("  wasm-pack build --release --target bundler");
    println!("  wasm-pack build --release --target nodejs");
    println!("  wasm-pack build --release --target web\n");

    println!("Example completed: boundary behavior only; no protocol operation succeeded.");
}
