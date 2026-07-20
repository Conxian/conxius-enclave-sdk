//! WASM Integration Example
//!
//! This example demonstrates how to use the Conclave SDK from JavaScript/WebAssembly.

fn main() {
    println!("=== Conclave SDK: WASM Integration ===\n");

    // Available WASM Clients
    println!("Available WASM Clients:");
    println!("  ✓ ConclaveWasmClient (main entry)");
    println!("  ✓ ark() - Ark vTXO operations");
    println!("  ✓ bitvm() - BitVM2 challenges");
    println!("  ✓ bitvm2() - BitVM2 orchestrator");
    println!("  ✓ fedimint() - Federation operations");
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
    println!("  // Ark operations");
    println!("  // Approved provider integrations are not enabled by this release.");
    println!("  // Future clients will expose public-key/signing capabilities only.");
    println!("  const publicKey = arkClient.derive_vutxo_public_key(0);");
    println!();
    println!("  // BitVM2 challenge");
    println!("  const bitvm2 = client.bitvm2();");
    println!("  const status = bitvm2.get_status(commitmentId);\n");

    // Build Instructions
    println!("Build Instructions:");
    println!("  wasm-pack build --release --target bundler");
    println!("  wasm-pack build --release --target nodejs");
    println!("  wasm-pack build --release --target web\n");

    println!("Example completed successfully!");
}
