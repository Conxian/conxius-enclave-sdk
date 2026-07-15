//! WASM Integration Example
//!
//! This example demonstrates how to use the Conclave SDK from JavaScript/WebAssembly.

fn main() {
    println!("=== Conclave SDK: WASM Integration ===\n");

    // Available WASM Clients
    println!("Available WASM Clients:");
    println!("  - ConclaveWasmClient (main entry)");
    println!("  - ark() - Ark vTXO operations");
    println!("  - bitvm() - BitVM2 challenges");
    println!("  - fedimint() - Federation operations");
    println!("  - ethereum() - ERC-20 transfers");
    println!("  - solana() - SPL transfers");
    println!("  - lightning() - LND operations");
    println!("  - solver() - Intent resolution");
    println!("  - zkml() - ZK proofs\n");

    // JavaScript Usage
    println!("JavaScript Usage:");
    println!("  const client = new ConclaveWasmClient('enclave-url');");
    println!("  const arkClient = client.ark();");
    println!("  const vutxoKey = arkClient.derive_vutxo_key(seedHex, index);\n");

    // Build Instructions
    println!("Build Instructions:");
    println!("  wasm-pack build --target web");
    println!("  wasm-pack build --target nodejs\n");

    println!("Example completed successfully!");
}
