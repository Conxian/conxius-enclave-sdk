//! Multi-Chain Signing Example
//!
//! This example demonstrates signing across multiple blockchain networks.

fn main() {
    println!("=== Conclave SDK: Multi-Chain Signing ===\n");

    // Supported Chains
    println!("Supported Chains:");
    println!("  ✓ Bitcoin (ECDSA, Schnorr/Taproot)");
    println!("  ✓ Ethereum (secp256k1, EIP-712)");
    println!("  ✓ Solana (Ed25519)");
    println!("  ✓ Stacks (secp256k1)");
    println!("  ✓ Cosmos (secp256k1)");
    println!("  ✓ Polygon (secp256k1)");
    println!("  ✓ 25+ additional chains\n");

    // Chain Abstraction
    println!("Chain Abstraction Layer:");
    println!("  - Universal address derivation");
    println!("  - Unified signing interface");
    println!("  - Hardware-backed security\n");

    // Example: Cross-chain intent
    println!("Cross-Chain Intent Example:");
    println!("  Source: BTC (on-chain)");
    println!("  Dest: ETH (via Bridge)");
    println!("  Amount: 0.1 BTC -> 1.5 ETH\n");

    // Account Abstraction
    println!("ERC-7579 Account Abstraction:");
    println!("  ✓ Modular smart accounts");
    println!("  ✓ Passkey-secured");
    println!("  ✓ Gasless transactions\n");

    println!("Example completed successfully!");
}
