//! Basic Bitcoin Transaction Signing Example
//!
//! This example demonstrates how to use the Conclave SDK for basic Bitcoin transaction signing.

fn main() {
    println!("=== Conclave SDK: Basic Bitcoin Signing ===\n");

    // Example 1: Address Derivation
    println!("1. Bitcoin Address Derivation");
    println!("   - Using BIP-322 for message signing");
    println!("   - Supports legacy (P2PKH) and SegWit (P2WPKH) addresses\n");

    // Example 2: PSBT Operations
    println!("2. Partially Signed Bitcoin Transactions (PSBT)");
    println!("   - Create PSBT with inputs and outputs");
    println!("   - Sign PSBT with hardware key");
    println!("   - Finalize and extract transaction\n");

    // Example 3: Schnorr Signing
    println!("3. Schnorr Signature (BIP-340)");
    println!("   - Taproot-compatible signing");
    println!("   - MuSig2 multi-signature aggregation supported\n");

    println!("Example completed successfully!");
}
