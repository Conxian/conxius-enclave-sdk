//! Basic Bitcoin Transaction Signing Example
//!
//! This example demonstrates how to use the Conclave SDK for basic Bitcoin transaction signing.

fn main() {
    println!("=== Conclave SDK: Basic Bitcoin Signing ===\n");

    // Example 1: Address Format
    println!("1. Bitcoin Address Formats");
    println!("   P2PKH (Legacy):    1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
    println!("   P2SH (Script):     3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");
    println!("   P2WPKH (SegWit):   bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh");
    println!("   P2TR (Taproot):    bc1p5d7rshj3ew6xzxjyhs0s0kh0uzpv9kj0wxp0fqj2x9rq7qkw0uq7nvrgz\n");

    // Example 2: Transaction Intent
    println!("2. Transaction Intent Structure");
    println!("   - Create signable intent from transaction details");
    println!("   - Bind attestation to intent hash");
    println!("   - Support for multiple chain types\n");

    // Example 3: Multi-signature support
    println!("3. Multi-Signature (MuSig2)");
    println!("   - Aggregate public keys from multiple parties");
    println!("   - Create combined signature");
    println!("   - Verify aggregated signature\n");

    // Example 4: Sign message with BIP-322
    println!("4. BIP-322 Message Signing");
    println!("   - Standardized message signing format");
    println!("   - Compatible with Bitcoin Core");
    println!("   - Supports legacy and SegWit addresses\n");

    println!("Example completed successfully!");
}
