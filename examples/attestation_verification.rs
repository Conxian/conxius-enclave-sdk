//! Hardware Attestation Verification Example
//!
//! This example demonstrates how to verify hardware attestation reports.

fn main() {
    println!("=== Conclave SDK: Attestation Verification ===\n");

    // Trust Tiers
    println!("Trust Tiers:");
    println!("  - CloudTEE: Production (Intel SGX / AMD SEV-SNP)");
    println!("  - StrongBox: Production (ARM PSA)");
    println!("  - TEE: Development only");
    println!("  - Software: Blocked for production\n");

    // Verification Flow
    println!("Verification Flow:");
    println!("  1. Generate nonce (32 bytes)");
    println!("  2. Request attestation from enclave");
    println!("  3. Verify attestation signature");
    println!("  4. Validate certificate chain");
    println!("  5. Check freshness (TTL window)\n");

    // Example: Trust Tier Enforcement
    println!("Trust Tier Enforcement:");
    println!("  - High-value operations require CloudTEE or StrongBox");
    println!("  - Development tier allows testing without hardware");
    println!("  - Software tier is always blocked for production\n");

    println!("Example completed successfully!");
}
