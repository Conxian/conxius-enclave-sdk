//! Hardware Attestation Verification Example
//!
//! This example demonstrates how to verify hardware attestation reports.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("=== Conclave SDK: Attestation Verification ===\n");

    // Trust Tiers
    println!("Trust Tiers:");
    println!("  - CloudTEE: Production (Intel SGX / AMD SEV-SNP) ✓");
    println!("  - StrongBox: Production (ARM PSA) ✓");
    println!("  - TEE: Development only");
    println!("  - Software: Blocked for production ✗\n");

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

    // Freshness Check Example
    println!("Freshness Validation:");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let attestation_time = now - 30; // 30 seconds ago
    let freshness_window = 60_u64;
    let is_fresh = (now - attestation_time) <= freshness_window;
    println!("  Current: {}", now);
    println!("  Attestation: {}", attestation_time);
    println!(
        "  Fresh: {} (within {}s window)\n",
        is_fresh, freshness_window
    );

    println!("Example completed successfully!");
}
