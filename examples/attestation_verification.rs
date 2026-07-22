//! Hardware Attestation Verification Example
//!
//! This example demonstrates how to verify hardware attestation reports.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("=== Conclave SDK: Attestation Verification ===\n");

    // Trust Tiers
    println!("Trust Tiers:");
    println!("  - CloudTEE: Conditional vocabulary; provider verifier unavailable");
    println!("  - StrongBox: Conditional vocabulary; provider verifier unavailable");
    println!("  - TEE: Development/test evidence only");
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
    println!("  - High-value operations remain blocked until provider-verified CloudTEE or StrongBox support is integrated.");
    println!("  - Development tier allows testing without hardware");
    println!("  - Software tier is always blocked for production\n");

    // Freshness Check Example
    println!("Freshness Validation:");
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => {
            println!("  Trusted clock unavailable; fail closed");
            return;
        }
    };
    let attestation_time = now.saturating_sub(30); // 30 seconds ago
    let freshness_window = 60_u64;
    let is_fresh = (now - attestation_time) <= freshness_window;
    println!("  Current: {}", now);
    println!("  Attestation: {}", attestation_time);
    println!(
        "  Fresh: {} (within {}s window)\n",
        is_fresh, freshness_window
    );

    println!("Provider note: this example is functional documentation only.");
    println!("It does not verify a vendor root, provider collateral, hardware,");
    println!("KMS release, durable replay, or production readiness.\n");

    println!("Example completed successfully!");
}
