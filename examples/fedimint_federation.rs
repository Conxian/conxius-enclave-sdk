//! Fedimint Federation Boundary Example
//!
//! This example demonstrates the fail-closed Fedimint boundary. Federation
//! joins, minting, note verification, DLEQ, and threshold operations are not
//! implemented in this SDK path.

fn main() {
    println!("=== Conxius SDK: Fedimint Boundary ===\n");

    println!("1. Typed boundary models");
    println!("   - Versioned federation and provider identifiers");
    println!("   - Provider-owned opaque note/blinding handles");
    println!("   - Idempotent operation IDs and redacted note metadata\n");

    println!("2. Quarantined value-bearing operations");
    println!("   - Federation registration/join: ProtocolUnsupported");
    println!("   - Minting and note verification: ProtocolUnsupported");
    println!("   - TBS/DLEQ and threshold aggregation: ProtocolUnsupported\n");

    println!("No invite code, note secret, blinding factor, network call, or synthetic signature is emitted.");
}
