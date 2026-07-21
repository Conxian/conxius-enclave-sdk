//! Ark vTXO Boundary Example
//!
//! This example demonstrates the fail-closed Ark boundary. Key derivation,
//! recovery, tree construction, and settlement signing are not implemented.

fn main() {
    println!("=== Conxius SDK: Ark vTXO Boundary ===\n");

    println!("1. Typed boundary models");
    println!("   - Versioned VTXO, outpoint, round, server, connector, and exit IDs");
    println!("   - Provider-owned handles instead of caller-supplied seed material");
    println!("   - Structural validation only; no protocol execution\n");

    println!("2. Quarantined value-bearing operations");
    println!("   - V-UTXO key derivation: ProtocolUnsupported");
    println!("   - ASP recovery scan: ProtocolUnsupported");
    println!("   - vTXO tree construction: ProtocolUnsupported");
    println!("   - Forfeit/settlement signing: ProtocolUnsupported\n");

    println!("No synthetic keys, trees, recovery results, or signatures are produced.");
}
