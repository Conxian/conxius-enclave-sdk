# Conxian Nexus: Universal Blockchain & Asset Support Strategy (v2.0.0)

## Global Brand Vision
Conxian Nexus is the definitive **Universal Payment Infrastructure** for the digital-first global economy. We abstract multi-chain complexities to enable retail users and institutional merchants to interact with **all currencies, all stablecoins, and all crypto** through a unified, hardware-secure, non-custodial middleware.

## Universal Asset Registry
The `AssetRegistry` (`src/protocol/asset.rs`) has been expanded to support a vast taxonomy of assets across 30+ blockchain networks.

### Tier 1: Sovereign & Global Assets
- **Bitcoin Stack**: Native BTC, sBTC (Stacks), L-BTC (Liquid), RSK, BOB, Mezo, Babylon, Botanix, Citrea.
- **Global USD Stablecoins**: USDC (Multi-chain), USDT (Multi-chain), PYUSD (PayPal).
- **Core Ecosystem Tokens**: ETH, SOL, STX, POL, AVAX, NEAR, XRP, TRX, CELO, FTM, GNO.

### Tier 2: Universal Regional Stablecoins (Global South & Emerging Markets)
- **Africa**: ZARP (South African Rand), NGNC (Nigerian Naira).
- **Latin America**: BRLA (Brazilian Real).
- **Asia-Pacific**: JPYC/GYEN (Japanese Yen), XSGD (Singapore Dollar), KRW (South Korean Won).
- **Europe/Middle East**: EURC (Euro), GBPT (Pound), XCHF (Swiss Franc), TRYB (Turkish Lira).
- **North America**: QCAD (Canadian Dollar).

## Unified Orchestration Architecture
1. **Multi-Chain Execution (Alloy-rs & BDK)**: High-performance Rust-native engines for EVM, Bitcoin, and SVM state synchronization.
2. **Intent-Based Settlement (ERC-7683)**: Facilitates "Pay in Any Token, Settle in Target Stablecoin" flows via atomic solver fulfillment.
3. **Account Abstraction (ERC-7579)**: Provides gasless, passkey-secured modular smart accounts for a consumer-grade experience.
4. **Native Interoperability (Circle CCTP)**: Permissionless burn-and-mint for institutional USDC liquidity.

## FDC3 Corporate Treasury Handshake (v1.9.2 Alignment)
Research into FDC3 (Financial Desktop Connectivity and Collaboration Standard) integration reveals a major opportunity for Conclave to serve as the "Universal Settlement Resolver" for institutional desktops.

### Key Contexts
- **fdc3.instrument**: Standardized representation of financial assets.
- **conxian.settlement**: Proprietary extension for hardware-attested cross-chain settlement intents.

### Implementation Path
1. **Context Mapping**: Bridge FDC3 Instrument identifiers to `AssetIdentifier` in the `AssetRegistry`.
2. **Intent Orchestration**: Allow `RailProxy` to accept FDC3 payloads and resolve them into signed `SwapIntent` objects.
3. **Hardware Backing**: Ensure every FDC3-triggered settlement carries a `DeviceIntegrityReport`.

## Universal Hardware Attestation (Solana/NEAR)
For Ed25519-based chains, the attestation model must be hardened beyond the current simulation.

### Requirements
- **Certificate Chain**: Must verify against hardware-specific roots (e.g., Google StrongBox or AWS Nitro).
- **Algorithm Alignment**: Native Ed25519 signing in the enclave must produce a verifiable proof bound to the transaction hash.

## Advanced Bitcoin Primitives (v0.2.8 Research)

### BitVM2 Multi-Party Aggregation
BitVM2 requires verifying complex computations on Bitcoin. This is achieved by splitting the computation into a large number of Taproot leaves (364 for the verification floor). To scale to multiple participants, signatures for these leaves must be aggregated.
- **Mechanism**: Use MuSig2 for non-interactive key aggregation and partial signature aggregation.
- **Structure**: A Taproot tree where each leaf contains a script for a specific part of the computation, and the control block enables verification by any participant if a challenge is met.

### OP_CAT Recursive Covenants (BIP-347)
OP_CAT enables concatenating two stack elements. When combined with Schnorr signatures and Tapscript, it allows for "recursive covenants" where a transaction output can restrict how it is spent in perpetuity.
- **Use Case**: Vaults, non-custodial L2 bridges (BitVM2), and stateful smart contracts on Bitcoin.
- **Implementation**: Helpers to construct  equivalents and verify script data against transaction outputs.

### FROST (Flexible Round-Optimized Schnorr Threshold Signatures)
FROST provides a way to create Schnorr signatures with a threshold of signers (himBHsof-$) in a way that is indistinguishable from a single-party signature.
- **Benefit**: Reduced on-chain footprint and improved privacy compared to traditional multi-sig.
- **Integration**: Essential for institutional-grade orchestration in the Conclave SDK.

## Advanced Bitcoin Primitives (v0.2.8 Research)

### BitVM2 Multi-Party Aggregation
BitVM2 requires verifying complex computations on Bitcoin. This is achieved by splitting the computation into a large number of Taproot leaves (364 for the verification floor). To scale to multiple participants, signatures for these leaves must be aggregated.
- **Mechanism**: Use MuSig2 for non-interactive key aggregation and partial signature aggregation.
- **Structure**: A Taproot tree where each leaf contains a script for a specific part of the computation, and the control block enables verification by any participant if a challenge is met.

### OP_CAT Recursive Covenants (BIP-347)
OP_CAT enables concatenating two stack elements. When combined with Schnorr signatures and Tapscript, it allows for "recursive covenants" where a transaction output can restrict how it is spent in perpetuity.
- **Use Case**: Vaults, non-custodial L2 bridges (BitVM2), and stateful smart contracts on Bitcoin.
- **Implementation**: Helpers to construct `SIGHASH_EXTERNAL` equivalents and verify script data against transaction outputs.

### FROST (Flexible Round-Optimized Schnorr Threshold Signatures)
FROST provides a way to create Schnorr signatures with a threshold of signers ($t$-of-$n$) in a way that is indistinguishable from a single-party signature.
- **Benefit**: Reduced on-chain footprint and improved privacy compared to traditional multi-sig.
- **Integration**: Essential for institutional-grade orchestration in the Conclave SDK.
