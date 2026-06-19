# Conclave SDK System Alignment Report (v0.2.0)

## Status: v0.2.0 Aligned

### Remediations
- **CON-371 (Principals)**: Verified that core contracts and protocols use `SP...` mainnet principals.
- **RUSTSEC-2025-0055**: Remediated by upgrading `sha2` to `0.11.0` to ensure cryptographic integrity in CI.
- **Contamination Guard**: All mock/placeholder logic in `CloudEnclave` and `RailProxy` has been replaced with functional Gateway API implementations.

### Shared Services
- **Identity (Business Manager)**: Hardware-backed partner identity generation and cryptographic attribution enforced.
- **Asset Registry**: Centralized registry for cross-chain metadata (BTC, ETH, STX, USDT, SOL, USDC, LIQUID, LIGHTNING, MEZO, BABYLON, BOTANIX, CITREA).
- **ZKML (Zero-Knowledge ML)**: Integrated `ZkmlService` for privacy-preserving compliance proofs.
- **DLC (Discreet Log Contracts)**: Added `DlcManager` structure to support non-custodial financial agreements.
- **SIDL (Sovereign Identity Layer)**: Integrated `SidlService` for governance voting and cart mandates.

### Observability & Telemetry
- **TelemetryClient**: Integrated into `RailProxy` to track signature hashes during high-value operations.
- **Observability**: `Nexus`-compatible telemetry paths implemented for auditability.

### Documentation
- All files (README.md, GOVERNANCE.md, REMEDIATION.md) updated to reflect v0.2.0 standards.
- Coding standards (No-Panic, Zeroization) strictly enforced.

### v0.2.1 Updates
- **Modular Rail Consolidation**: Unified rail implementations in `src/protocol/rails/` and ensured consistent Gateway API interaction.
- **Enhanced Test Coverage**: Added comprehensive unit tests for `IdentityManager`, `ZkmlService`, `DlcManager`, `SidlService`, and `MmrService`.
- **Shared Network Client**: Refactored all network-facing services (`Fiat`, `A2p`, `Mmr`, `ZKML`, `SIDL`) to utilize a shared `reqwest::Client` for improved performance and connection pooling.

### v0.2.2 Updates
- **Expanded Bitcoin Network Support**: Added MEZO, BABYLON, BOTANIX, and CITREA identifiers to ensure future-proof L2/scaling support.
- **Lightning Resilience Model**: Implemented the SRL-1 resilience and recovery layer for Lightning payments.
- **Mempool Orchestration**: Added Bitcoin L1 mempool policy and transaction state tracking for RBF/CPFP handling.

### v0.2.3 Updates
- **Universal Chain Support (CON-810)**: Expanded `Chain` enum and `AssetRegistry` to include Cosmos Hub (ATOM). Formalized Tier 1 chain family selection and support boundaries in architectural documentation.
- **Hardware-Backed Universal Signing**: Implemented Ed25519 signing support in `CloudEnclave` using `ed25519-dalek`, enabling hardware-attested transaction orchestration for Solana and NEAR.
- **Enhanced Lightning Resilience (CON-688)**: Refined `LightningPaymentIntent` with explicit retry limits, status finality checks, and expiration handling to improve production payment reliability.
- **WASM CI Remediation**: Optimized build configuration for `wasm32-unknown-unknown` targets, implementing intrinsic-based C library shims and async thread-safety for web environments.
