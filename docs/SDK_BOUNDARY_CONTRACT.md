# SDK Boundary Contract (CON-628)

This document defines the module boundaries and interface contracts for the Conclave SDK, ensuring a clean separation between core security logic and application-level (Wallet/Gateway) concerns.

## 1. Core Module Boundaries

### A. Signing Core (Hardware Enforcer)
- **Scope**: Key generation, derivation, signing (ECDSA/Schnorr), and hardware attestation.
- **Interface**: `EnclaveManager` trait.
- **Boundary**: No awareness of transaction semantics beyond signing hashes and verifying nonces.
- **Constraint**: **Zero Secret Egress**. Private keys never leave this boundary.

### B. Routing Orchestration (Intent Layer)
- **Scope**: Pathfinding logic, intent construction, and liquidity rail selection.
- **Interface**: `FiatRouterService`, `A2pRouterService`, `RailProxy`.
- **Boundary**: Consumes `Signing Core` to sign generated intents.
- **Constraint**: Stateless. Does not persist user balance or state; strictly handles transformation and broadcast.

### C. Chain Adapters (Protocol Layer)
- **Scope**: Chain-specific encoding (Bitcoin Taproot, Stacks, EVM, Solana).
- **Interface**: `AssetRegistry`, `Chain` enum, `TaprootManager`.
- **Boundary**: Decoupled from specific liquidity rails. Provides the "language" for cross-chain interaction.

## 2. Interface Contracts (WASM/Binding Layer)

The `ConclaveWasmClient` serves as the canonical entry point for external integrators.

### In-Scope (SDK Goals)
- Cryptographic identity management.
- Multi-chain transaction signing.
- Hardware-backed attestation reporting.
- Cross-chain swap orchestration (Sovereign Handshake).
- ZKML and PSI shared services.

### Out-of-Scope (Wallet/UX Concerns)
- **UI State**: The SDK does not manage transaction history, contact lists, or "active" wallet state.
- **Balance Tracking**: The SDK does not cache or track account balances; it provides the signing logic to move them.
- **Secret Recovery UI**: Biometric or PIN prompt UIs are handled by the consumer application, using SDK callbacks.

## 3. Extensibility Model
- Partners add new liquidity rails by implementing the `SovereignRail` trait in `src/protocol/rails/`.
- New chains are added to the `AssetRegistry` and `Chain` enum in `src/protocol/asset.rs`.
