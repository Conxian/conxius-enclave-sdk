## Why
The current SDK implementation lacks a formalized structure for core entities: Businesses (Partners/Affiliates), Assets (Cross-chain registry), and Modules (Enclave and Protocol extensions). This leads to fragmentation, hardcoded logic in `rails.rs`, and limited extensibility for new partners or chains. We need a unified spec-driven architecture to align with our security ethos and scale the platform.

## What Changes
- **BREAKING**: Refactor `AffiliateManager` into a more comprehensive `BusinessManager` that handles partner onboarding, permissioning, and cryptographic attribution.
- **BREAKING**: Replace string-based asset identification with a structured `AssetRegistry` that includes decimals, chain IDs, and validation rules.
- **New**: Introduce a formal `ModuleSystem` for the SDK to allow pluggable Enclaves (e.g., Apple Secure Enclave) and Protocol extensions without modifying the core crate.
- **Modification**: Update `RailProxy` to consume the new `AssetRegistry` and `BusinessManager` for transaction validation.

## Capabilities

### New Capabilities
- `business-management`: Lifecycle and cryptographic identity for partners and affiliates.
- `asset-registry`: Structured registry and validation for cross-chain assets.
- `modular-architecture`: Plugin system for enclaves and protocols.

### Modified Capabilities
- `sovereign-handshake`: Update the handshake to include business and asset context validation.

## Impact
- `src/protocol/affiliate.rs` -> `src/protocol/business.rs` (Refactor)
- `src/protocol/rails.rs` (Modified to use new registries)
- `src/enclave/mod.rs` (Updated for modularity)
- `Cargo.toml` (Potential new dependencies for registry handling)
