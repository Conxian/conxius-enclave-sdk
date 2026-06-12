# SDK Core Architecture Tasks

## 1. Core Traits and Registries
- [x] 1.1 Implement `AssetRegistry` with chain-aware metadata
- [x] 1.2 Define the `EnclaveManager` trait for hardware abstraction
- [x] 1.3 Implement `BusinessManager` with cryptographic identity support

## 2. Protocol Refactoring
- [x] 2.1 Refactor `RailProxy` to consume the `AssetRegistry`
- [x] 2.2 Update `SwapRequest` to use structured asset objects
- [x] 2.3 Refactor `AffiliateManager` into `BusinessManager`

## 3. Implementation of Plug-ins
- [x] 3.1 Implement a mock `CloudEnclave` using the new `EnclaveManager` trait
- [x] 3.2 Add a `CustomRail` extension example in `rails.rs`

## 4. Verification & Enhancement (Audit Cycle)
- [x] 4.1 Implement cryptographic verification for `BusinessAttribution`
- [x] 4.2 Integrate `TelemetryClient` into `RailProxy`
- [x] 4.3 Add automated unit tests for core protocol flows
- [x] 4.4 Align `MuSig2Orchestrator` with musig2 v0.3.1
- [x] 4.5 Verify SIP-018 Stacks message signing

## 5. Universal Support & Roadmap (Phase 1)
- [ ] 5.1 Expand `Chain` enum in `src/protocol/asset.rs` to include NEAR, Aptos, and Cosmos (CON-810)
- [ ] 5.2 Implement Ed25519 signing support in `CloudEnclave` for testing (CON-810)
- [ ] 5.3 Finalize Tier 1 family set selection: EVM, Solana, Bitcoin (CON-789)
- [ ] 5.4 Document universal chain support boundaries and criteria (CON-810)

## 6. Lightning Resilience (SRL-1)
- [/] 6.1 Implement Lightning resilience and recovery models (CON-1174)
- [ ] 6.2 Define payment lifecycle semantics and retry behavior (CON-688)
