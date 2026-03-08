## 1. Core Traits and Registries

- [ ] 1.1 Implement `AssetRegistry` with chain-aware metadata
- [ ] 1.2 Define the `EnclaveManager` trait for hardware abstraction
- [ ] 1.3 Implement `BusinessManager` with cryptographic identity support

## 2. Protocol Refactoring

- [ ] 2.1 Refactor `RailProxy` to consume the `AssetRegistry`
- [ ] 2.2 Update `SwapRequest` to use structured asset objects
- [ ] 2.3 Refactor `AffiliateManager` into `BusinessManager`

## 3. Implementation of Plug-ins

- [ ] 3.1 Implement a mock `CloudEnclave` using the new `EnclaveManager` trait
- [ ] 3.2 Add a `CustomRail` extension example in `rails.rs`
