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
