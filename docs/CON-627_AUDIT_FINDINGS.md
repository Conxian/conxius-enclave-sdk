# CON-627: SDK Extraction Audit Findings

## Overview
The current `lib-conclave-sdk` architecture was audited for its viability as a standalone, reusable SDK that can be decoupled from any specific wallet UI.

## Findings

### 1. Modularity & Coupling
- **Enclave Abstraction**: Hardware-signing and key management are abstracted via the `EnclaveManager` trait. This allows the SDK to remain agnostic of specific hardware implementations while providing a consistent API to the UI.
- **Protocol Separation**: All protocol logic (Rails, Asset Registry, Business Management, DLC, etc.) is contained within the `src/protocol/` directory.
- **Zero UI Coupling**: A grep of the `src/` directory confirms zero hard dependencies on UI frameworks or DOM-specific logic. All inputs/outputs are primitive types or serializable structures.
- **WASM Bindings**: `src/wasm_bindings.rs` provides a clean entry point (`ConclaveWasmClient`) for external integrators.

### 2. Risky Refactor Points
- **ConclaveWasmClient Bloat**: The `ConclaveWasmClient` is becoming a "God object" that holds references to all services. As the SDK grows, this should be broken down into specialized clients (e.g., `SigningClient`, `SwapClient`, `IdentityClient`).
- **Chain Adapter Logic**: Currently, chain-specific logic is somewhat spread between `src/protocol/asset.rs` and individual rail implementations. A more unified "Chain Adapter" pattern would improve extensibility.
- **Network Dependency**: The SDK relies on `reqwest` for Gateway communication. While functional in WASM, it creates a dependency on a specific networking stack.

### 3. Recommendation
- **Extraction Viability**: **HIGH**. The SDK is already modular enough to be published as a standalone package.
- **Next Steps**:
    - Formalize the module boundaries (CON-628).
    - Reduce the `ConclaveWasmClient` surface by grouping related methods into sub-objects.
    - Publish the SDK as a separate repository or workspace member to enforce strict boundary checks.
