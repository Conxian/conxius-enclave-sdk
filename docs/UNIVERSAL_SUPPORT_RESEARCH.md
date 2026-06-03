# Universal Blockchain Support Research & Roadmap

## 1. Executive Summary
Conclave SDK is evolving from a "Bitcoin-Native" focus to "Universal Support with a Bitcoin Moat." We will serve all major chains (Ethereum, Solana, Cosmos, etc.) by integrating leading interoperability standards and chain abstraction protocols, while leveraging our unique hardware-backed signing and Bitcoin-native primitives (MuSig2, DLC, Taproot) as the primary differentiator.

## 2. Landscape Analysis
### A. Chain Abstraction & Universal Accounts
*   **NEAR Chain Signatures:** Enables a single NEAR account (or smart contract) to control accounts on any chain via MPC.
*   **Particle Network:** Focuses on Universal Accounts and Universal Liquidity to abstract chain boundaries for the end-user.
*   **Conclave Opportunity:** Integrate "Hardware-Backed Multi-Chain Accounts" where the Conclave Enclave (StrongBox/TEE) serves as the Root of Trust for all derived chain addresses.

### B. Interoperability Protocols
*   **LayerZero V2:** Immutable messaging and OFT (Omnichain Fungible Token) standards.
*   **Chainlink CCIP:** High-security messaging with a dedicated Risk Management Network.
*   **Axelar:** Cross-chain messaging and token transfers with a decentralized validator set.
*   **Conclave Strategy:** Support these protocols as "Sovereign Rails" within the `RailProxy` architecture.

### C. Bitcoin-Native Advancements
*   **BitVM2:** Trust-minimized computation and bridging on Bitcoin using SNARK verifiers.
*   **Babylon:** Bitcoin staking to secure PoS chains.
*   **Conclave Moat:** Deep integration with MuSig2 for MPC-style security without the complexity of a full MPC network, and DLCs for non-custodial finance.

## 3. Proposed Architectural Enhancements

### I. Universal Asset & Chain Registry
*   Expand `Chain` enum in `src/protocol/asset.rs` to include more networks (Aptos, NEAR, Cosmos).
*   Implement a dynamic `ChainConfig` that handles gas estimation, block finality, and address formats for each network.

### II. Multi-Curve Enclave Support
*   Update `EnclaveManager` to support `Ed25519` (Solana, Aptos, NEAR) and `Schnorr` (Taproot) alongside `Secp256k1`.
*   Ensure hardware attestation covers all signing curves.

### III. Interop Rail Expansion
*   Implement `LayerZeroRail`, `CCIPRail`, and `AxelarRail` in `src/protocol/rails/`.
*   Standardize the `SwapIntent` to handle "Omnichain Intents" (e.g., ERC-7683).

### IV. Universal Client API
*   Refactor `ConclaveWasmClient` to provide chain-agnostic methods: `get_balance`, `transfer`, `sign_intent`.
*   Maintain `bitcoin_native` sub-module for specialized L1/L2/L3 Bitcoin features.

## 4. Roadmap
*   **Phase 1 (Alignment):** Expand `Chain` enum and `AssetRegistry`. Add Ed25519 support to `CloudEnclave` (simulated).
*   **Phase 2 (Expansion):** Integrate LayerZero V2 and CCIP as Rails.
*   **Phase 3 (Universal Accounts):** Implement deterministic multi-chain address derivation from a single hardware seed.
*   **Phase 4 (Bitcoin-Native Moat):** Launch BitVM2 bridge support and Babylon staking orchestration.
