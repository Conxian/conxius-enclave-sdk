# Universal Blockchain Support Research & Roadmap

## 1. Executive Summary
Conclave SDK is evolving from a "Bitcoin-Native" focus to "Universal Support with a Bitcoin Moat." We will serve all major chains (Ethereum, Solana, Cosmos, etc.) by integrating leading interoperability standards and chain abstraction protocols, while leveraging our unique hardware-backed signing and Bitcoin-native primitives (MuSig2, DLC, BTC-as-Gas) as the primary differentiator.

## 2. Landscape Analysis

### A. LayerZero V2 (Omnichain Messaging)
*   **OApp & OFT:** LayerZero V2 provides standardized interfaces for "Omnichain Applications" and "Omnichain Fungible Tokens." OFTs allow tokens to be moved across chains without wrapping, by burning on the source and minting on the destination (or using a lock/unlock mechanism).
*   **DVN (Decentralized Verifier Network):** Unlike V1, V2 allows applications to select a specific set of DVNs to verify messages. This enables a "Sovereign Configuration" where Conclave can require high-integrity verifiers for its routes.
*   **Dynamic Call:** The IOTA/Move implementation of LayerZero V2 introduces dynamic cross-contract coordination using a secure "hot-potato" pattern, emulating dynamic dispatch in a static environment.
*   **Conclave Strategy:** Support LayerZero V2 as a Tier 2/T3 "Sovereign Rail," allowing universal asset movement while enforcing DVN diversity via the `RailProxy`.

### B. Chainlink CCIP (Programmable Transfers)
*   **Risk Management Network:** CCIP features a dedicated network that monitors for anomalous activity, providing a "defense-in-depth" layer beyond the primary oracle network.
*   **Programmable Messaging:** CCIP allows sending tokens and arbitrary data in a single atomic transaction (`EVM2AnyMessage`). This is critical for complex intents like "swap on destination."
*   **Fee Abstraction:** Fees can be paid in LINK or the native gas token of the source chain, simplifying the user experience.
*   **Conclave Strategy:** Utilize CCIP for high-value enterprise routes, leveraging its Risk Management Network as an additional "Attester" signal for T2/T3 trust tiers.

### C. Axelar (General Message Passing)
*   **GMP (General Message Passing):** Axelar enables cross-chain function calls and state synchronization. It uses a decentralized PoS validator set to verify messages.
*   **Gas Service:** Axelar provides a gas receiver on the source chain (`payNativeGasForContractCall`) to handle relayer execution on the destination, abstracting gas management from the user.
*   **Conclave Strategy:** Support Axelar GMP as a modular rail for "Capped Corridors" and non-canonical asset routes (T3).

### D. NEAR Chain Signatures (MPC-Based Abstraction)
*   **Universal MPC Signing:** NEAR uses a distributed MPC network to enable a single NEAR account (or smart contract) to sign transactions for Bitcoin, Ethereum, and other chains without traditional bridges.
*   **Derivation Paths:** Addresses are derived deterministically using the NEAR account ID and a path (e.g., `ethereum-1`), allowing for "Universal Accounts."
*   **Conclave Strategy:** Integrate "Hardware-Backed Multi-Chain Accounts" where the Conclave Enclave (StrongBox/TEE) serves as the Root of Trust for all derived chain addresses, potentially using NEAR as a decentralized relayer for the signed payloads.

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

See also: [Approved Bridge and Messaging Trust-Tier Policy](architecture/APPROVED_BRIDGE_AND_MESSAGING_SYSTEMS_BY_TRUST_TIER.md)
