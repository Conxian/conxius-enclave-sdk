# Universal Blockchain Support Architecture

## Overview
The Conclave SDK has been enhanced to support universal blockchain transaction orchestration, addressing the needs of enterprise and fintech clients (SAP, Oracle, Circle, Fireblocks) while maintaining a strict "Bitcoin-First" moat. This expansion allows clients largely on Ethereum and Solana to leverage Conclave's hardware-backed security.

## 1. Tier 1 Chain Families (CON-789)
The Conclave SDK prioritizes three primary chain families as its Tier 1 set for Nexus and Gateway execution:
- **Bitcoin/UTXO**: Native Bitcoin (L1), Stacks (L2), Liquid (Sidechain), Rootstock, BOB, Mezo, Babylon, Botanix, Citrea.
- **EVM**: Ethereum, Arbitrum, Base, Optimism, Polygon, BSC, Linea, Scroll, ZKsync, Celo.
- **Solana/SVM**: Native Solana and SVM-compatible environments.

Additional support (Tier 2/3) is provided for Cosmos/IBC, NEAR, Aptos, Sui, and XRP Ledger to ensure global reach across emerging markets.

## 2. Support Boundaries and Criteria (CON-810)
Universal support is tiered based on security guarantees and implementation depth.

### Tier 1 (Native Execution)
- **Criteria**:
    - Full hardware attestation (TEE/StrongBox) mandated for all signing operations.
    - High-performance Rust-native engines (Alloy-rs, BDK, Solana-SDK).
    - Direct Gateway/Nexus orchestration without intermediary custodial bridges.
    - Support for the specific primitives evidenced for the target capability; current Ethereum evidence is limited to address and signed-message validation, not EIP-1559 transaction serialization or Account Abstraction execution.
- **Boundary**: These chains are suitable for institutional settlement and large-value industrial payments.

### Tier 2 (Hybrid/Bridge-Mediated)
- **Criteria**:
    - Cross-chain interoperability via "Sovereign Rails" (LayerZero V2, CCIP, Axelar).
    - Trust dependent on both local attestation and bridge validator sets.
- **Boundary**: Suitable for retail-scale swaps and regional stablecoin movement within capped corridors.

### Tier 3 (Extended Reach)
- **Criteria**:
    - Software-backed or simulated adapters for initial integration.
    - Limited feature set (e.g., basic transfer only).
- **Boundary**: Used for emerging market exploration and low-value testing.

## 3. Multi-Curve Enclave Support
The `EnclaveManager` and `SignRequest` primitives now support multiple signing algorithms and cryptographic curves:
- **Secp256k1 (ECDSA)**: Used for Bitcoin Legacy/SegWit and EVM chains.
- **Secp256k1 (Schnorr)**: Used for Bitcoin Taproot (BIP341).
- **Ed25519**: Used for Solana, NEAR, Aptos, and SUI.

## 4. Protocol Isolation (The Moat)
To preserve our Bitcoin native moat, chain-specific logic is isolated into dedicated managers. While universal support is provided, Bitcoin remains the primary sellable primitive with the deepest feature set (Taproot, sBTC, Clarity integration).
- `BitcoinManager`: Descriptor-based wallet management (BDK) and Taproot support.
- `StacksManager`: Clarity-specific transaction and message handling.
- `EthereumManager`: Scoped Ethereum address and signed-message validation (Keccak, EIP-55, EIP-191, EIP-2098, EIP-155 `v`, and recoverable-signature parity); transaction serialization, EIP-1559, and EIP-712 remain outside this evidence scope.
- `SolanaManager`: Native Ed25519 signing for Solana.
- `ChainAbstractionService`: Orchestrates NEAR-style chain signatures and universal intent settlement.

## 5. Universal Reach & Interop Rails
The `Chain` enum and `AssetRegistry` support a vast taxonomy of assets.
- **Interoperability Standards** are integrated via "Sovereign Rails":
  - **LayerZero V2**: Omnichain messaging and OFTs with DVN diversity.
  - **Chainlink CCIP**: Programmable token transfers with Risk Management Network backing.
  - **Axelar**: General Message Passing for cross-chain contract calls.

## 6. Hardware Attestation
Value-bearing production operations are intended to require a `DeviceIntegrityReport` and hardware-backed policy, but the current repository evidence is simulated/conditional rather than provider-backed hardware support. The Ethereum capability documented here covers address and message/signature validation; it does not establish hardware-backed signing or provider/runtime evidence.

## 7. Integration Path
Integrators access these capabilities via the `ConclaveWasmClient`:
- `client.bitcoin()` -> BitcoinManager
- `client.ethereum()` -> EthereumManager
- `client.solana()` -> SolanaManager
- `client.universal()` -> ChainAbstractionService

## 8. Trust-Tier Enforcement
The `RailProxy` enforces the [Approved Bridge and Messaging Trust-Tier Policy](architecture/APPROVED_BRIDGE_AND_MESSAGING_SYSTEMS_BY_TRUST_TIER.md). High-value enterprise routes are restricted to T1/T2 systems (IBC, hardened LayerZero/CCIP), while T3 systems (Axelar, Wormhole) are used for capped corridors.
