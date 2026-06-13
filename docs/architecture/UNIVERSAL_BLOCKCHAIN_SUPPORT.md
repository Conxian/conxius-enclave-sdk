# Universal Blockchain Support Architecture

## Overview
The Conclave SDK has been enhanced to support universal blockchain transaction orchestration, addressing the needs of enterprise and fintech clients (SAP, Oracle, Circle, Fireblocks) while maintaining a strict "Bitcoin-First" moat. This expansion allows clients largely on Ethereum and Solana to leverage Conclave's hardware-backed security.

## 1. Multi-Curve Enclave Support
The `EnclaveManager` and `SignRequest` primitives now support multiple signing algorithms and cryptographic curves:
- **Secp256k1 (ECDSA)**: Used for Bitcoin Legacy/SegWit and EVM chains (Ethereum, Arbitrum, Base, Polygon, BSC).
- **Secp256k1 (Schnorr)**: Used for Bitcoin Taproot (BIP341).
- **Ed25519**: Used for Solana, NEAR, Aptos, and SUI.

## 2. Protocol Isolation (The Moat)
To preserve our Bitcoin native moat, chain-specific logic is isolated into dedicated managers. While universal support is provided, Bitcoin remains the primary sellable primitive with the deepest feature set (Taproot, sBTC, Clarity integration).
- `BitcoinManager`: Descriptor-based wallet management (BDK) and Taproot support.
- `StacksManager`: Clarity-specific transaction and message handling.
- `EthereumManager`: Universal EVM support (EIP-1559, recoverable signatures).
- `SolanaManager`: Native Ed25519 signing for Solana.
- `ChainAbstractionService`: Orchestrates NEAR-style chain signatures and universal intent settlement.

## 3. Universal Reach & Interop Rails
The `Chain` enum and `AssetRegistry` have been expanded to include:
- **L1s**: Bitcoin, Ethereum, Solana, Stacks, BSC, Polygon, NEAR.
- **L2s/Sidechains**: Arbitrum, Base, Liquid, Rootstock, BOB, Mezo, Babylon, Botanix, Citrea.
- **Interoperability Standards**: Integrated via "Sovereign Rails":
  - **LayerZero V2**: Omnichain messaging and OFTs with DVN diversity.
  - **Chainlink CCIP**: Programmable token transfers with Risk Management Network backing.
  - **Axelar**: General Message Passing for cross-chain contract calls.

## 4. Hardware Attestation
Universal operations maintain the same high-integrity standards as the Bitcoin stack. All signatures (regardless of chain) are accompanied by a `DeviceIntegrityReport` verifying the TEE/StrongBox environment.

## 5. Integration Path
Integrators access these capabilities via the `ConclaveWasmClient`:
- `client.bitcoin()` -> BitcoinManager
- `client.ethereum()` -> EthereumManager
- `client.solana()` -> SolanaManager
- `client.universal()` -> ChainAbstractionService

## 6. Trust-Tier Enforcement
The `RailProxy` enforces the [Approved Bridge and Messaging Trust-Tier Policy](architecture/APPROVED_BRIDGE_AND_MESSAGING_SYSTEMS_BY_TRUST_TIER.md). High-value enterprise routes are restricted to T1/T2 systems (IBC, hardened LayerZero/CCIP), while T3 systems (Axelar, Wormhole) are used for capped corridors.
