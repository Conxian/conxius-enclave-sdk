# Universal Blockchain Support Architecture

## Overview
The Conclave SDK has been enhanced to support universal blockchain transaction orchestration, addressing the needs of enterprise and fintech clients (SAP, Oracle, Circle, Fireblocks) while maintaining a strict "Bitcoin-First" moat. This expansion allows clients largely on Ethereum and Solana to leverage Conclave's hardware-backed security.

## 1. Multi-Curve Enclave Support
The `EnclaveManager` and `SignRequest` primitives now support multiple signing algorithms and cryptographic curves:
- **Secp256k1 (ECDSA)**: Used for Bitcoin Legacy/SegWit and EVM chains (Ethereum, Arbitrum, Base, Polygon, BSC).
- **Secp256k1 (Schnorr)**: Used for Bitcoin Taproot (BIP341).
- **Ed25519**: Used for Solana.

## 2. Protocol Isolation (The Moat)
To preserve our Bitcoin native moat, chain-specific logic is isolated into dedicated managers. While universal support is provided, Bitcoin remains the primary sellable primitive with the deepest feature set (Taproot, sBTC, Clarity integration).
- `BitcoinManager`: Descriptor-based wallet management (BDK) and Taproot support.
- `StacksManager`: Clarity-specific transaction and message handling.
- `EthereumManager`: Universal EVM support (EIP-1559, recoverable signatures).
- `SolanaManager`: Native Ed25519 signing for Solana.

## 3. Universal Reach
The `Chain` enum and `AssetRegistry` have been expanded to include:
- **L1s**: Bitcoin, Ethereum, Solana, Stacks, BSC, Polygon.
- **L2s/Sidechains**: Arbitrum, Base, Liquid, Rootstock, BOB.
- **Micro-payments**: Lightning.
- **Stablecoins**: Canonical USDC/USDT mapping across ETH and SOL.

## 4. Hardware Attestation
Universal operations maintain the same high-integrity standards as the Bitcoin stack. All signatures (regardless of chain) are accompanied by a `DeviceIntegrityReport` verifying the TEE/StrongBox environment.

## 5. Integration Path
Integrators access these capabilities via the `ConclaveWasmClient`:
- `client.bitcoin()` -> BitcoinManager
- `client.ethereum()` -> EthereumManager
- `client.solana()` -> SolanaManager
