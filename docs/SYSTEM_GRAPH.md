# Conxian Nexus: Universal System Architecture & Component Graph

## Core Infrastructure
- **Nexus OS**: The heart of the middleware, managing universal state and orchestration.
- **RailProxy**: Security enforcement layer with TEE-backed attestation gates.
- **AssetRegistry**: Canonical source of truth for 50+ global assets.

## Universal Payment Lifecycle
[User / Retailer]
    --> [Intent Declaration (ERC-7683)]
    --> [Modular Smart Account (ERC-7579 + Passkey)]
    --> [Nexus Orchestrator (StablecoinOrchestrator)]
        --> [SwapRouter (Exact-Out: SOL/ETH -> Stable)]
        --> [CctpManager (USDC Burn/Mint)]
        --> [Solver Network (Across/Eco fulfillment)]
    --> [Universal Settlement (T1-T3 Rails)]

## Supported Chain Families
- **Bitcoin Family**: L1, Stacks, Liquid, Rootstock, BOB, Mezo, Babylon, Botanix, Citrea.
- **EVM Family**: Ethereum, Arbitrum, Base, Optimism, Linea, Polygon, BSC, Avalanche, Fantom, Gnosis, ZKsync, Scroll.
- **SVM Family**: Solana.
- **Global / Regional L1s**: Stellar, XRP Ledger, Near, Tron, Celo, Cosmos.

## Security & Trust Tiers
- **T1 Sovereign**: Hardware-isolated, native settlement.
- **T2 Hybrid**: TEE-attested sidechains.
- **T3 Attester**: Decentralized intent solver networks.
- **T4 Forbidden**: High-risk, centralized bridges.
