# Conxian Ethos & Security Alignment
## Core Principles
1. **Zero Secret Egress**: Private keys never leave the hardware enclave (StrongBox/TEE).
2. **Sovereign Handshake**: Non-custodial signing workflow where the Gateway pushes requests to the mobile Enclave.
3. **Hardware Attestation**: Cryptographic proof of device integrity before high-value operations.

## Status & Gaps
- [x] SDK Hardware Abstraction (Headless/Android)
- [ ] Real Rails Deployment (Changelly, Bisq, Wormhole)
- [ ] Hardware Attestation Activation
- [ ] Stacks CLP Security Fixes (CON-15)
- [ ] Affiliate/Marketing Secure Integration


## Real Rails Implementation
- **Changelly Proxy**: Centralized liquidity partner for fast swaps. Integrated via secure proxy to hide user metadata.
- **Bisq Node**: P2P Bitcoin-to-Fiat/Altcoin rails. Sovereign and censorship-resistant.
- **Wormhole Transceivers**: Cross-chain bridging for EVM and Solana compatibility.

## Infrastructure
Deployed on Render and GCP, monitored via health check heartbeats.

## Secure Marketing & Affiliate Alignment
- **Cryptographic Attribution**: Referral proofs are signed by the user's Enclave, preventing bot-fraud and ensuring privacy-preserving attribution.
- **Non-Custodial Data**: Marketing metrics are stored in a siloed Neon schema with strict RLS policies, ensuring affiliate data doesn't leak into the core financial ledger.
