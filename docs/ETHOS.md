# Conxian Ethos & Security Alignment

**Conxian builds native application infrastructure for Bitcoin.**

## Core Principles
1. **Zero Secret Egress**: Private keys never leave the hardware enclave (StrongBox/TEE). Key generation and signing are strictly internal to the hardware security module.
2. **Sovereign Handshake**: A native, non-custodial coordination protocol where transaction intents are verified and signed within the hardware enclave before broadcast.
3. **Hardware Attestation**: Mandatory cryptographic proof of device integrity. High-value operations on Bitcoin rails require a verified hardware report.

## Strategic Alignment
As of May 2026, Conxian has pivoted to an **SDK-first GTM strategy**.

- **Primary Goal**: Empower developers to build secure, native Bitcoin applications using the Conclave SDK.
- **Reference Application**: The `conxius-wallet` is demoted to a reference client for developer validation.
- **Infrastructure Supporting**: The `conxian-gateway` and related protocol work are repositioned as secondary supporting infrastructure for the SDK.

## Status & Gaps
- [x] SDK Hardware Abstraction (Headless/Android)
- [x] Stacks CLP Security & Math Fixes (CON-15)
- [x] Affiliate/Marketing Secure Integration
- [x] Real Rails Deployment (Changelly, Bisq, Wormhole) - Logic & Validation
- [x] Hardware Attestation Activation (Integrated with RailProxy)
- [x] Native Bitcoin Taproot Integration (Superior Upgrade: BIP341 Native Tweaks)

## Real Rails Implementation
- **Changelly Proxy**: Centralized liquidity partner for fast swaps. Integrated via secure proxy to hide user metadata.
- **Bisq Node**: P2P Bitcoin-to-Fiat/Altcoin rails. Sovereign and censorship-resistant.
- **Wormhole Transceivers**: Cross-chain bridging for EVM and Solana compatibility.

## Infrastructure
Deployed on Render and GCP, monitored via health check heartbeats.

## Secure Marketing & Affiliate Alignment
- **Cryptographic Attribution**: Referral proofs are signed by the user's Enclave, preventing bot-fraud and ensuring privacy-preserving attribution.
- **Non-Custodial Data**: Marketing metrics are stored in a siloed Neon schema with strict RLS policies, ensuring affiliate data doesn't leak into the core financial ledger.
