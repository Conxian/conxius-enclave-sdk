# Conxian Ethos & Security Alignment

**Conxian builds native application infrastructure for Bitcoin.**

## Core Principles
1. **Zero Secret Egress**: Private keys never leave the hardware enclave (StrongBox/TEE). Key generation and signing are strictly internal to the hardware security module.
2. **Sovereign Handshake**: A native, non-custodial coordination protocol where transaction intents are verified and signed within the hardware enclave before broadcast.
3. **Hardware Attestation**: Mandatory cryptographic proof of device integrity. High-value operations on Bitcoin rails require a verified hardware report.
4. **The Sovereign Bridge**: Our transition path from "Legacy Rails" (Visa/Mastercard) to "Sovereign Rails" (Bitcoin/L2). We bridge traditional liquidity into hardware-secure zones with zero metadata leak.

## Strategic Alignment
As of May 2026, Conxian has pivoted to an **SDK-first GTM strategy**.

- **Primary Goal**: Empower developers to build secure, native Bitcoin applications using the Conclave SDK.
- **Industrial Intent (x402)**: Expanding into autonomous B2B payments by bridging ERP systems (SAP, Oracle) directly to Bitcoin settlement.
- **Reference Application**: The `conxius-wallet` is demoted to a reference client for developer validation.

## Aligned Enhancements (V2.1)
- [x] **Sovereign Fiat**: Refactored Fiat support to prioritize P2P and hardware-attested on-ramps over legacy providers.
- [x] **Industrial x402**: Implementation of the Payment-Required rail for machine-to-machine industrial payments.
- [x] **Ubuntu Credit**: Hardware-attested group vouching primitive to replace centralized credit scores with social trust.
- [x] **Hardware Attestation**: Integrated with RailProxy to enforce TEE/StrongBox requirements for high-value swaps.
- [x] **Native Bitcoin Taproot**: Advanced BIP341 support for computational layers and BitVM.

## Real Rails Implementation
- **Changelly Proxy**: Centralized liquidity partner for fast swaps. Integrated via secure proxy to hide user metadata.
- **Bisq Node**: P2P Bitcoin-to-Fiat/Altcoin rails. Sovereign and censorship-resistant.
- **x402 Rail**: Autonomous industrial payment rail for ERP integration.
- **Wormhole Transceivers**: Cross-chain bridging for EVM and Solana compatibility.

## Infrastructure
Deployed on Render and GCP, monitored via health check heartbeats.

## Secure Marketing & Affiliate Alignment
- **Cryptographic Attribution**: Referral proofs are signed by the user's Enclave, preventing bot-fraud and ensuring privacy-preserving attribution.
- **Non-Custodial Data**: Marketing metrics are stored in a siloed Neon schema with strict RLS policies, ensuring affiliate data doesn't leak into the core financial ledger.
