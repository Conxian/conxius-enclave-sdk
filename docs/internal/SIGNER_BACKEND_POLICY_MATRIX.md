# Signer Backend Policy Matrix (CON-792)

This document defines the allowed signer backends for production use within the Conxian ecosystem, categorized by chain family and trust tier.

## 1. Signer Backend Classes

| Class | Description | Trust Level | Production Status |
| --- | --- | --- | --- |
| **Mobile Enclave** | Android StrongBox / Apple Secure Enclave. Hardware-isolated keys. | High | **Allowed** |
| **TEE (Cloud)** | AWS Nitro Enclaves / Azure SNP. Hardware-attested cloud compute. | High | **Allowed** |
| **HSM** | FIPS 140-2 Level 3 Hardware Security Modules. | High | **Allowed (Institutional)** |
| **MPC / Threshold** | Distributed key shares with hardware-backed participants. | Medium-High | **Restricted (requires audit)** |
| **Hardware Wallet** | Trezor / Ledger / Coldcard via Conclave bridge. | High | **Allowed (User-initiated)** |
| **Software / Mock** | Plaintext keys or simulated enclaves (CloudEnclave dev mode). | Low | **Disallowed (Dev/Test only)** |

## 2. Policy Matrix by Chain Family

| Chain Family | Allowed Backends | Restricted Backends | Disallowed Backends |
| --- | --- | --- | --- |
| **Bitcoin (L1/L2)** | StrongBox, TEE, HSM, HW Wallet | MPC (audit req), Taproot-MuSig2 | Software/Simulated |
| **EVM (ETH/L2)** | StrongBox, TEE, HSM, HW Wallet | MPC, Account Abstraction (ERC-4337) | Software/Simulated |
| **SVM (Solana)** | StrongBox, TEE, HSM, HW Wallet | MPC | Software/Simulated |
| **Lightning** | StrongBox, TEE (LDK-ready) | VLS (Validating Lightning Signer) | Software/Simulated |

## 3. Trust-Tier Enforcement (RailProxy Integration)

The `RailProxy` must enforce the following signer-to-rail mapping:

- **T1 Rails (Sovereign)**: Require Hardware Attestation (`StrongBox`, `TEE`, or `CloudTEE`). Software attestation MUST fail closed.
- **T2 Rails (Hybrid)**: Require Hardware Attestation.
- **T3 Rails (Attester)**: Allow MPC or audited Multi-sig signers with lower hardware requirements.
- **T4 Rails (Forbidden)**: No production traffic allowed.

## 4. Implementation Implications

- **Gateway**: Must reject any `SignResponse` that does not include a valid `DeviceIntegrityReport` matching the required level for the target rail.
- **Nexus**: Must store signer class metadata in the `ProofEnvelope` to allow downstream audit of signing integrity.
- **Enclave SDK**: All production drivers MUST emit hardened attestation levels. Software drivers are strictly for local development and interface testing.
