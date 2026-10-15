# Signer Backend Policy Matrix (CON-792)

This document defines the allowed signer backends for production use within the Conxian ecosystem, categorized by chain family and trust tier.

## 1. Signer Backend Classes

| Class | Description | Trust Level | Production Status |
| --- | --- | --- | --- |
| **Mobile Enclave** | Android StrongBox / Apple Secure Enclave. Hardware-isolated keys. | High | **Allowed** |
| **TEE (Cloud)** | AWS Nitro Enclaves / Azure SNP. Provider-backed hardware evidence required. | High | **Conditional only; unsupported by this SDK until provider verification and review are evidenced** |
| **HSM** | FIPS 140-2 Level 3 Hardware Security Modules. | High | **Allowed (Institutional)** |
| **MPC / Threshold** | Distributed key shares with hardware-backed participants. | Medium-High | **Restricted (requires audit)** |
| **Hardware Wallet** | Trezor / Ledger / Coldcard via Conclave bridge. | High | **Allowed (User-initiated)** |
| **Software / Mock** | Plaintext keys or simulated enclaves (CloudEnclave dev mode). | Low | **Disallowed (Dev/Test only)** |

## 2. Policy Matrix by Chain Family

| Chain Family | Allowed Backends | Restricted Backends | Disallowed Backends |
| --- | --- | --- | --- |
| **Bitcoin (L1/L2)** | StrongBox, HSM, HW Wallet | TEE/CloudTEE (provider evidence and audit required), MPC (audit req), Taproot-MuSig2 | Software/Simulated |
| **EVM (ETH/L2)** | StrongBox, HSM, HW Wallet | TEE/CloudTEE (provider evidence and audit required), MPC, Account Abstraction (ERC-4337) | Software/Simulated |
| **SVM (Solana)** | StrongBox, HSM, HW Wallet | TEE/CloudTEE (provider evidence and audit required), MPC | Software/Simulated |
| **Lightning** | StrongBox, HSM, HW Wallet | TEE/CloudTEE (provider evidence and audit required), VLS (Validating Lightning Signer) | Software/Simulated |

## 3. Trust-Tier Enforcement (RailProxy Integration)

The `RailProxy` must enforce the following signer-to-rail mapping:

- **T1 Rails (Sovereign)**: Require independently verified hardware attestation (`StrongBox`, `TEE`, or `CloudTEE`). Software attestation MUST fail closed; this SDK does not currently register an AWS Nitro provider verifier.
- **T2 Rails (Hybrid)**: Require Hardware Attestation.
- **T3 Rails (Attester)**: Allow MPC or audited Multi-sig signers with lower hardware requirements.
- **T4 Rails (Forbidden)**: No production traffic allowed.

## 4. Implementation Implications

- **Gateway**: Must reject any `SignResponse` that does not include a valid `DeviceIntegrityReport` matching the required level for the target rail.
- **Nexus**: Must store signer class metadata in the `ProofEnvelope` to allow downstream audit of signing integrity.
- **Enclave SDK**: All production drivers MUST emit hardened attestation levels. Software drivers are strictly for local development and interface testing.


## 5. Hardware Chipset & Driver Technical Specifications Matrix

This section defines provider identifiers understood by the SDK. An identifier
does **not** assert that a production verifier, signer, chipset, curve, FIPS
certificate, or cloud configuration is available. Production support remains
`unsupported` until the corresponding evidence gate in
`HARDWARE_SIGNING_PROVIDER_MATRIX_2026.md` passes.

| Provider identifier | Integration boundary | Evidence that must be verified | Important separation |
| --- | --- | --- | --- |
| **`INTEL_SGX_DCAP`** | SGX DCAP quote/collateral verifier | Quote, PCK/QE chain, TCB status, measurements, freshness | TDX has a distinct quote/TCB profile and needs its own typed verifier before enablement. |
| **`ANDROID_STRONGBOX`** | Android KeyMint/Key Attestation | Google-rooted certificate path, attestation challenge, authorization lists, verified boot and security level | Package names, key IDs, model names, and Play Integrity alone do not prove StrongBox. |
| **`AWS_NITRO`** | NSM attestation + KMS release policy | COSE signature/chain, PCRs, nonce/user data/public key, freshness, KMS conditions | Nitro attests an enclave; application/KMS key algorithms are a separate capability. |
| **`TPM_20`** | TPM 2.0 quote and key certification | EK/AK trust, quote signature, PCR selection/values, nonce, certified key attributes | `tpm2-pkcs11` discovery metadata is not a TPM quote. |
| **`APPLE_SECURE_ENCLAVE`** | Apple key authorization / App Attest profile | Apple chain, nonce/challenge, app identity, key binding and freshness | Secure Enclave key use and App Attest are separate Apple security APIs. |
| **`AMD_SEV_SNP`** | SNP attestation report verifier | ARK/ASK/VCEK or VLEK path, report signature, TCB, policy, measurement, report data | Guest signing algorithms are not implied by the SNP report signature algorithm. |
| **`ARM_TRUSTZONE`** | PSA initial-attestation profile | EAT/CBOR token signature, implementation identity, lifecycle, measurements, challenge | Arm CCA Realm attestation is a separate architecture/profile and needs a distinct type. |
| **`KEYSTONE_RISCV`** | RISC-V Keystone TEE attestation | Security-monitor/enclave measurement chain, challenge, freshness, key binding | This is not the Keystone air-gapped hardware wallet product. |
| **`PKCS11_HSM`** | PKCS#11 signing adapter plus provider profile | Authenticated slot/key identity, non-extractability, mechanism allow-list, provider/FIPS evidence | Manufacturer/module strings and `C_GetTokenInfo` are inventory hints only. |
| **`WEBAUTHN_FIDO2`** | WebAuthn/FIDO authenticator verifier | Client data, RP ID, challenge, authenticator data, statement format, trust policy, counters | WebAuthn authentication is not a general Bitcoin transaction-signing API. |
