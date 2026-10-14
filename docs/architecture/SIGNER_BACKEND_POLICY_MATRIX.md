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

This section defines the 10 hardware provider types (`HardwareProviderType`) supported by the SDK, their underlying driver interfaces, hardware chipsets, attestation schemes, and supported cryptographic curves.

| Provider (`HardwareProviderType`) | Chipset / Hardware Module | Driver Interface & Specification | Attestation Scheme | Hardware Tier | Supported Curves |
| --- | --- | --- | --- | --- | --- |
| **`INTEL_SGX_DCAP`** | Intel SGX / TDX (Xeon Scalable) | Intel SGX DCAP 1.23+ / `/dev/sgx_enclave` | ECDSA P-256 Quote over PCK/QE certs & Intel PCS | CloudTEE | secp256r1, secp256k1, rsa3048 |
| **`ANDROID_STRONGBOX`** | Google Titan M2, Samsung Knox Vault, Qualcomm SPU | Android KeyMint v4 / StrongBox Keymaster SE API | X.509 Key Attestation chain & Play Integrity evidence | StrongBox | secp256r1, secp256k1, rsa2048, ed25519 |
| **`AWS_NITRO`** | AWS Nitro Security Module (NSM) | `/dev/nsm` ioctl / AWS Enclave CLI | COSE CBOR document signed by AWS Nitro Root CA G1 (P-384) | CloudTEE | secp256r1, secp384r1, secp256k1, ed25519 |
| **`TPM_20`** | Infineon Optiga, STMicro ST33, MS Pluton | TCG TPM 2.0 Library Spec v1.85 / `tpm2-pkcs11` | Attestation Key (AK) quote over PCRs & EK X.509 cert | StrongBox | secp256r1, rsa2048 |
| **`APPLE_SECURE_ENCLAVE`** | Apple Silicon (M1-M4, A14-A18) SEP | DeviceCheck App Attest API / CryptoTokenKit | CBOR/COSE attestation object signed by Apple App Attest Root CA | StrongBox | secp256r1 |
| **`AMD_SEV_SNP`** | AMD EPYC Processors (Zen 3+) | AMD SEV-SNP Firmware ABI / SVSM Interface | VCEK/VLEK certificate chain rooted in AMD Root Key (ARK) | CloudTEE | secp256r1, secp384r1 |
| **`ARM_TRUSTZONE`** | ARM Cortex-A/M TrustZone / ARM CCA | ARM PSA Attestation API 1.0.2 / CCA RMM | PSA Attestation Token (EAT / CBOR) over Realm measurements | TEE | secp256r1, ed25519 |
| **`KEYSTONE_RISCV`** | Keystone 3 Pro HW / RISC-V Keystone Enclave | Keystone PMP Security Monitor / Air-gapped QR/USB | Hardware SE050 attestation / Keystone PMP security proof | TEE / HW | secp256k1, Schnorr, ed25519 |
| **`PKCS11_HSM`** | Thales Luna, Utimaco ISG, YubiHSM2, AWS CloudHSM | OASIS PKCS#11 v3.2 (`cryptoki` C API) | C_GetTokenInfo / C_GetAttributeValue slot & key metadata | StrongBox | secp256k1, secp256r1, rsa2048/4048, ed25519 |
| **`WEBAUTHN_FIDO2`** | YubiKey 5, TouchID/FaceID, Titan Key | W3C WebAuthn Level 3 / FIDO MDS 3.1.1 | FIDO2 packed / TPM / Android / Apple attestation statement | StrongBox | secp256r1, ed25519, rsa2048 |
