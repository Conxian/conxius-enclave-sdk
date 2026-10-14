# Hardware and driver qualification refresh

Primary sources checked on 2026-10-14. These are qualification targets, not enabled production signers. Bitcoin is the canonical trust root for universal-chain operations. Every qualification must bind device/firmware, module hash, key provenance, algorithm, operation, fresh evidence, replay policy, and independent review.

## Android secure-element inventory

Google's [Ready SE directory](https://developers.google.com/android/security/android-ready-se/supported-chipsets) remains dated 2024-10-31 when fetched in 2026. Its maturity distinctions must be preserved:

| Vendor | Listed products / stated KeyMint level |
|---|---|
| Giesecke+Devrient | Sm@rtSIM CX Copernicus2.0M: 2.0/3.0 |
| Goodix | GSEA0, GSE20, GSN11, GSN22: 2.0/3.0 |
| Kigen | THD89-2048: 2.0/3.0 |
| NXP | SN300, SN220, SN110, SE060, SE050; level unspecified |
| Samsung | S3SSE1A: 1.0 |
| STMicroelectronics | ST54L00/01/02/03/04/06/20/21/22/23xxx, STSAFS320Wxxx; level unspecified |
| Thales | Connected eSE 4.2.3: 2.0; 5.3.4: 2.0/3.0 |
| Tongxin Micro | THN41, T10-Mobile: 2.0/3.0 |
| Unisoc | Future support stated; no released StrongBox qualification inferred |
| Valid | mioSIM eUICC Consumer v3.0: 2.0/3.0 |

Apps use Android Keystore/KeyMint; OEM HAL drivers belong to device integration. Chipset metadata does not establish the app key's security level or Bitcoin algorithm.

[Android guidance](https://developer.android.com/privacy-and-security/security-key-attestation) documents two root anchors, including a root signing chains from February 2026. Separate-server validation must check chain signatures, revocation, and the first trusted attestation extension in chain order. HS-001/HS-002 need root-set lifecycle and extension-order negatives; a client chain cannot supply its own trust anchor.

## Driver and transport map

| Target | Boundary | Qualification gap |
|---|---|---|
| StrongBox/TEE, Knox Vault, Qualcomm SPU, Titan | Keystore/KeyMint + OEM implementation | Verified key security level, attestation, device matrix |
| Apple Secure Enclave | CryptoKit/Security authorization factor | P-256 identity binding; Bitcoin signer separate |
| Nitro | NSM + bounded vsock | Measurement policy, KMS release/key binding, replay |
| CloudHSM | Client SDK 5 PKCS#11 | Exact mechanisms, key attributes, session policy, failover |
| YubiHSM 2 | Yubico module + connector | Vendor attestation, authentication domains, export policy |
| Thales/Utimaco | Vendor PKCS#11 profile | Approved module/model/firmware and evidence verifier |
| TPM 2.0 | Linux driver + TSS/ESAPI/FAPI | EK/AK, quote/PCR/event-log and discovered curves |
| Intel SGX / TDX | Separate DCAP profiles | Collateral, TCB, measurements, returned-key binding |
| AMD SEV-SNP | `sev-guest` report interface | Report-data, VCEK/VLEK, TCB, custody binding |
| Arm CCA / RISC-V Keystone TEE | Platform attestation/endorsements | Profile, measurement, isolated-key evidence |
| Keystone hardware wallet | PSBT / `crypto-psbt` UR transport | Exact output policy, QR bounds/replay, device ceremony |

AWS lists secp256k1 in its [PKCS#11 key types](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html) and ECDSA/EdDSA/ML-DSA in its [mechanisms](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html). Neither qualifies Conxian BIP-340 signing. Record interface-specific support; KSP/JCE/PKCS#11 are different surfaces.

[Yubico](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-tools-pkcs11.html) documents asymmetric verification and digests in software. Generic `C_Verify` success is not hardware provenance.

Driver references: [Linux TPM](https://docs.kernel.org/security/tpm/index.html), [SEV guest API](https://docs.kernel.org/virt/coco/sev-guest.html), [Intel DCAP](https://github.com/intel/confidential-computing.tee.dcap), [Keystone integration](https://github.com/KeystoneHQ/Keystone-developer-hub/blob/main/Integration_guide.md). Keystone hardware-wallet transport and the RISC-V Keystone enclave framework are separate systems.

## Execution boundary

Retain real cryptographic feature gates and external-chain modules. Provider hints stay diagnostic; unconfigured providers fail closed. SDK #559 and provider-matrix HS-001 through HS-016 track hardware/driver qualification. This refresh qualified no physical device, HSM fleet, independent signer domains, or production threshold ceremony. The public KMS artifact proves P-256 challenge signatures only; community verification needs no AWS credentials.
