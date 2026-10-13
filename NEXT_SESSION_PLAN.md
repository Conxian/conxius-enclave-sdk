# Next Session Plan

## Session 84 Completed (2026-10-11) — Hardware Signing Chipset Drivers, HSM, Keystone, Enclave & StrongBox Research Expansion

Provider identifiers and policy bindings were added as an inventory and
verification contract. They do not grant production support by themselves.

## Hardware signing expansion added (2026-10-13)

The verified provider matrix and implementation queue are maintained in
[`docs/architecture/HARDWARE_SIGNING_PROVIDER_MATRIX_2026.md`](docs/architecture/HARDWARE_SIGNING_PROVIDER_MATRIX_2026.md).
The immediate order is HS-001/002 (Android verifier + signer), HS-003 (Nitro
NSM/KMS signer), HS-004/005 (PKCS#11 provider policy + correct capability
discovery), and HS-012 (qualification harness). TPM, DCAP, SEV-SNP, Keystone,
Apple authorization, YubiHSM, and cloud-HSM profiles remain explicitly
unsupported until their listed evidence gates pass.

This queue preserves the Bitcoin L1, zero-native-token boundary. Vendor and
chipset names are inventory metadata, never proof of hardware signing.

### ✅ Hardware Provider Types & Chipset Driver Classification
- Implemented `HardwareProviderType` enum (`IntelSgx`, `AndroidStrongBox`, `AwsNitro`, `Tpm20`, `AppleSecureEnclave`, `AmdSevSnp`, `ArmTrustZone`, `Keystone`, `Pkcs11Hsm`, `WebAuthnFido2`) in `src/enclave/attestation.rs`.
- Added helper methods for provider classification, driver interface spec resolution, default attestation level, and supported curves.
- Extended `AttestationExtension` with 10 typed provider variants (`ProviderIntelSgx`, etc.) and mapped canonical parsing and tag numbers.
- Added `with_hardware_provider` to `AttestationPolicy`.
- Added `classify_hardware_module()` in `Pkcs11AttestationEvidence` and `identify_chipset_driver()` in `AndroidAuthorizationEvidence`.

### ✅ Documentation & Knowledge Base Synchronization
- Expanded `RESEARCH_LOG.md` with an exhaustive research section covering online specs, drivers, chipsets, attestation schemes, and security boundaries.
- Updated `docs/architecture/SIGNER_BACKEND_POLICY_MATRIX.md` with the Hardware Chipset & Driver Technical Specifications Matrix.
- Updated `docs/architecture/CAPABILITY_MATRIX.md`, `docs/architecture/GAP_SCORECARD.md`, `DEBT_INVENTORY.md`, `TRACKING.md`, `.session/ledger.md`, and `CHANGELOG.md`.

---

## Session 85 Planned

### P0: Automated BitVM2/Ark Challenge Watchtower Execution
- Extend `BitVm2Orchestrator` and `ArkClient` to support automated challenge-response transaction triggering on fraudulent state root detection.

### P0: Hardware Key Management as a Service (KMaaS) Policy Enforcement
- Extend `ThresholdEnclaveManager` / `UniversalChainSigner` to support policy-enforced Hardware KMaaS signing limits and authorization rules.

### P0: Independent Security Review & Release Acceptance (#202)
- Maintain tracking for independent security auditor review evidence and release acceptance artifacts.
