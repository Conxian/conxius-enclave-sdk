# Next Session Plan

## Current P0 continuation — 20 October 2026

Review the clock-persistence correction candidate under #240 against the exact PR head and hosted evidence. Preserve replay history and normal independent review/promotion controls. Next qualify the service-owned transactional backend, replica/restart/outage/rollback behavior, current provider collateral and operation/key binding. Local file-store tests do not close distributed replay, hardware or release acceptance. See `openspec/changes/2026-10-20-replay-clock-persistence/proposal.md` and SEC-003 in `DEBT_INVENTORY.md`.

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

### ✅ Provider inventory and fail-closed policy binding
- Implemented `HardwareProviderType` identifiers in `src/enclave/attestation.rs` for policy and inventory use only.
- Added provider classification and driver-spec references, but removed blanket curve/support claims that were not established by authenticated runtime discovery.
- Extended `AttestationExtension` with typed provider variants and bound exactly one expected provider into the canonical policy digest.
- Added `with_hardware_provider` to `AttestationPolicy`; provider metadata cannot establish provenance.
- Generic PKCS#11 metadata and Android vendor/chipset strings now remain unverified inventory data and cannot grant hardware-backed signing capability.

### P0: Public decentralized-signing qualification
- Maintain the public non-release conformance proof and tamper-rejecting OpenSSL verifier.
- Execute the seven-system signing inventory in `docs/architecture/decentralized-signing-inventory.json`.
- Treat the current three-key, single-account/single-region AWS KMS set as centralized P-256 signing connectivity only.
- Build independently administered secp256k1/BIP340-capable signer domains, authenticated DKG/nonce/recovery ceremonies, public negative vectors, independent review, and release-bound evidence before production promotion.

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
