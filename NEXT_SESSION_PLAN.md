# Next Session Plan

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

## Session 83 Completed (2026-10-11) — Turnkey Enclave Pre-Attested WASM Execution Harness Implementation

### ✅ Turnkey Enclave Pre-Attested WASM Execution Harness
- Implemented  and  in  and re-exported in .
- Enforced fail-closed validation (,  on zero measurements) and memory zeroization of wrapped secret inputs via .
- Added unit tests () verifying context instantiation, zero measurement rejection, runtime rejection, and secret memory access.

### ✅ Capability Evidence & Knowledge Base Synchronization
- Regenerated  via wrote generated capability matrix: /app/docs/architecture/CAPABILITY_MATRIX.md.
- Updated , , , , and .

---

## Session 84 Completed (2026-10-12) — BitVM2 Watchtower Challenge & KMaaS Policy Enforcement

### ✅ Automated BitVM2/Ark Challenge Watchtower Execution
- Extended `BitVm2Orchestrator` in `src/protocol/bitvm2.rs` with `register_active_challenge` and `trigger_watchtower_challenge` methods for automated challenge-response transaction triggering on fraudulent state root commitments.

### ✅ Hardware Key Management as a Service (KMaaS) Policy Enforcement
- Extended `ThresholdEnclaveManager` in `src/enclave/threshold.rs` with `with_max_value_limit` and value limit policy checks in `sign_value_bearing_provider`.

---

## Session 85 Planned

### P0: Independent Security Review & Release Acceptance (#202)
- Maintain tracking for independent security auditor review evidence and release acceptance artifacts.
