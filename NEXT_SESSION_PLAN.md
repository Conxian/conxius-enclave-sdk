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

## Session 84 Planned

### P0: Automated BitVM2/Ark Challenge Watchtower Mock Execution
- Extend  and  to support automated challenge-response transaction triggering on fraudulent state root detection.

### P0: Hardware Key Management as a Service (KMaaS) Policy Enforcement
- Extend  /  to support policy-enforced Hardware KMaaS signing limits and authorization rules.

### P0: Independent Security Review & Release Acceptance (#202)
- Maintain tracking for independent security auditor review evidence and release acceptance artifacts.
