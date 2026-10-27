# Next Session Plan

## Current P0 continuation — 27 October 2026

Session 86 completed research expansion on production readiness, issue resolution via decentralized system patterns (#200, #202, #240, #241, #242, #271), T1-T4 trust-tier bridge interoperability, and Conxian Nexus business opportunities (Turnkey KMaaS, WASM Compute, Autonomous SLA 80/10/10 yield splitting, x402 payment escrows).

### Planned Work for Session 87
1. **Phala dStack TEE WASM Execution Harness (#200)**: Complete integration of `WasmPreAttestationContext` and `WasmSecretBuffer` with Phala dStack TEE runtime environment.
2. **Cosmos IBC State Replay & High-Water Mark Replication (#240)**: Extend `DurableReplayStore` with Cosmos CometBFT light-client state proof verifiers for cross-region replay protection.
3. **Independent Security Review & Release Acceptance (#202)**: Maintain tracking for OpenSpec evidence pack, mainnet acceptance PR checks, and third-party security audit reports.
Lower-level #599 is integrated into dev and staged. Review the higher-level durable-request clock correction in `openspec/changes/2026-10-20-durable-request-clock/proposal.md` against its exact head: clock persistence precedes every record path, including duplicate/conflicting retries, with failure/recovery/restart regressions. Keep the mainnet acceptance pack and real #240/#202 outcomes open.

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

## Session 86/87 research intake correction (2026-10-27)

The decentralized-system list is retained as an unadopted candidate inventory. Earlier wording that described systems as approved, implemented, mitigating open issues, or commercially enabled was not supported by primary-source evidence or repository adoption and has been withdrawn.

### Next executable research steps
1. Consume the source-dated standards compatibility register maintained under Business #1390/#1423/#1424.
2. For each candidate, record primary sources, supported versions/contracts, maintenance status, license, security and trust assumptions, data rights, and exact applicability to an existing SDK issue.
3. Prefer maintained implementations and thin tested adapters. Do not design a custom replay consensus, attestation quorum, oracle, or bridge layer without an evidenced gap and an accepted OpenSpec.
4. Keep #200, #202, #240, #241, #242, and #271 open. Produce implementation and runtime evidence in their owning repositories before proposing any status change.
5. Preserve existing promotion, release, soak, CODEOWNERS, and independent acceptance controls.

### Scope boundaries
- Bitcoin-rooted universal-chain scope and zero-native-token policy remain unchanged.
- No staking/restaking, yield, RWA, pricing, treasury, custody, settlement, or production activation is authorized.
- Research recommendations are neither adopted policy nor conformance, deployment, or Mainnet proof.
