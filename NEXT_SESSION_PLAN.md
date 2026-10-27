# Next Session Plan

## Current P0 continuation — 20 October 2026

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


## Session 86 Completed (2026-10-27) — Decentralized Systems Interoperability, Production Readiness & Business Opportunities

### ✅ Research Expansion & Knowledge Base Synchronization
- Expanded `RESEARCH_LOG.md` with Session 86 research covering Phala Network dStack CVM TEEs, EigenLayer AVS watchtowers, Lit Network DKG/KMaaS, Nomic BTC & Babylon dual staking, Celestia/Avail DA, and IBC/Hyperlane/LayerZero/Wormhole bridges.
- Updated `docs/architecture/APPROVED_BRIDGE_AND_MESSAGING_SYSTEMS_BY_TRUST_TIER.md` with Section 6 defining trust-tier classifications, proof conditions, and commercial enablement rules for decentralized networks.
- Updated `DEBT_INVENTORY.md` and `docs/architecture/GAP_SCORECARD.md` (Score: 68).
- Created issue specification in `issues/0621.md` and updated tracking ledgers (`ISSUES_INDEX.md`, `TRACKING.md`).


## Session 87 Completed (2026-10-27) — Org-Wide Workload Management & Decentralized Systems Expansion

### ✅ Workload Governance & Knowledge Base Synchronization
- Expanded `RESEARCH_LOG.md` (Session 87) covering Pyth/Chainlink Oracles, Oasis Sapphire Confidential EVM, Arweave/Filecoin DA, Centrifuge RWAs, and Ritual/Akash AI compute.
- Updated `docs/architecture/APPROVED_BRIDGE_AND_MESSAGING_SYSTEMS_BY_TRUST_TIER.md` (Section 7) with trust-tier policies for decentralized compute, oracles, DA, and storage.
- Expanded `issues/0621.md` with anti-loop workload management directives and org-wide mitigation mappings.
- Updated `DEBT_INVENTORY.md`, `docs/architecture/GAP_SCORECARD.md`, `TRACKING.md`, and `.session/ledger.md`.

## Session 88 Planned

### P0: Decentralized Replay Consensus Specification (#240)
- Specify the Raft/Tendermint consensus engine interface for Phala dStack CVM nodes with Celestia DA blob archiving.

### P0: Multi-Hardware Attestation Policy Quorum (#195 / #242)
- Formalize 2-of-3 threshold hardware attestation policy evaluation across AWS Nitro, Phala SGX/TDX, and Lit Network MPC nodes.

### P0: Independent Security Review & Release Acceptance (#202)
- Maintain tracking for independent security auditor review evidence and release acceptance artifacts.
