# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Hardened BIP-322 Verification: Full proof-of-ownership support for Legacy (P2PKH, P2SH), SegWit, and Taproot addresses.
- `Unsupported` variant to `ConclaveError` for explicit 'Fail-Closed' feature gating.
- `base64` dependency for secure signature witness decoding in Bitcoin protocols.

### Changed
- Updated `GAP_SCORECARD.md` and `SYSTEM_ALIGNMENT.md` to v2.0.3 status.
- Expanded BIP-322 test suite to include mainnet legacy address validation.

## [0.2.0] - 2026-05-14

### Added
- Rootstock (RSK) and BOB (Bitcoin on Build) support in `Chain` and `AssetRegistry`.
- `BitcoinManager` in `src/protocol/bitcoin.rs` for BDK-compatible descriptor generation (SegWit/Taproot).
- `sign_bitvm_challenge` in `TaprootManager` to support BitVM-style interactions.
- Comprehensive unit tests for Bitcoin L2 registration and wallet logic.

## [0.1.3] - 2026-04-29

### Fixed
- Protocol Integrity: Implemented deterministic intent hashing in `RailProxy` to prevent signature verification failures caused by `HashMap` iteration order non-determinism.

### Added
- Specific test case for verifying hash determinism across multiple iterations.

## [0.1.2] - 2026-04-24

### Added
- `IdentityManager` in `src/protocol/identity.rs` for hardware-backed Personal Sovereign Identity (PSI).
- `ZkmlService` in `src/protocol/zkml.rs` for Zero-Knowledge Machine Learning compliance proofs.
- `DlcManager` in `src/protocol/dlc.rs` for Discreet Log Contract support.
- `SidlService` in `src/protocol/sidl.rs` for Sovereign Identity Layer governance.
- `create_personal_identity` and `generate_zkml_proof` to WASM bindings.
- `docs/SYSTEM_ALIGNMENT.md` for v1.9.2 status tracking.

### Fixed
- Remediated `RUSTSEC-2025-0055` by locking `sha2` version.
- Completed integration of shared services into `ConclaveWasmClient`.
- Updated `REMEDIATION.md` with final v1.9.2 status.

## [0.1.1] - 2026-04-18

### Added
- `contracts/oracle/oracle-aggregator.clar` for fail-closed price aggregation.
- `contracts/oracle/dimensional-oracle.clar` for multi-dimensional market data with confidence checks.
- `contracts/core/risk-manager.clar` for health-factor and liquidation logic.
- `contracts/core/admin-facade.clar` for explicit RBAC on privileged paths.
- `contracts/core/emergency-control.clar` for centralized circuit breaking.
- `contracts/lending/lending-manager.clar` for solvent lending operations.
- Explicit quorum tracking in `oracle-aggregator.clar`.
- Active circuit breaker and solvency cross-calls in `lending-manager.clar`.

### Changed
- Downgraded `sha2` to `0.10.8` to resolve dependency conflict with `hmac`, `pbkdf2`, and `k256`.
- Updated `REMEDIATION.md` with Oracle, Risk, and Admin implementation details.

## [0.1.0] - 2026-04-12

### Added
- Automated Repository Hygiene checks in CI to prevent tracked secrets and testnet contamination.
- Comprehensive unit tests for `IdentityManager`, `ZkmlService`, `DlcManager`, `SidlService`, and `MmrService`.
- Functional `execute_swap` implementation for all Sovereign Rails (Changelly, Bisq, Wormhole, Boltz, NTT).
- Network-backed `create_session` in `FiatRouterService` and `A2pRouterService`.
- TEE-verified proposal-only external settlement triggers (CON-162).
- `GOVERNANCE.md` defining the SDK's business role and ownership.
- GitHub Actions CI workflow for Rust tests, linting, and WASM builds.

### Changed
- Refactored `RailProxy` to inject the gateway endpoint into all registered Rails.
- Refactored `BusinessRegistry` and `AssetRegistry` to use thread-safe interior mutability (`RwLock`).
- Enforced "No-Panic" standards across core SDK modules.
- Updated documentation to reflect v1.9.2 standards.
