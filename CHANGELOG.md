# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive unit tests for `IdentityManager`, `ZkmlService`, `DlcManager`, `SidlService`, and `MmrService`.

### Changed
- Refactored `MmrService`, `FiatRouterService`, and `A2pRouterService` to use a shared `reqwest::Client` for better resource management.
- Cleaned up modular rail structure in `src/protocol/rails/`.

### Added
- Functional `execute_swap` implementation for all Sovereign Rails (Changelly, Bisq, Wormhole, Boltz, NTT) replacing mock responses with real Gateway API interactions (CON-409).
- Network-backed `create_session` in `FiatRouterService` to communicate with Conxian Gateway for stateless fiat on-ramps.
- Network-backed `initiate_verification` and `verify_otp` in `A2pRouterService` for secure hardware-attested phone verification.
- `set_gateway_url` method to `ConclaveWasmClient` for dynamic environment configuration.
- TEE-verified proposal-only external settlement triggers (CON-162).
- `SettlementTrigger` and `SettlementProposal` structures for ISO 20022, PAPSS, and BRICS integration.
- Mandatory 144-block time-lock and 5/5/90 yield routing logic for settlement proposals.
- `SettlementManager` and `ConclaveSettlementService` for secure trigger processing within TEE.
- `create_settlement_proposal` method in WASM bindings.
- `GOVERNANCE.md` defining the SDK's business role, ownership, and integration surface.
- Prioritized build/repair list for Mainnet Readiness in `GOVERNANCE.md`.
- GitHub Actions CI workflow for Rust tests, linting, and WASM builds.
- CI status badges to README.
- `Default` implementations for core registries and managers to improve idiomatic Rust usage.
- `cdylib` crate-type to `Cargo.toml` for WASM compatibility.

### Changed
- Refactored `RailProxy` to inject the gateway endpoint into all registered Rails.
- Updated `ConclaveWasmClient` to use the unified gateway URL for all protocol services.
- Refactored `BusinessRegistry` and `AssetRegistry` to use thread-safe interior mutability (`RwLock`), preventing runtime panics during registration.
- `CloudEnclave::with_dev_key` now returns `ConclaveResult<Self>` instead of panicking on invalid key bytes.
- ISO 20022 trigger validation now requires `<Document>` as the XML root element and rejects extra content outside it.
- Normalized SDK naming and discovery across documentation and external issue tracking (CON-171).
- Switched test cases from testnet (`ST...`) to mainnet (`SP...`) principal examples.
- Updated `RELEASING.md` with detailed release flow and security audit requirements.
- Improved idiomatic Rust and fixed 14 Clippy warnings across the codebase.
- Enforced "No-Panic" standards across core SDK modules (`src/enclave`, `src/state`) by replacing `unwrap()` with safe error handling.
- Updated documentation to reflect the current verified toolchain (Rust 1.94+).
- Clarified repository categorization as a "Security Infrastructure SDK".

### Removed
- Removed mock response logic from `src/protocol/fiat.rs` and `src/protocol/a2p.rs`.
- Removed `Cargo.lock` from Git tracking as per repository standards.

### Fixed
- Remediated mock logic in `CloudEnclave` and `CoreEnclaveManager` to support production-grade operations (CON-409).
- Strengthened `SettlementManager` and `SettlementService` validation for ISO 20022 and enforced the 144-block timelock policy (CON-409).
- Updated WASM bindings to include missing `unlock_enclave` and session management methods for high-fidelity integration.

## [0.1.1] - 2026-04-18

### Added
- `contracts/oracle/oracle-aggregator.clar` for fail-closed price aggregation.
- `contracts/oracle/dimensional-oracle.clar` for multi-dimensional market data with confidence checks.

### Changed
- Downgraded `sha2` to `0.10.8` to resolve dependency conflict with `hmac`, `pbkdf2`, and `k256`.
- Updated `REMEDIATION.md` with Oracle implementation details.

### Added
- `contracts/core/risk-manager.clar` for health-factor and liquidation logic.
- `contracts/core/admin-facade.clar` for explicit RBAC on privileged paths.

## [0.1.1] - 2026-04-18

### Added
- `contracts/oracle/oracle-aggregator.clar` for fail-closed price aggregation.
- `contracts/oracle/dimensional-oracle.clar` for multi-dimensional market data with confidence checks.
- `contracts/core/risk-manager.clar` for health-factor and liquidation logic.
- `contracts/core/admin-facade.clar` for explicit RBAC on privileged paths.

### Changed
- Downgraded `sha2` to `0.10.8` to resolve dependency conflict with `hmac`, `pbkdf2`, and `k256`.
- Updated `REMEDIATION.md` with Oracle, Risk, and Admin implementation details.

### Added
- `contracts/core/emergency-control.clar` for centralized circuit breaking.
- `contracts/lending/lending-manager.clar` for solvent lending operations.

### Added
- Explicit quorum tracking in `oracle-aggregator.clar`.
- Active circuit breaker and solvency cross-calls in `lending-manager.clar`.

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
