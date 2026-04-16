# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Updated documentation to reflect the current verified toolchain (Rust 1.94+).
- Clarified repository categorization as a "Security Infrastructure SDK".

### Removed
- Removed mock response logic from `src/protocol/fiat.rs` and `src/protocol/a2p.rs`.
- Removed `Cargo.lock` from Git tracking as per repository standards.

### Fixed
- Remediated mock logic in `CloudEnclave` and `CoreEnclaveManager` to support production-grade operations (CON-409).
- Strengthened `SettlementManager` and `SettlementService` validation for ISO 20022 and enforced the 144-block timelock policy (CON-409).
- Updated WASM bindings to include missing `unlock_enclave` and session management methods for high-fidelity integration.
