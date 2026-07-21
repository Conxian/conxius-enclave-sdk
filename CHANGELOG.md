# Changelog

## [Unreleased]

### Breaking
- **Breaking:** `ArkManager::with_backend` now returns `ConclaveResult<Self>` instead of `Self`; callers must handle the result. `ArkBackend::ProviderOwned` remains rejected with typed `ProtocolUnsupported`, and production/provider support remains unavailable pending issue #195. `ArkBackend::Unconfigured` remains the safe disabled variant and succeeds.

### Added
- Added `bip110_compliant` feature flag for BIP-110 Reduced Data Temporary Softfork compliance
- Added BIP-110 validator module with limits: 256-byte pushdata, 83-byte OP_RETURN, 34-byte ScriptPubKey
- Added message chunking utilities for BIP-322 under BIP-110 rules

### Changed
- Removed the WASM `derive_vutxo_key` private-key export and added provider-backed public-key/signing capability names.
- Made unsupported WASM runtimes, providers, BitVM2 construction, and secret-bearing Fedimint flows fail closed with typed error codes.
- Added the [WASM runtime/provider support matrix](docs/architecture/WASM_SUPPORT_MATRIX.md) and [key-boundary migration note](docs/migrations/wasm-key-boundary.md).

### Documentation

## [2.0.12] - 2026-07-15

### Fixed
- Refactored the BitVM2 vTXO tree-root helper into an associated function so stable Clippy passes.
- Bumped the crate version after v2.0.11 was already published to crates.io.

## [2.0.11] - 2026-07-15

### Added
- Added auto-create GitHub Release job on tag push
- Added auto-publish to crates.io on tag push

### Changed
- Fully automated release pipeline (tag → tests → SBOM → release → crates.io)

## [2.0.10] - 2026-07-15

### Fixed
- Resolved Rust 2024 let chain syntax issue in `rails/mod.rs` (refactored to nested if statements)
- Fixed missing struct fields in `ZkmlProofRequest` test (`proof_system`, `expected_output_hash`)
- Added `#[allow(dead_code)]` to unused `bitvm_manager` field in `bitvm2.rs`
- Fixed needless borrow clippy warning in `fedimint.rs` `create_dleq_proof`
- Fixed WASM mutable borrow errors in `WasmBitVm2Orchestrator` using `Arc<RefCell<>>`

### Added
- Comprehensive hardware attestation test suite with 25 tests covering trust tiers, freshness, replay protection, and trust enforcement
- Session Continuity Protocol in AGENTS.md for strict production verification

### Documentation
- Fixed version staleness across AGENTS.md, README.md, and TRACKING.md
- Updated REPOSITORY_ANALYSIS.md to v2.0.9 with TEST-001 resolved
- Updated GAP_SCORECARD.md to v2.0.9
- Updated CODEOWNERS for hardware_attestation_tests.rs

## [2.0.9] - 2026-07-13

### Changed
- Renamed crate from `conxius-enclave-sdk` to `conxius-enclave-sdk` to match repository name

## [2.0.8] - 2026-07-13

### Added
- Local issue and PR tracking system with sync script
- Repository analysis documentation
- Production readiness checklist
- Strict CI/CD workflows (ci-strict, release-strict, security-strict)
- Branch protection policy documentation

### Changed
- Enforced strict release gate requiring both validation and SBOM jobs
- Improved provenance attestation workflow with better artifact detection
- Added required metadata fields for crates.io publication (description, docs, repository)
- Fixed SLSA provenance subject-path configuration

### Fixed
- Fixed `attest-build-provenance` action to use valid `subject-path` parameter
- Fixed library artifact filename detection (liblib_conclave_sdk.so pattern)
- Replaced hardcoded SIP-010 trait principal with portable inline trait definition

## [2.0.7] - 2026-07-05

### Added
- Support for joining Fedimint federations via invite codes in `FedimintAdapter`.
- Implementation of binary vTXO tree construction in `ArkManager` for multi-party exits.
- v2.0.7 alignment in `GAP_SCORECARD.md`.

### Changed
- Hardened Secp256k1 cryptographic operations in Fedimint nexus adapter.

## [2.0.6] - 2026-05-24

### Added
- Multi-federation support in `FedimintAdapter` with federation registration logic.
- Structural verification for OP_CAT (`BIP-347`) recursive invariants in `CovenantManager`.
- Hardened stateless recovery scan in `ArkManager` with safety boundaries and gap limit validation.
- WASM bindings for the new hardened features.

### Changed
- Refactored `FedimintAdapter` to use `Default` trait and registry-based architecture.

### Fixed
- Improved error paths and validation in Ark V-UTXO discovery.

## [2.0.5] - 2026-05-18

### Added
- Hardened FROST Round 3 signature share aggregation.
- Real Secp256k1-based Chaumian blinding in `FedimintAdapter`.
