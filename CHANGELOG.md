# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `GOVERNANCE.md` defining the SDK's business role, ownership, and integration surface.
- Prioritized build/repair list for Mainnet Readiness in `GOVERNANCE.md`.
- GitHub Actions CI workflow for Rust tests, linting, and WASM builds.
- CI status badges to README.
- `Default` implementations for core registries and managers to improve idiomatic Rust usage.
- `cdylib` crate-type to `Cargo.toml` for WASM compatibility.

### Changed
- Normalized SDK naming and discovery across documentation and external issue tracking.
- Updated `RELEASING.md` with detailed release flow and security audit requirements.
- Improved idiomatic Rust and fixed 14 Clippy warnings across the codebase.
- Updated documentation to reflect the current verified toolchain (Rust 1.94+).
- Clarified repository categorization as a "Security Infrastructure SDK".

### Removed
- Removed `Cargo.lock` from Git tracking as per repository standards.
