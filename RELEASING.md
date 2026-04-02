# Releasing lib-conclave-sdk

This document outlines the process for releasing new versions of the Conclave SDK.

## Versioning Policy

We follow [Semantic Versioning (SemVer)](https://semver.org/).

- **Major**: Incompatible API changes (e.g., refactoring `EnclaveManager` trait).
- **Minor**: Additive features in a backward-compatible manner (e.g., new `Rail` implementation).
- **Patch**: Backward-compatible bug fixes and technical debt (e.g., hygiene updates).

## Release Flow

1. **Update CHANGELOG.md**: Move entries from `[Unreleased]` to a new version header with the current date.
2. **Bump Version**: Update `version` in `Cargo.toml`.
3. **Verify Build**:
   ```bash
   cargo fmt --all -- --check
   cargo clippy -- -D warnings
   cargo test
   wasm-pack build
   ```
4. **Git Tag**: Create a signed git tag.
   ```bash
   git tag -s v0.1.x -m "Release v0.1.x"
   ```
5. **Publish**: Publish to crates.io manually.
   ```bash
   cargo publish
   ```

## Mainnet Readiness

Versions >= 1.0.0 require a full independent security audit of the `Sovereign Handshake` and `EnclaveManager` implementations.
