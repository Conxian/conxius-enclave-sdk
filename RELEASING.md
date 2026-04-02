# Releasing lib-conclave-sdk

This document outlines the process for releasing new versions of the Conclave SDK. All releases must adhere to the [Governance](GOVERNANCE.md) and [Security](SECURITY.md) policies of the project.

## Versioning Policy

We strictly follow [Semantic Versioning (SemVer)](https://semver.org/).

- **Major (`X.Y.Z` → `(X+1).0.0`)**: Incompatible API changes (e.g., refactoring `EnclaveManager` trait).
- **Minor (`X.Y.Z` → `X.(Y+1).0`)**: Additive features in a backward-compatible manner (e.g., new `Rail` implementation).
- **Patch (`X.Y.Z` → `X.Y.(Z+1)`)**: Backward-compatible bug fixes, performance improvements, and technical debt (e.g., hygiene updates).

**Note on 0.y.z versions**: During the Beta phase (`0.y.z`), breaking changes may occur in minor releases (`0.y.0`).

## Release Flow

1. **Update CHANGELOG.md**: Move entries from `[Unreleased]` to a new version header with the current date. Ensure all changes are categorized (Added, Changed, Fixed, Removed).
2. **Bump Version**: Update the `version` field in `Cargo.toml`.
3. **Verify Build & Quality**:
   ```bash
   # Check formatting
   cargo fmt --all -- --check
   # Run clippy and fail on any warnings
   cargo clippy -- -D warnings
   # Run the full test suite
   cargo test
   # Check dependencies for known vulnerabilities (requires `cargo install cargo-audit`)
   cargo audit
   # Verify WASM build compatibility
   wasm-pack build
   ```
4. **Create Git Tag**: Create a signed git tag for the release.
   ```bash
   git tag -s vX.Y.Z -m "Release vX.Y.Z"
   ```
5. **Publish to crates.io**:
   ```bash
   cargo publish
   ```
6. **Publish WASM Package (if applicable)**: Publish the WASM npm package using the repo's chosen approach (e.g., `wasm-pack publish` or a reviewed wrapper package). Avoid publishing the generated `pkg/` directory without review.

## Mainnet Readiness & Security

- **Audit Requirements**: Versions >= 1.0.0 require a formal, independent security audit of the `Sovereign Handshake` and `EnclaveManager` implementations.
- **Dependency Hygiene**: Run the dependency vulnerability check from step 3 (e.g., `cargo audit`) before every release.
- **Credential Safety**: Ensure no development secrets or artifacts are included in the published package.
