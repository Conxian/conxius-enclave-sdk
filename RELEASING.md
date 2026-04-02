# Releasing lib-conclave-sdk

This document outlines the process for releasing new versions of the Conclave SDK. All releases must adhere to the [Governance](GOVERNANCE.md) and [Security](SECURITY.md) policies of the project.

## Versioning Policy

We strictly follow [Semantic Versioning (SemVer)](https://semver.org/).

- **Major (`X.Y.Z` → `(X+1).0.0`)**: Incompatible API changes (e.g., refactoring `EnclaveManager` trait).
- **Minor (`X.Y.Z` → `X.(Y+1).0`)**: Backward-compatible additive features (e.g., new `Rail` implementation).
- **Patch (`X.Y.Z` → `X.Y.(Z+1)`)**: Backward-compatible bug fixes, performance improvements, documentation updates, and technical debt (e.g., hygiene updates).

**Note on 0.x.y versions**: During the Beta phase (`0.x.y`), this is an intentional exception to the usual backward-compatible minor rule: breaking changes may occur in minor releases (e.g., `0.2.3` → `0.3.0`), while patch releases remain backward-compatible (e.g., `0.2.3` → `0.2.4`).

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
   # Check dependencies for known vulnerabilities (first-time install: `cargo install cargo-audit --locked`)
   cargo audit
   # Verify WASM build compatibility (produces ./pkg/)
   wasm-pack build --release --target bundler
   ```
4. **Create Release Commit**: Commit the release version and changelog updates.
   ```bash
   git add CHANGELOG.md Cargo.toml
   git commit -m "Release vX.Y.Z"
   ```
5. **Create Git Tag**: Create a signed git tag for the release.
   ```bash
   git tag -s vX.Y.Z -m "Release vX.Y.Z"
   git push origin master --follow-tags
   ```
6. **Publish to crates.io**:
   ```bash
   cargo publish
   ```
7. **Publish WASM Package (if applicable)**: Publish the generated WASM npm package from `pkg/` after inspecting what will be shipped.
   ```bash
   cd pkg
   TARBALL="$(npm pack)"
   tar -tzf "$TARBALL"
   npm publish "$TARBALL" --access public
   ```

## Mainnet Readiness & Security

- **Audit Requirements**: Versions >= 1.0.0 require a formal, independent security audit of the `Sovereign Handshake` and `EnclaveManager` implementations.
- **Dependency Hygiene**: Ensure the dependency vulnerability check from step 3 (`cargo audit`) runs and passes before every release (prefer CI as the release gate; local runs are a preflight). If advisories are found, fix them before releasing or document an explicit exception via a committed `audit.toml` policy.
- **Credential Safety**: Ensure no development secrets or artifacts are included in the published package.
