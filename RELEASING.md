# Releasing conxius-enclave-sdk

This document defines the release process for `conxius-enclave-sdk`.

All releases must follow [Governance](GOVERNANCE.md) and [Security](SECURITY.md), and versioning must follow [Semantic Versioning](https://semver.org/).

## Versioning Policy

- **Major (`X.Y.Z` → `(X+1).0.0`)**: Incompatible API changes.
- **Minor (`X.Y.Z` → `X.(Y+1).0`)**: Backward-compatible additive features.
- **Patch (`X.Y.Z` → `X.Y.(Z+1)`)**: Backward-compatible bug fixes and maintenance updates.

### Beta-phase note (`0.x.y`)

During beta (`0.x.y`), breaking changes may occur in minor bumps (for example `0.2.3` → `0.3.0`). Patch releases remain backward-compatible.

## Required Automation and Gates

The repository now enforces release readiness through GitHub Actions:

- `CI` workflow: tests, lint, and wasm build on push/PR to `main`.
- `Security` workflow: `cargo audit` + `cargo deny` on push/PR/schedule.
- `CodeQL` workflow: Rust static analysis on push/PR/schedule.
- `Release Strict` (`.github/workflows/release-strict.yml`) is the sole authoritative release workflow:
  - Runs automatically on `vX.Y.Z` tag push.
  - Validates the committed lockfile and pinned Rust toolchain.
  - Packages the exact crate, records its checksum, generates an SPDX SBOM, and verifies build provenance.
  - Creates the GitHub Release with the evidence bundle after validation.
  - Publishes to crates.io through exactly one tag-triggered publisher protected by the `release` environment; the same job is available as a manual recovery path.
- `SBOM` (`.github/workflows/sbom.yml`) is non-release dependency validation and does not publish or attest a release.
- `Secret Scanning` runs a pinned, checksum-verified MIT-licensed Gitleaks history scan.

## Release Metadata Requirements

Before a release tag is pushed:

1. `Cargo.toml` `[package].version` must be the target release version (`X.Y.Z`).
2. `CHANGELOG.md` must include a version section for that release (not only `[Unreleased]`).
3. Release tags must use `vX.Y.Z` format and map to the same Cargo version.
4. `Cargo.lock` must be committed and pass `cargo metadata --locked`.
5. The supported dependency MSRV is Rust `1.94.1`; CI and release jobs use the pinned Rust `1.97.1` toolchain.

These checks are enforced by CI and release workflows.

## GitHub Release Environment Setup

1. Open the repository in GitHub and go to **Settings** → **Environments**.
2. Create (or open) an environment named `release`.
3. In that environment, under **Environment secrets**, click **Add secret**.
4. Add secret name `CARGO_REGISTRY_TOKEN` and set it to the crates.io API token used for publishing.

## Manual Publish Recovery Checklist

- Go to **Actions** → **Release Strict** → **Run workflow**.
- Set **Use workflow from** to the release tag (`vX.Y.Z`).
- Set `release_version` to `X.Y.Z` or `vX.Y.Z` matching the tag/Cargo version.
- Set `publish_to_crates_io` to `true` only when recovering a validated tag run.
- Verify `validate-release`, `sbom-provenance`, and provenance verification pass before approving the environment.
- Verify the expected version appears on crates.io.

## Release Flow

1. **Prepare release commit**
   - Move release notes from `[Unreleased]` to a new version section in `CHANGELOG.md`.
   - Set `Cargo.toml` version to that same version.
   - Run local preflight checks (below).

2. **Merge to `main`**
   - Release metadata changes must land on default branch before tagging.

3. **Create and push release tag**
   ```bash
   git tag -s vX.Y.Z -m "Release vX.Y.Z"
   git push origin main
   git push origin vX.Y.Z
   ```

4. **Verify tag gate run**
   - The `Release Strict` workflow runs automatically on tag push.
   - It validates metadata, runs locked tests/lint, packages the crate, writes a checksum, generates an SPDX SBOM, and verifies the package attestation.
   - It creates the GitHub Release with the crate, checksum, SBOM, and release manifest.
   - The single tag-triggered publisher runs after the validation, evidence, and provenance gates.

5. **Manual publish recovery (controlled)**
   - If the automatic publisher needs recovery, run the `Release Strict` workflow manually (`workflow_dispatch`) against the same tag with:
     - `release_version`: `X.Y.Z` or `vX.Y.Z`
     - `publish_to_crates_io`: `true`
   - Publishing requires `CARGO_REGISTRY_TOKEN` configured in the `release` environment.
   - The recovery path uses the same publisher job and evidence checks; it is not a competing publisher.

6. **Optional WASM package publication**
   - Build and inspect package contents before publishing:
   ```bash
   wasm-pack build --release --target bundler
   cd pkg
   TARBALL="$(npm pack)"
   tar -tzf "$TARBALL"
   npm publish "$TARBALL" --access public
   ```

## Local Preflight Commands

The repository commits `Cargo.lock`; do not regenerate or update it implicitly in CI. Use the pinned toolchain from `rust-toolchain.toml`:

```bash
rustup show active-toolchain
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo metadata --locked --format-version 1

# Security checks
cargo audit --file Cargo.lock
cargo deny --config deny.toml --locked check advisories bans licenses sources

# Package and evidence checks
cargo package --locked
cargo publish --locked --dry-run
.github/scripts/verify-release-metadata.sh X.Y.Z
.github/scripts/verify-release-artifacts.sh X.Y.Z <crate> <checksum> <sbom> [manifest]
```

The current repository metadata declares `2.0.12`, while the latest visible release/tag evidence remains `v2.0.11`. This hardening change does not change versions, create a tag, publish a package, or establish release acceptance.

## Mainnet Readiness and Security

- Versions `>= 1.0.0` require an independent security audit for handshake/enclave-critical paths.
- Resolve dependency advisories before release, or document explicit, committed policy exceptions.
- Ensure no credentials or local secrets are included in release artifacts.
