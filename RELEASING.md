# Releasing lib-conclave-sdk

This document defines the release process for `lib-conclave-sdk`.

All releases must follow [Governance](GOVERNANCE.md) and [Security](SECURITY.md), and versioning must follow [Semantic Versioning](https://semver.org/).

## Versioning Policy

- **Major (`X.Y.Z` → `(X+1).0.0`)**: Incompatible API changes.
- **Minor (`X.Y.Z` → `X.(Y+1).0`)**: Backward-compatible additive features.
- **Patch (`X.Y.Z` → `X.Y.(Z+1)`)**: Backward-compatible bug fixes and maintenance updates.

### Beta-phase note (`0.x.y`)

During beta (`0.x.y`), breaking changes may occur in minor bumps (for example `0.2.3` → `0.3.0`). Patch releases remain backward-compatible.

## Required Automation and Gates

The repository now enforces release readiness through GitHub Actions:

- `CI` workflow: tests, lint, and wasm build on push/PR to `master`.
- `Security` workflow: `cargo audit` + `cargo deny` on push/PR/schedule.
- `CodeQL` workflow: Rust static analysis on push/PR/schedule.
- `Release` workflow:
  - Runs automatically on `vX.Y.Z` tag push.
  - Runs manually via `workflow_dispatch` for controlled publish.
  - Uses `.github/scripts/verify-release-metadata.sh` to validate release metadata.

## Release Metadata Requirements

Before a release tag is pushed:

1. `Cargo.toml` `[package].version` must be the target release version (`X.Y.Z`).
2. `CHANGELOG.md` must include a version section for that release (not only `[Unreleased]`).
3. Release tags must use `vX.Y.Z` format and map to the same Cargo version.

These checks are enforced by CI and release workflows.

## Release Flow

1. **Prepare release commit**
   - Move release notes from `[Unreleased]` to a new version section in `CHANGELOG.md`.
   - Set `Cargo.toml` version to that same version.
   - Run local preflight checks (below).

2. **Merge to `master`**
   - Release metadata changes must land on default branch before tagging.

3. **Create and push release tag**
   ```bash
   git tag -s vX.Y.Z -m "Release vX.Y.Z"
   git push origin master
   git push origin vX.Y.Z
   ```

4. **Verify tag gate run**
   - The `Release` workflow runs automatically on tag push.
   - It validates metadata, runs `cargo test`, and runs `cargo publish --dry-run`.
   - No automatic crates.io publish occurs on tag push.

5. **Manual publish (controlled)**
   - If tag validation passes, run the `Release` workflow manually (`workflow_dispatch`) against that tag with:
     - `release_version`: `X.Y.Z` or `vX.Y.Z`
     - `publish_to_crates_io`: `true`
   - Publishing requires `CARGO_REGISTRY_TOKEN` configured in the `release` environment.

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

`Cargo.lock` remains untracked in this repository. Generate it locally/ephemerally for checks:

```bash
cargo fmt --all -- --check
cargo clippy -- -D warnings
cargo test

# Security checks
mkdir -p .cargo
cp audit.toml .cargo/audit.toml
cargo generate-lockfile
cargo audit --file Cargo.lock
cargo deny --locked check --config deny.toml advisories bans licenses sources
```

## Mainnet Readiness and Security

- Versions `>= 1.0.0` require an independent security audit for handshake/enclave-critical paths.
- Resolve dependency advisories before release, or document explicit, committed policy exceptions.
- Ensure no credentials or local secrets are included in release artifacts.
