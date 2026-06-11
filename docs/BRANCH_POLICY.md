# Branch Protection & CI Policy (CON-520)

To ensure the integrity of the production codebase, all core Conxian repositories must adhere to the following branch protection and required-check baseline.

## 1. Protected Branches
- **Branch**: `main`.
- **Standard**: Strictly for mainnet-ready, production code.
- **Rule**: Direct commits are prohibited. All changes must arrive via Pull Request.

## 2. Pull Request Requirements
- **Mandatory Review**: At least one approval from a designated owner (see `CODEOWNERS`) is required.
- **Review Scope**: Focus on security boundaries, Zero Secret Egress compliance, and No-Panic standards.
- **Merge Method**: Squash merge is preferred to maintain a clean, linear history.

## 3. Required CI Checks
The following checks must pass before a Pull Request can be merged:
- **Rust Tests**: `cargo test` must pass all units and integration tests.
- **Linting**: `cargo fmt --check` and `cargo clippy -- -D warnings` must pass.
- **Hygiene**: No testnet principals (`ST...`), forbidden extensions (`.key`, `.pem`), or sensitive files (`.env`) permitted in production paths.
- **WASM Build**: `wasm-pack build` must succeed for SDK repositories.

## 4. Release Pipeline
- **Validation**: High-risk changes should be validated on a `staged` branch before merging to `main`.
- **Changelog**: Every PR that modifies logic must update `CHANGELOG.md` under the `[Unreleased]` section.
- **Versioning**: Version bumps must follow SemVer and occur during the final release tag workflow.

## 5. Drift Control
- Monthly audits are performed to ensure repositories haven't drifted from these standards.
- Any repository found with direct commits to `main` or bypassed CI checks will be flagged for immediate remediation.
