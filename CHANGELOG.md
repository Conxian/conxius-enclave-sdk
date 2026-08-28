# Changelog

## [Unreleased]

### Added
- `src/protocol/lightning.rs`: Added `parse_and_validate_invoice` and `verify_settlement_preimage` on `LightningPaymentIntent` for BOLT11 invoice verification via `lightning-invoice` and SHA-256 settlement preimage checking (#271).
- `src/signing/lightning_signing.rs`: Added `sign_htlc_transaction` for HTLC success and refund transaction script signing through UCS (#271).
- `.gitignore`: Added explicit ignore rules for generated test and runtime artifacts (`test-results/`, `playwright-report/`, `coverage/`, `.nyc_output/`, `*.log`, `*.tmp`, `tmp/`, `.tmp/`, `.cache/`, `dist/`, `build/`).

### Security & Governance
- `.github/workflows/hygiene.yml`: Hardened repository hygiene CI check to verify no tracked test-results, playwright-reports, coverage output, release evidence, or sensitive credentials/config files exist in git.

## [v2.0.16] - 2026-08-07

### Fixed
- Cargo.lock: root version synced to 2.0.15 (was 2.0.14), re-locked for CI Strict
- Cargo fmt: trailing blank lines removed from P1 cleanup (5 files)
- CI: all 10 workflow checks green after lockfile + format fixes
- Version bump to 2.0.16 for crates.io publish (v2.0.15 tag protected)
- DeepSeek CI review: JS template literals replaced with array concat (YAML parse fix)

## [v2.0.15] - 2026-08-05 (unreleased; version reverted to 2.0.14 for release alignment)
