# Changelog

## [Unreleased]

### Added
- `src/enclave/android_authorization.rs`: Added comprehensive unit tests for `AndroidAuthorizationEvidence` validation, including Play Integrity evidence version/bounds checking, certificate chain size/byte limits, and timestamp lifetime/future-skew boundary verification (#241).
- `src/wasm_support.rs`: Added `test_wasm_runtime_unapproved_provider_error_code_stability` and `test_wasm_unverified_runtime_rejection_message` to harden WASM secret boundary enforcement and verify stable typed error codes (`UNSUPPORTED_PROVIDER`, `UNSUPPORTED_RUNTIME`) (#200).
- Knowledge Base & System Audit: Verified 70 capability evidence items, scored roadmap candidates via 75-point formula, and synchronized issue tracking indexes.

## [2.0.17]

### Added
- `src/protocol/lightning.rs`: Added `parse_and_validate_invoice` and `verify_settlement_preimage` on `LightningPaymentIntent` for BOLT11 invoice verification via `lightning-invoice` and SHA-256 settlement preimage checking (#271).
- `src/signing/lightning_signing.rs`: Added `sign_htlc_transaction` for HTLC success and refund transaction script signing through UCS (#271).
- `src/protocol/lightning.rs`: Added `LightningRouter::find_route` (deterministic, fail-closed Dijkstra route selection over a type-safe channel graph) and `LightningPaymentIntent::compute_route`, plus `LightningNetworkGraph`, `LightningChannelEdge`, `LightningRoute`, and `LightningRouteConstraints` types (#271).
- `src/protocol/lightning_channel.rs`: Added a fail-closed metadata channel state machine (`LightningChannel`) covering the funding/open/HTLC-settle/fail/cooperative-close/force-close lifecycle with a conserved capacity invariant and SHA-256 preimage settlement verification (#271).
- `src/enclave/replay_store_file.rs`: Added `DurableFileReplayStore`, the first `ReplayStore` adapter advertising `ReplayStoreDurability::DurableProvider`, with `fsync`-ed O_EXCL records, all-or-nothing `consume_once_batch`, a persisted anti-rollback high-water clock, and validation-before-time-observation; passes the backend-neutral consume-once conformance suite (#240).
- `src/protocol/ark.rs`: Removed residual fail-open/panic paths in `construct_vtxo_tree` — it no longer silently substitutes empty/zero txids (`unwrap_or_default`/zero-txid fallback) or panics on `.unwrap()`/`.expect()`; it now fails closed via `ConclaveError::InvalidConfiguration` (port of unmerged `c47b23fd`).
- `.gitignore`: Added explicit ignore rules for generated test and runtime artifacts (`test-results/`, `playwright-report/`, `coverage/`, `.nyc_output/`, `*.log`, `*.tmp`, `tmp/`, `.tmp/`, `.cache/`, `dist/`, `build/`).
- `src/protocol/nexus/fedimint_crypto.rs`: Added real BLS12-381 Fedimint e-cash primitives behind the `fedimint-crypto` feature — `FedimintG1Point`/`FedimintScalar` typed wrappers, `blind_message`/`unblind_signature`, and Chaum-Pedersen `FedimintDleqProof` generation + fail-closed verification with an RFC 6979-style deterministic nonce (PROTO-001).
- `src/protocol/nexus/fedimint.rs`: Wired `DleqProof::verify`, `FedimintAdapter::create_dleq_proof`, and `FedimintAdapter::create_blind_signature_request` to the real BLS12-381 `fedimint-crypto` backend under `#[cfg(feature = "fedimint-crypto")]`, ensuring fail-closed `ProtocolUnsupported` behavior when the feature is disabled (PROTO-001).

### Changed
- `Cargo.toml` / `Cargo.lock`: Downgraded the direct `bitcoin 0.33.0-beta` → `0.32.102` (converging on the stable `bdk_wallet` line) and bumped `secp256k1 0.32.0-beta.2` → `0.33.1`, fully removing the yanked `secp256k1 0.32.0-beta.2` from the dependency graph (#320).
- Migrated the `bitcoin` 0.33 modular API (`ScriptPubKeyBuf`/`ScriptSigBuf`/`TapScript*`, `Transaction { input, output }` + `TxOut.value`, `Witness::nth`, `Version::non_standard`, `XOnlyPublicKey::from_slice`/`to_byte_array`) to 0.32-compatible forms across `src/protocol/`, `src/signing/`, and `src/enclave/` (#320).

### Security & Governance
- Removed tracked root operational artifacts (`.audit_report_session57.md`, root `pre_commit_review.json`) from git, updated `.gitignore`, and hardened `.github/workflows/hygiene.yml` CI checks.
- `.github/workflows/hygiene.yml`: Hardened repository hygiene CI check to verify no tracked test-results, playwright-reports, coverage output, release evidence, or sensitive credentials/config files exist in git.

## [v2.0.16] - 2026-08-07

### Fixed
- Cargo.lock: root version synced to 2.0.15 (was 2.0.14), re-locked for CI Strict
- Cargo fmt: trailing blank lines removed from P1 cleanup (5 files)
- CI: all 10 workflow checks green after lockfile + format fixes
- Version bump to 2.0.16 for crates.io publish (v2.0.15 tag protected)
- DeepSeek CI review: JS template literals replaced with array concat (YAML parse fix)

## [v2.0.15] - 2026-08-05 (unreleased; version reverted to 2.0.14 for release alignment)
