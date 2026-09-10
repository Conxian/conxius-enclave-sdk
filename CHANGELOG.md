# Changelog

## [Unreleased]

### Added
- `src/protocol/babylon.rs`: Hardened Babylon BTC Staking protocol with Extractable One-Time Signatures (EOTS) primitives — added `BabylonEotsCommitment` hash computation, `BabylonEotsSignature` verification, double-signing detection at identical height/round, and algebraic slashing secret key extraction (`extract_slashing_key`) (SDK-005).
- `src/protocol/rgb.rs`: Hardened RGB Client-Side Validated Asset protocol with blinded single-use seals (`RgbBlindedSeal`), UTXO blinding factor verification (`verify`), asset allocation assignments (`RgbAssetAllocation`), and batch transition signing through UCS (`RgbBatchTransition`) (SDK-006).
- `docs/architecture/GAP_SCORECARD.md` & `DEBT_INVENTORY.md`: Updated Session 73/74 gap research synthesis, candidate evaluation rubric, and verified end-to-end multi-chain protocol support status.
- `docs/guides/CLIENT_ONBOARDING_AND_DEPLOYMENT_SPEC.md`: Created comprehensive client installation, onboarding, purchasing, and deployment specification. Details Enterprise Vault, Managed Gateway, and Operator Signer tiers, configuration inputs (AWS Nitro KMS keys, Android StrongBox, Neon PostgreSQL, Redis), 4-layer connectivity graph, and unified CLI installer (`conxius-ctl`) design.
- Fixed compiler warnings in `src/protocol/frost.rs` non-crypto build configurations for unused `_raw_package_bytes` parameters.

### Added
- `src/protocol/frost.rs`: Fixed unused parameter warnings in non-frost-crypto build configurations for `verify_dkg_round1_bytes` and `verify_dkg_round2_bytes`.
- Candidate Scoring & Audit Sync: Evaluated all 6 open GitHub issues and updated 75-point candidate matrix in `DEBT_INVENTORY.md` and `GAP_SCORECARD.md` establishing `#200 WASM Secret Isolation` (61/75) as top actionable non-external candidate.
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
