# Next Session Plan

> **For**: OpenHands AI Agent  
> **Context**: Continuing Conxius Enclave SDK v2.0.17 development
> **Priority Order**: Remaining P0 gates â†’ P1 â†’ P2
> **Knowledge Base**: v0.7.0 (Session 62, Aug 2026)
> **Last Session**: Session 65 — doc-vs-code audit (module count + MSRV) remediation


## Session 66 Completed (2026-09-03) — Fedimint DLEQ proof integration (PROTO-001)

### ✅ Fedimint DLEQ proof wiring
- Wired `DleqProof::verify`, `FedimintAdapter::create_dleq_proof`, and `FedimintAdapter::create_blind_signature_request` in `src/protocol/nexus/fedimint.rs` to the real BLS12-381 `fedimint_crypto` backend under `#[cfg(feature = "fedimint-crypto")]`.
- Enforced fail-closed `ProtocolUnsupported` behavior when `fedimint-crypto` is disabled.
- Unit tests added for genuine proof verification, tampered proof rejection, and feature-gated fallback.

---

## Session 65 Completed (2026-09-01) — doc-vs-code audit (module count + MSRV) remediation

### ✅ Protocol module recount (SDK + core)
- Recounted `src/protocol/mod.rs` (43 non-test `pub mod` declarations): **43 protocol modules = 25 blockchain + 18 infrastructure**.
- Corrected `AGENTS.md` header (was "50 Modules (25 + 25)"; infrastructure list actually has 18, not 25), `Directory Map` ("50" → "43"), and removed the `enclave-poc/` references (Nitro POC lives in `lib-conxian-core`, not this repo).
- Corrected `lib-conxian-core/AGENTS.md` cross-reference ("52 (24 + 28)" → "43 (25 + 18)").

### ✅ MSRV regression fixed (core)
- `lib-conxian-core/Cargo.toml` `rust-version` was `1.94.0`, contradicting the v0.3.0 CHANGELOG ("Raised the package MSRV to Rust 1.97.1"), all docs (README/COMPATIBILITY/RELEASE_PROCESS/COVERAGE), and every sub-crate (tests + addons at `1.97.1`). Restored to `1.97.1`.

---

## Session 64 Completed (2026-08-31) — KB audit + live verification + crates.io cleanup

### ✅ KB → code → CI audit
- Read all KBs; aligned with verified repo/cross-repo state (module count 50, `re_exports.rs`→`lib.rs`, `SystemState`→`EnclaveManager`, v2.0.17, 42 chains, MSRV 1.97.1).

### ✅ Live verification (first full toolchain run)
- Rust 1.97.1: `cargo test --locked` 629 passed; `--all-features` 645 passed; `fmt` + `clippy -D warnings` clean.

### ✅ Dependency security scan
- `cargo audit` 0 vulns; `cargo deny` ok. Added `RUSTSEC-2023-0089` to `.cargo/audit.toml`; removed orphaned root `audit.toml`; reconciled DEP-002.

### ✅ crates.io cleanup
- Yanked `lib-conclave-sdk@2.0.8` (DEP-003 resolved) + `anya-core@1.2.0`.

### PRs
- #329 merged (this work).

---

## Session 63 Completed (2026-08-30) — Dependency spine + release remediation

### ✅ Yanked-crate purge (org-wide, P0 #320)
- `bitcoin 0.33.0-beta` → `0.32.102`, `secp256k1 0.32.0-beta.2` → `0.33.1` across SDK, `lib-conxian-core`, and `conxian-nexus`. Yanked crate = 0 occurrences in all three Rust lockfiles. PRs #321, #281, #280 (lib-core), #255 (nexus) merged.

### ✅ v2.0.17 release + CI remediation
- v2.0.17 released to crates.io (first tag free of the yanked crate). PRs #325 (bump), #326 (User-Agent 403 fix) merged.
- **Root-caused** the missing GitHub Releases: `verify-registry-artifact.sh` curl lacked `User-Agent` → crates.io 403 since v2.0.16.
- Backfilled GitHub Releases v2.0.16 + v2.0.17 manually; #327 (recovery tag-gate fix) **merged** (approved by `admin-conxian-labs`) and #328 (KB audit session 63) **merged** — release recovery can now run without a tag ref.

### ✅ Cross-repo hygiene
- Closed broken dependabot PRs: gateway #350 (Rust group break), Conxian #700 (npm lock drift).

---


## Session 60 Completed (2026-08-08)

### âś… Comprehensive System Audit & Candidate 75-Point Scoring
- Audited remaining open issues and open PRs; updated 75-point candidate scoring matrix and selected `#271` (LDK Lightning Payment Execution Engine) as top candidate (71/75).

### âś… LDK Lightning Payment Execution Engine (#271)
- Implemented `parse_and_validate_invoice` and `verify_settlement_preimage` in `src/protocol/lightning.rs`; `sign_htlc_transaction` in `src/signing/lightning_signing.rs`; unit tests.

## Session 61 Completed (2026-08-29)

### âś… Full cycle re-sync
- `git fetch --all`, `scripts/sync_issues.sh` (39 issues / 279 PRs), org-wide audit (Conxian, 14 repos), gap scan (0 TODO/FIXME; 3 placeholders in ucs/statechain/dlc).

### âś… Real Groth16 BLS12-381 pairing verification (#267) â€” P0
- Added `groth16 = ["dep:bls12_381"]` feature and `bls12_381 = "0.8"` (alloc/groups/pairings, optional).
- Rewrote `BitVm2Groth16Verifier::verify` to run the actual pairing equation and fail closed on malformed/off-curve/identity/arity-mismatch inputs; removed the prior fail-open path that returned `Valid` for arbitrary bytes.
- Tests: `groth16_verifier_verifies_genuine_proof`, `groth16_verifier_rejects_arity_mismatch`, `groth16_verifier_rejects_arbitrary_bytes_fail_closed`; clippy `-D warnings` clean; 564 (default) / 566 (groth16) tests pass.

---

## Session 62 Completed (2026-08-29)

### âś… #271 â€” channel state machine (code-actionable scope complete)
- `src/protocol/lightning_channel.rs`: fail-closed metadata `LightningChannel` (funding/open/HTLC-settle/fail/cooperative-close/force-close), conserved capacity invariant, monotonic `commitment_number`, SHA-256 preimage settlement.
- Remaining `#271` items are live LND/LDK commitment/revocation coordination + gossip-based pathfinding â€” provider integration (external to this crate).

### âś… #240 â€” durable ReplayStore provider (code-actionable scope complete)
- `src/enclave/replay_store_file.rs`: `DurableFileReplayStore` (`ReplayStoreDurability::DurableProvider`), passes the full backend-neutral consume-once conformance suite.
- Acceptance items 1,2,3,4,5,7 are code-complete; item 6 (artifact/SBOM/provenance/independent review) is external-blocked on #202.

---

## Session 63 â€” Planned

### P0: Unblock yanked `secp256k1` (#320)
- Bump `secp256k1` 0.32.0-beta.2 â†’ 0.33.0 (non-yanked) in this SDK; re-verify FROST (`frost-secp256k1-tr` v3.0.0) compatibility.
- `cargo generate-lockfile` succeeds; `cargo test --locked` + clippy clean; `frost` feature tests pass.
- Publish a patch release and bump the `conxius-enclave-sdk` pin in `lib-conxian-core` â†’ `conxian-nexus`, so nexus PR #250 can merge.
- **Research correction (Session 63):** bumping the direct `secp256k1` alone is **insufficient** â€” `bitcoin 0.33.0-beta` transitively depends on `secp256k1 ^0.32.0-beta.2` (yanked) and there is no stable `bitcoin 0.33.x` yet. A complete unblock also requires downgrading the direct `bitcoin` `0.33.0-beta` â†’ `0.32.102` (converging on the `bdk_wallet` line) or waiting for stable `bitcoin 0.33.0`. Also drop the removed `rand` feature when bumping `secp256k1` â†’ `0.33.x` (`features = ["recovery", "std"]`). Full analysis in `RESEARCH_LOG.md` (Session 63).

### P0: Finish the cross-repo replay/idempotency backend (conxian-nexus)
- ✅ `IdempotencyStore` PR #250 merged (2026-08-29). Remaining: wire to Neon `Conxian Nexus` (`DATABASE_URL` + run migration).
- Add the live-DB conformance suite (single/batch/restart/anti-rollback/retention/32-thread contention) mirroring `tests/durable_replay_conformance.rs` (nexus #251).

### P1: #271 â€” expand research + mainnet proofing (kept open)
- Research: BOLT12 offers, BIP-353, trampoline routing, splicing, async payments, MPP/AMP, blinded paths.
- Mainnet proofing: test vectors, signet/mainnet dry-runs vs LND/LDK, commitment/revocation interop.

### P0: Remaining provider/runtime evidence gates (external-blocked)
- `#242` AWS Nitro live attestation + KMS (AWS deployment); `#241` Android KeyMint/StrongBox (device); `#200` WASM runtime (headless browser/Node); `#240` item 6 / `#202` independent review (external).

### P1: Fedimint real threshold BLS blinding (DEBT PROTO-001)
- Replace Fedimint structural-only path with real BLS12-381 threshold blinding/DLEQ validation (now that `bls12_381` is a dependency).

---


## Session 67 Completed (2026-09-03) — BOLT12 Offers & BIP-353 Payment Domain Resolution (#271)
## Session 67 Completed (2026-09-03) — BOLT12 Offers & BIP-353 Payment Domain Resolution (#271)

### ✅ BOLT12 Offer Parsing & BIP-353 Payment Address Support
- Implemented `Bolt12Offer` and `Bip353PaymentAddress` structs with `parse_and_validate` methods in `src/protocol/lightning.rs`.
- Added unit tests for BOLT12 offer validation (`lno1` prefix, SHA-256 offer ID) and BIP-353 DNS payment domain addresses (`user@domain`).
- Verified zero clippy warnings and 586 passing unit/integration tests.

---

## Session 68 Completed (2026-09-03) — AWS Nitro Attestation & KMS Release Key Binding (#242)

### ✅ Configurable KMS Release Key Binding
- Added `with_kms_key_identifier_hash` builder method and `kms_key_identifier_hash: [u8; 32]` property to `AwsNitroVerifier` in `src/enclave/verifiers/nitro_verifier.rs`.
- Enabled callers and verifier registries to dynamically bind a 32-byte KMS key hash for release key authorization instead of defaulting to `[0u8; 32]`.
- Added unit test `nitro_verifier_binds_kms_key_hash` in `src/enclave/verifiers/nitro_verifier.rs`.

---

## Session 69 Planned

### P0: Android KeyMint/StrongBox Authorization & Play Integrity Verification (#241)
- Qualify Android KeyMint/StrongBox authorization and Play Integrity attestation verification boundaries in `src/enclave/android_authorization.rs` and `src/enclave/android_strongbox.rs`.

### P0: Attestation Roots & ReplayStore Operations (#240)
- Continue operationalizing attestation roots, collateral, and distributed replay store contracts.
