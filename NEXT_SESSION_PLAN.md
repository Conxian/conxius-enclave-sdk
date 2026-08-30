# Next Session Plan

> **For**: OpenHands AI Agent  
> **Context**: Continuing Conxius Enclave SDK v2.0.16 development
> **Priority Order**: Remaining P0 gates → P1 → P2
> **Knowledge Base**: v0.7.0 (Session 62, Aug 2026)
> **Last Session**: Session 62 — Full scope #271 + #240 (channel state machine + durable ReplayStore provider)

---

## Session 60 Completed (2026-08-08)

### ✅ Comprehensive System Audit & Candidate 75-Point Scoring
- Audited remaining open issues and open PRs; updated 75-point candidate scoring matrix and selected `#271` (LDK Lightning Payment Execution Engine) as top candidate (71/75).

### ✅ LDK Lightning Payment Execution Engine (#271)
- Implemented `parse_and_validate_invoice` and `verify_settlement_preimage` in `src/protocol/lightning.rs`; `sign_htlc_transaction` in `src/signing/lightning_signing.rs`; unit tests.

## Session 61 Completed (2026-08-29)

### ✅ Full cycle re-sync
- `git fetch --all`, `scripts/sync_issues.sh` (39 issues / 279 PRs), org-wide audit (Conxian, 14 repos), gap scan (0 TODO/FIXME; 3 placeholders in ucs/statechain/dlc).

### ✅ Real Groth16 BLS12-381 pairing verification (#267) — P0
- Added `groth16 = ["dep:bls12_381"]` feature and `bls12_381 = "0.8"` (alloc/groups/pairings, optional).
- Rewrote `BitVm2Groth16Verifier::verify` to run the actual pairing equation and fail closed on malformed/off-curve/identity/arity-mismatch inputs; removed the prior fail-open path that returned `Valid` for arbitrary bytes.
- Tests: `groth16_verifier_verifies_genuine_proof`, `groth16_verifier_rejects_arity_mismatch`, `groth16_verifier_rejects_arbitrary_bytes_fail_closed`; clippy `-D warnings` clean; 564 (default) / 566 (groth16) tests pass.

---

## Session 62 Completed (2026-08-29)

### ✅ #271 — channel state machine (code-actionable scope complete)
- `src/protocol/lightning_channel.rs`: fail-closed metadata `LightningChannel` (funding/open/HTLC-settle/fail/cooperative-close/force-close), conserved capacity invariant, monotonic `commitment_number`, SHA-256 preimage settlement.
- Remaining `#271` items are live LND/LDK commitment/revocation coordination + gossip-based pathfinding — provider integration (external to this crate).

### ✅ #240 — durable ReplayStore provider (code-actionable scope complete)
- `src/enclave/replay_store_file.rs`: `DurableFileReplayStore` (`ReplayStoreDurability::DurableProvider`), passes the full backend-neutral consume-once conformance suite.
- Acceptance items 1,2,3,4,5,7 are code-complete; item 6 (artifact/SBOM/provenance/independent review) is external-blocked on #202.

---

## Session 63 — Planned

### P0: Unblock yanked `secp256k1` (#320)
- Bump `secp256k1` 0.32.0-beta.2 → 0.33.0 (non-yanked) in this SDK; re-verify FROST (`frost-secp256k1-tr` v3.0.0) compatibility.
- `cargo generate-lockfile` succeeds; `cargo test --locked` + clippy clean; `frost` feature tests pass.
- Publish a patch release and bump the `conxius-enclave-sdk` pin in `lib-conxian-core` → `conxian-nexus`, so nexus PR #250 can merge.
- **Research correction (Session 63):** bumping the direct `secp256k1` alone is **insufficient** — `bitcoin 0.33.0-beta` transitively depends on `secp256k1 ^0.32.0-beta.2` (yanked) and there is no stable `bitcoin 0.33.x` yet. A complete unblock also requires downgrading the direct `bitcoin` `0.33.0-beta` → `0.32.102` (converging on the `bdk_wallet` line) or waiting for stable `bitcoin 0.33.0`. Also drop the removed `rand` feature when bumping `secp256k1` → `0.33.x` (`features = ["recovery", "std"]`). Full analysis in `RESEARCH_LOG.md` (Session 63).

### P0: Finish the cross-repo replay/idempotency backend (conxian-nexus)
- After #320: land `IdempotencyStore` PR #250; wire to Neon `Conxian Nexus` (`DATABASE_URL` + run migration).
- Add the live-DB conformance suite (single/batch/restart/anti-rollback/retention/32-thread contention) mirroring `tests/durable_replay_conformance.rs` (nexus #251).

### P1: #271 — expand research + mainnet proofing (kept open)
- Research: BOLT12 offers, BIP-353, trampoline routing, splicing, async payments, MPP/AMP, blinded paths.
- Mainnet proofing: test vectors, signet/mainnet dry-runs vs LND/LDK, commitment/revocation interop.

### P0: Remaining provider/runtime evidence gates (external-blocked)
- `#242` AWS Nitro live attestation + KMS (AWS deployment); `#241` Android KeyMint/StrongBox (device); `#200` WASM runtime (headless browser/Node); `#240` item 6 / `#202` independent review (external).

### P1: Fedimint real threshold BLS blinding (DEBT PROTO-001)
- Replace Fedimint structural-only path with real BLS12-381 threshold blinding/DLEQ validation (now that `bls12_381` is a dependency).

---
