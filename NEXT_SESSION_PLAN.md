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

### P0: Remaining provider/runtime evidence gates (external-blocked)
- `#242` AWS Nitro live attestation + KMS boundary (requires AWS deployment).
- `#241` Android KeyMint/StrongBox + Play Integrity (requires real device).
- `#200` WASM runtime/platform evidence (requires headless browser/Node).
- `#202` independent security review + release acceptance (requires external reviewer); `#240` item 6 depends on this.

### P0: Close-out bookkeeping for #271 + #240
- `#271`: confirm scope decision (metadata state machine + route-finding done; live LDK node out-of-scope) and post a close/narrow-scope comment.
- `#240`: confirm items 1-5,7 done and item 6 external-blocked; update the issue acceptance checklist.

### P1: Fedimint real threshold BLS blinding (DEBT PROTO-001)
- Replace Fedimint structural-only path with real BLS12-381 threshold blinding/DLEQ validation (now that `bls12_381` is a dependency).

---
