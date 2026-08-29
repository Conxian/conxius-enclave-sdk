# Next Session Plan

> **For**: OpenHands AI Agent  
> **Context**: Continuing Conxius Enclave SDK v2.0.16 development
> **Priority Order**: Remaining P0 gates → P1 → P2
> **Knowledge Base**: v0.6.2 (Session 61, Aug 2026)
> **Last Session**: Session 61 — Real Groth16 BLS12-381 pairing verification (#267)

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

## Session 62 — Planned

### P0: Close the implemented-but-open issues (#267, #271)
- `#267` Groth16 pairing verification is implemented and tested; confirm no residual acceptance items and close the issue with a completion note.
- `#271` LDK payment execution is implemented; confirm remaining sub-items (route-finding / channel state machine) are either complete or explicitly deferred, then close or narrow scope.

### P0: Durable distributed replay backend (#240 / G240-RP, score 66)
- Promote the in-memory `ReplayStore`/`MockDurableReplayBackend` contract to a real durable backend adapter (DynamoDB conditional-write or PostgreSQL `ON CONFLICT`) behind the provider-neutral `ReplayStore` trait; keep production status gated pending provider/runtime evidence.

### P0: Remaining provider/runtime evidence gates (external-blocked)
- `#242` AWS Nitro live attestation + KMS boundary (requires AWS deployment).
- `#241` Android KeyMint/StrongBox + Play Integrity (requires real device).
- `#200` WASM runtime/platform evidence (requires headless browser/Node).
- `#202` independent security review + release acceptance (requires external reviewer).

### P1: Fedimint real threshold BLS blinding (DEBT PROTO-001)
- Replace Fedimint structural-only path with real BLS12-381 threshold blinding/DLEQ validation (now that `bls12_381` is a dependency).

---
