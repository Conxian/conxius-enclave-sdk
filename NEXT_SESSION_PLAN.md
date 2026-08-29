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

### P0: Finish #271 (channel state machine)
- Route-finding is implemented (`LightningRouter::find_route` + `LightningPaymentIntent::compute_route`); the remaining `#271` "Required" item is a channel state machine. Implement or explicitly narrow scope, then close.

### P0: Operationalize #240 trust/collateral items (trust store side)
- The replay backend (`FileBackedDurableReplayStore`) is done; remaining `#240` acceptance items are versioned authenticated root/collateral bundles as release inputs, deterministic revocation/expiry/TCB/freshness enforcement, and recovery/rotation/audit tests on the `TrustBundle` surface.

### P0: Remaining provider/runtime evidence gates (external-blocked)
- `#242` AWS Nitro live attestation + KMS boundary (requires AWS deployment).
- `#241` Android KeyMint/StrongBox + Play Integrity (requires real device).
- `#200` WASM runtime/platform evidence (requires headless browser/Node).
- `#202` independent security review + release acceptance (requires external reviewer).

### P1: Fedimint real threshold BLS blinding (DEBT PROTO-001)
- Replace Fedimint structural-only path with real BLS12-381 threshold blinding/DLEQ validation (now that `bls12_381` is a dependency).

---
