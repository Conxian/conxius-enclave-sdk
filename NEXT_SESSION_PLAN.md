# Next Session Plan

> **For**: OpenHands AI Agent  
> **Context**: Continuing Conclave SDK v2.0.12 development  
> **Priority Order**: P1 → P2 → P3
> **Knowledge Base**: v0.4.2

## Ordered end-of-sprint follow-up (2026-07-20)

This sequence advances [issue #191](https://github.com/Conxian/conxius-enclave-sdk/issues/191) while keeping containment evidence separate from production-readiness claims:

1. Obtain review and merge [PR #214](https://github.com/Conxian/conxius-enclave-sdk/pull/214), which records the current fail-closed containment slice and remains the implementation system of record for that work.
2. After #214 is reviewed, inspect draft [PR #205](https://github.com/Conxian/conxius-enclave-sdk/pull/205) and split/reconcile only the valuable provider-wrapper changes into independently reviewable work; do not wholesale-merge, overwrite, or close the draft.
3. Keep WASM secret-boundary and runtime/platform evidence under [issue #200](https://github.com/Conxian/conxius-enclave-sdk/issues/200) and [PR #211](https://github.com/Conxian/conxius-enclave-sdk/pull/211); do not move that lane into the containment or tracking PR.
4. Implement the typed operation/provider envelope and complete key/algorithm/provider binding under [issue #195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), preserving the fail-closed behavior while provider verification and hardware evidence are incomplete.
5. Once the implementation and provider evidence are independently reviewable, pursue the independent security review and release acceptance gate in [issue #202](https://github.com/Conxian/conxius-enclave-sdk/issues/202). Do not treat passing local or GitHub checks as a substitute for this gate.

### Deferred capability evidence-index update

Open [PR #210](https://github.com/Conxian/conxius-enclave-sdk/pull/210) owns `docs/architecture/capability-evidence.json` and the generated `docs/architecture/CAPABILITY_MATRIX.md`; open [PR #211](https://github.com/Conxian/conxius-enclave-sdk/pull/211) owns the WASM documentation lane. The current capability validator passes, but this branch intentionally leaves both evidence files untouched to avoid overlap. After #210 is resolved, add explicit PR #214 containment/test references only if the schema still supports them, keep `productionSupport` false or conditional as appropriate, and regenerate the matrix through the validator.

Do not change `README.md`, `PRODUCTION_READINESS.md`, security/releasing documents, or workflows in this tracking PR; those paths remain owned by the open lanes and the repository remains Beta / conditional.

## Current Follow-up

The machine-first capability evidence follow-up to merged PR #193 is recorded in `docs/architecture/capability-evidence.json` and generated into `docs/architecture/CAPABILITY_MATRIX.md`. The next session must continue with evidence work, not infer production support from API rows, unit tests, WASM builds, or historical closed issues.

Remaining gates are already tracked by GitHub #195–#202. Prioritize hardware-backed signing/attestation, canonical cryptographic verification, placeholder quarantine, reproducible release artifacts, and WASM runtime/secret-boundary evidence. Do not create duplicate issues.

---

## Session Startup Checklist

```bash
# 1. Pull latest changes
git pull origin main

# 2. Sync issues and PRs from GitHub (MANDATORY)
./scripts/sync_issues.sh

# 3. Verify build (MANDATORY - blocks work until passing)
cargo fmt --all -- --check && cargo clippy --all-features -- -D warnings && cargo test

# 4. Read session history
cat SESSION_HISTORY.md

# 5. Review this plan
cat NEXT_SESSION_PLAN.md

# 6. Read current issues (after sync)
cat ISSUES_INDEX.md
```

---

## ✅ Completed Items

### ARCH-001 - WASM Bindings Completeness Audit (DONE)
- All 12+ modules now have WASM bindings
- Lightning, Swap Router, Settlement Service, Solver, ZKML, DLC
- Stablecoin Orchestrator, MMR, Opportunity, Business Logic, A2P
- All CI checks passing ✅

### G-002 - Ark BitVM2 Challenge Orchestration (DONE)
- Initial implementation complete
- `WasmBitVm2Orchestrator` with RefCell for interior mutability
- Challenge lifecycle management working

---

---

## ✅ Completed: DOC-002 - Examples Directory

### Implementation Complete (Cycle 6)
- `examples/` directory created with 6 practical examples
- `basic_signing.rs` - Bitcoin address formats, transaction intents, MuSig2, BIP-322
- `attestation_verification.rs` - Trust tiers, verification flow, freshness validation
- `ark_vutxo_derivation.rs` - vTXO key derivation, stateless recovery, tree construction
- `fedimint_federation.rs` - Federation join, e-cash mint/spend, threshold BLS
- `multi_chain_signing.rs` - 30+ chain support, cross-chain intents, ERC-7579
- `wasm_integration.rs` - All 14 WASM clients, JavaScript usage examples

---

## ✅ Completed: G-002 - Ark BitVM2 Challenge Orchestration

### Implementation Complete (Cycle 8)
- `BitVm2Orchestrator` with full commitment lifecycle
- Challenge/Response flow with SNARK proof support
- WASM bindings (`WasmBitVm2Orchestrator`) with Arc<RefCell>
- 3 unit tests passing
- Documentation in `docs/architecture/BITVM2_ARK_RESEARCH.md`

---

## ✅ Completed: DEP-001 - Beta Dependencies

### Current State
```
bitcoin = "0.33.0-beta"        # Watch for 0.32.101 stable
secp256k1 = "0.32.0-beta.2"   # Watch for 0.31.1 stable
k256 = "0.14.0"                 # ✅ Upgraded to stable!
```

### Action Items (Remaining)
1. Monitor crates.io for bitcoin and secp256k1 stable releases
2. When stable release available:
   - Update Cargo.toml
   - Run full test suite
   - Check for breaking changes
   - Create compatibility shim if needed
   - Update CHANGELOG

### Monitoring Links
- https://crates.io/crates/bitcoin
- https://crates.io/crates/secp256k1
- https://crates.io/crates/k256 (✅ done)

---

## Stretch Goal: ZKML Enhancement

### Research Notes (from RESEARCH_LOG.md)
- **SNARKs**: ~192 bytes proof size, 3ms verification
- **STARKs**: 45-200KB proofs, hash-only verification (quantum-resistant)
- **Tooling**: ezkl (TensorFlow to SNARK), Succinct SP1 (zkVM for Bitcoin)
- **Use Cases**: Privacy oracles, AI marketplaces, fraud detection

### Implementation Steps
1. Review current `src/protocol/zkml.rs` implementation
2. Evaluate ezkl integration for model verification
3. Consider Succinct SP1 for Bitcoin-compatible verification
4. Document enhancement options

---

## Session Template

### Beginning
```bash
git pull origin main
cargo test && cargo fmt --check && cargo clippy -- -D warnings
cat SESSION_HISTORY.md
cat NEXT_SESSION_PLAN.md
cat RESEARCH_LOG.md
```

### During
- Work on highest priority item
- Run tests frequently
- Update SESSION_HISTORY.md with progress
- Check RESEARCH_LOG.md for relevant findings

### Ending
```bash
# Verify
cargo test && cargo fmt --check && cargo clippy -- -D warnings

# Update session history
# Update this plan with completed items
# Commit with descriptive message
git add -A && git commit -m "type: description"

# Push
git push origin main
```

---

## Notes for Agent

### Code Review Requirements
Per CODEOWNERS, these files require @botshelomokoka review:
- src/enclave/** (including new test files)
- src/protocol/frost.rs, musig2.rs, attestation.rs, fedimint.rs, ark.rs, bitvm.rs
- .github/workflows/**, audit.toml, deny.toml, Cargo.toml

### Production Safety
- Always run full test suite before committing
- Use `cargo clippy -- -D warnings` - no warnings allowed
- Maintain fail-closed security posture
- Document all security-relevant changes

### Communication
- Update SESSION_HISTORY.md with accomplishments
- Update NEXT_SESSION_PLAN.md with progress
- Report blockers immediately

### Self-Evolution Reminder
- Check RESEARCH_LOG.md for new external findings
- Conduct targeted research if new domains are relevant
- Update knowledge base with learnings

---

*Plan created: 2026-07-14*
*Updated: 2026-07-15 (Cycle 10)*
*Next update: After session completion*
