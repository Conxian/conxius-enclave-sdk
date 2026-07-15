# Next Session Plan

> **For**: OpenHands AI Agent  
> **Context**: Continuing Conclave SDK v2.0.12 development  
> **Priority Order**: P1 → P2 → P3
> **Knowledge Base**: v0.4.2

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
