# Next Session Plan

> **For**: OpenHands AI Agent  
> **Context**: Continuing Conclave SDK v2.0.9+ development  
> **Priority Order**: P1 → P2 → P3
> **Knowledge Base**: v0.4.0

---

## Session Startup Checklist

```bash
# 1. Pull and verify
git pull origin main
cargo test && cargo fmt --check && cargo clippy -- -D warnings

# 2. Read session history
cat SESSION_HISTORY.md

# 3. Review this plan
cat NEXT_SESSION_PLAN.md

# 4. Check for new research
cat RESEARCH_LOG.md

# 5. Check for new issues
cat ISSUES_INDEX.md
```

---

## Priority 1: ARCH-001 - WASM Bindings Completeness Audit

### Why This Matters
The WASM bindings (`src/wasm_bindings.rs`) provide the web/mobile integration surface. **12+ modules are missing bindings**, limiting SDK adoption.

### Current WASM Coverage (from wasm_bindings.rs)
- ✅ Ark bindings: `WasmArkClient` (derive_vutxo_key, recovery_scan, construct_vtxo_tree)
- ✅ BitVM bindings: `WasmBitVmClient` (sign_challenge, aggregate_challenge_signatures)
- ✅ Ethereum bindings: `WasmEthereumManager` (prepare_erc20_transfer)
- ✅ Solana bindings: `WasmSolanaManager` (prepare_spl_transfer)
- ✅ Fedimint bindings: `WasmFedimintClient` (register_federation, join_federation, mint, issue, verify)
- ✅ FROST bindings: `WasmFrostClient` (generate_key_package)
- ✅ Covenant bindings: `WasmCovenantClient` (generate_cat_vault_script, verify_recursive_invariant)
- ✅ Intent bindings: `WasmIntentClient` (instrument_context, settlement_context)
- ✅ Account bindings: `WasmAccountClient` (prepare_execution)
- ✅ CCTP bindings: `WasmCctpClient` (prepare_burn_payload)
- ✅ Iso20022 bindings: `Iso20022Wrapper` (wrap_pacs008)

### Missing WASM Bindings (Priority Order)
1. **Lightning LND**: `src/protocol/lightning.rs`
2. **Swap Router**: `src/protocol/swap_router.rs`
3. **Settlement Service**: `src/protocol/settlement_service.rs`
4. **Solver**: `src/protocol/solver.rs`
5. **ZKML**: `src/protocol/zkml.rs`
6. **DLC**: `src/protocol/dlc.rs`
7. **Stablecoin Orchestrator**: `src/protocol/stablecoin_orchestrator.rs`
8. **MMR (Merkle Mountain Range)**: `src/protocol/mmr.rs`
9. **Opportunity**: `src/protocol/opportunity.rs`
10. **Business Logic**: `src/protocol/business.rs`
11. **A2P**: `src/protocol/a2p.rs`

### Implementation Steps
1. Audit each module in `src/protocol/` for public APIs
2. Cross-reference with `wasm_bindings.rs` exports
3. Identify missing bindings
4. Implement missing WASM wrappers following modern patterns:
   - Core crate (no wasm-bindgen) + cdylib wrapper
   - Use `wasm-bindgen-futures` for async operations
   - Use `serde-wasm-bindgen` for type serialization
5. Add tests for WASM bindings
6. Update `REPOSITORY_ANALYSIS.md` ARCH-001 status

### Modern WASM SDK Patterns (from research)
- **Architecture**: Core crate (no wasm-bindgen) + wasm wrapper (cdylib)
- **Async**: wasm-bindgen-futures for Promise-based JS integration
- **Optimization**: wasm-opt -Oz, wasm-slim for 10-20% size reduction
- **Security**: Input validation at JS boundary, keys never exposed to JS

---

## Priority 2: DOC-002 - Examples Directory

### Why This Matters
Developers need working examples to adopt the SDK. No examples currently exist.

### Implementation Steps
1. Create `examples/` directory
2. Add basic signing example
3. Add attestation verification example
4. Add Ark vTXO derivation example
5. Add Fedimint federation join example
6. Add multi-chain signing example
7. Add WASM integration example (if bindings complete)

### Files to Create
```
examples/
├── Cargo.toml
├── README.md
├── basic_signing.rs
├── attestation_verification.rs
├── ark_vutxo_derivation.rs
├── fedimint_federation.rs
├── multi_chain_signing.rs
└── wasm_integration.rs
```

---

## Priority 3: G-002 - Ark BitVM2 Challenge Orchestration

### Why This Matters
Highest priority backlog item according to GAP_SCORECARD.md. Critical for Ark v3 integration.

### Research Notes (from RESEARCH_LOG.md)
- **BitVM2**: Optimistic rollup with permissionless challengers
- **Security**: Existential honesty (1-of-n honest verifier needed)
- **Performance**: ~$15k fees (targeting <$50 via BitVM3)
- **Ecosystem**: Citrea, BOB, Bitlayer, Botanix adoption

### Implementation Steps
1. Study BitVM2 specification
2. Understand Ark forfeit transaction structure
3. Design challenge-response integration
4. Document design in docs/architecture/
5. Implement prototype (if approved)

### Key Files to Research
- `src/protocol/ark.rs` - Current forfeit signing
- `src/protocol/bitvm.rs` - Current challenge structure
- `docs/architecture/BITVM2_ARK_RESEARCH.md` - Existing research

---

## Background: DEP-001 Beta Dependencies Monitoring

### Current State
```
bitcoin = "0.33.0-beta"        # Watch for stable
secp256k1 = "0.32.0-beta.2"   # Watch for stable
k256 = "0.14.0-rc.9"           # Watch for stable
```

### Action Items
1. Monitor crates.io for stable releases weekly
2. When stable release available:
   - Update Cargo.toml
   - Run full test suite
   - Check for breaking changes
   - Create compatibility shim if needed
   - Update CHANGELOG

### Monitoring Links
- https://crates.io/crates/bitcoin
- https://crates.io/crates/secp256k1
- https://crates.io/crates/k256

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
*Updated: 2026-07-15 (Cycle 2)*
*Next update: After session completion*
