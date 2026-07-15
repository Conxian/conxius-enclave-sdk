# Conclave SDK: Agent Directives (v0.4.2)

## Production Status

**✅ PRODUCTION READY** - v2.0.12

---

## 🚨 MANDATORY SESSION INITIALIZATION

**Execute these commands IMMEDIATELY at the start of EVERY session, in this exact order:**

```bash
# 1. Setup Rust if not available
source ~/.cargo/env 2>/dev/null || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source ~/.cargo/env

# 2. Verify build state (BLOCKS all further work until passing)
cargo fmt --all -- --check && cargo clippy --all-features -- -D warnings && cargo test

# 3. ONLY AFTER verification passes: proceed with session work
```

**VIOLATION CONSEQUENCE**: Pushing code without verification will result in CI failures and rejected PRs. This is non-negotiable.

See [PRODUCTION_READINESS.md](./PRODUCTION_READINESS.md) for full checklist.

---

## 🔄 Session Continuity Protocol

> **⚠️ VERIFY BEFORE ANY CHANGES - NON-NEGOTIABLE**
>
> At the start of **every new session**:
> 1. Run MANDATORY SESSION INITIALIZATION (see above)
> 2. Report any failures **BEFORE making ANY changes**
> 3. Only then proceed with new work
>
> **PATTERN VIOLATION**: Previous sessions skipped verification and made changes immediately. This caused CI failures and rejected PRs.
>
> This enforces strict live and production code standards.

---

## 📚 Session History & Knowledge Base

| File | Purpose |
|------|---------|
| [SESSION_HISTORY.md](./SESSION_HISTORY.md) | **CRITICAL**: Previous session accomplishments and next steps |
| [NEXT_SESSION_PLAN.md](./NEXT_SESSION_PLAN.md) | What to do next when you resume work |
| [DEBT_INVENTORY.md](./DEBT_INVENTORY.md) | Technical debt with resolution status |
| [GAP_SCORECARD.md](./docs/architecture/GAP_SCORECARD.md) | Implementation gap tracking |
| [REPOSITORY_ANALYSIS.md](./REPOSITORY_ANALYSIS.md) | Comprehensive repository state |
| [RESEARCH_LOG.md](./RESEARCH_LOG.md) | External research findings and technology monitoring |

---

## 🚀 Quick Start for New Sessions

### First 5 Minutes:
```bash
# 1. Pull latest changes
git pull origin main

# 2. Verify build
cargo test && cargo fmt --check && cargo clippy -- -D warnings

# 3. Read session history
cat SESSION_HISTORY.md

# 4. Review next session plan
cat NEXT_SESSION_PLAN.md

# 5. Check recent research
cat RESEARCH_LOG.md
```

### Key Accomplishments (2026-07-15 - Cycle 10):
- ✅ Released v2.0.12 with BitVM2 static method fix
- ✅ Updated all documentation to v2.0.12
- ✅ Researched BIP-110 Reduced Data Softfork
- ✅ Fixed CI failures: Rust 2024 let chains, missing struct fields, WASM mutable borrow
- ✅ Updated all GitHub Actions to Node.js 24 compatible versions (v4/v5)
- ✅ WASM bindings completeness (12+ modules covered)
- ✅ Comprehensive hardware attestation test suite (25 tests)

---

## 🔬 External Research Intelligence

### TEE Hardware Attestation (2024-2025)
- **Intel SGX**: DCAP with ECDSA quotes, verified against PCK certificates
- **AMD SEV-SNP**: 64-byte guest-data field for nonce/replay protection
- **ARM PSA/CCA**: EAT tokens with COSE protection
- **Best Practices**: Nonce-driven attestation, full certificate chain validation, hardware RNG for key generation

### BitVM2 Developments (Q4 2025)
- **Optimistic Rollup**: Permissionless challengers (anyone can verify)
- **Security Model**: Existential honesty (1-of-n honest verifier needed)
- **Performance**: ~$15k fees for challenged execution (targeting <$50)
- **SDK**: Q2 2025 Rust SDK release, Go/TypeScript bindings planned
- **Ecosystem**: Citrea, BOB, Bitlayer, Botanix adoption

### Fedimint eCash Evolution
- **Threshold BLS Blind Signatures**: Replaces single-key signing
- **DLEQ Proofs**: Discrete-log equality proofs in issuance flow
- **Performance**: 200ms intra-federation latency, 2-3x throughput improvement
- **Gateway**: Multi-federation support, LNURL-pay extensions in development

### WASM SDK Patterns
- **Architecture**: Core crate (no wasm-bindgen) + wasm wrapper (cdylib)
- **Async**: wasm-bindgen-futures for Promise-based JS integration
- **Security**: Input validation at JS boundary, keys never exposed to JS
- **Optimization**: wasm-opt -Oz, wasm-slim for 10-20% size reduction
- **CI**: wasm-pack test, cargo audit, deterministic builds via rust-toolchain.toml

### ZKML Developments
- **SNARKs**: ~192 bytes proof size, 3ms verification
- **STARKs**: 45-200KB proofs, hash-only verification (quantum-resistant)
- **Bitcoin Integration**: BitVM, Citrea rollups, zkBitcoin
- **Tooling**: ezkl, Circom/snarkjs, RISC-V (Succinct SP1)
- **Use Cases**: Privacy oracles, AI marketplaces, on-chain fraud detection

### BIP-110: Reduced Data Temporary Softfork
- **Limits**: 256-byte pushdata, 83-byte OP_RETURN, 34-byte ScriptPubKey
- **Activation**: Versionbits with 55% threshold, block 961,632
- **SDK Impact**: BIP-322 chunking, Ark/BitVM2 data segmentation, stricter outputs
- **Reference**: [BIP-110 Spec](https://bips.dev/110)

---

## 📊 Self-Evolution Patterns

### Adaptive Learning Protocol
1. **Research Gate**: On each session, conduct targeted external research on relevant domains
2. **Gap Analysis**: Compare current state against latest best practices
3. **Pattern Matching**: Identify applicable patterns from research findings
4. **Implementation Priority**: Rank by impact (security > functionality > developer experience)
5. **Documentation Update**: Record new patterns and learnings in RESEARCH_LOG.md

### Research Domains to Monitor
- TEE Attestation: Intel SGX DCAP, AMD SEV-SNP, ARM PSA
- Bitcoin L2: BitVM2/BitVM3, Ark, Rollups (Citrea, zkSync)
- Cryptographic Blinding: Fedimint, Cashu, Chaumian schemes
- WASM: wasm-bindgen ecosystem, size optimization techniques
- ZK/ML: SNARK/STARK developments, ezkl, RISC-V provers
- Rust Crypto: secp256k1, k256, bitcoin crate stable releases

---

## Repository Tracking

For comprehensive tracking of issues, pull requests, and branches:
- **TRACKING.md** - Main tracking overview
- **ISSUES_INDEX.md** - GitHub issues (synced locally)
- **PRS_INDEX.md** - Pull requests (synced locally)
- **BRANCHES_INDEX.md** - Branch overview
- **REPOSITORY_ANALYSIS.md** - Capabilities, gaps, and roadmap
- **DEBT_INVENTORY.md** - Technical debt tracking

### Syncing from GitHub
```bash
./scripts/sync_issues.sh
```

---

## Core Ethos
The Conclave SDK is the definitive **Sovereign Rails** infrastructure for native Bitcoin applications. We prioritize hardware-backed security (TEE, StrongBox), non-custodial orchestration, and universal asset support.

## Coding Standards
- **SDK-First**: Prioritize modularity and clear boundaries between enclave, protocol, and bindings.
- **Fail-Closed**: Always ensure a 'fail-closed' security posture for high-value operations. Hardware attestation must be mandatory in production.
- **No-Panic**: Avoid `panic!`, `unwrap()`, and `expect()` in production paths. Use `ConclaveResult` for error handling.
- **Zeroization**: Sensitive data must be zeroed out when no longer needed.

## Directory Map
- `src/enclave/`: Hardware attestation and secure signing (TEE/StrongBox).
- `src/protocol/`: Core Bitcoin/Multi-chain orchestration logic.
- `src/protocol/rails/`: Modular settlement rails (x402, Wormhole, Boltz, NTT, Bisq).
- `src/protocol/nexus/`: Fedimint and cross-protocol adapters.
- `src/wasm_bindings.rs`: Modular WASM sub-clients for web integration.
- `docs/architecture/`: Active architectural standards and research.
- `docs/audits/`: Mainnet readiness and security audit artifacts.

## Testing
- Use `cargo test` to verify all protocol changes.
- Ensure all 30+ chains in the `AssetRegistry` are correctly handled.
- Hardware-backed logic should be tested with both simulated and software attestation (for CI) but blocked for production-level Trust Tiers.

## WASM Binding Requirements
- ✅ Lightning, Settlement Service, Solver, Swap Router, ZKML, DLC
- ✅ Stablecoin Orchestrator, Job Card (ISO20022), MMR, Opportunity, Business logic

## GitHub Actions Node.js 24 Compliance
All workflows updated to support Node.js 24 (mandatory since Sept 2026):
- `actions/checkout@v4`
- `actions/upload-artifact@v5`
- `actions/download-artifact@v5`
- `actions/attest-build-provenance@v4.1.1`

---

*Knowledge Base Version: v0.4.2 | Last Updated: 2026-07-15*
