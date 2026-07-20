# `conxius-enclave-sdk`: Agent Directives (v0.4.2)

## Production Status

**BETA / CONDITIONAL** - 2.x interfaces are available for development and integration, but production support is capability- and artifact-specific. Do not claim repository-wide production readiness.

See [PRODUCTION_READINESS.md](./PRODUCTION_READINESS.md), the [production-enablement audit](./docs/audits/PRODUCTION_ENABLEMENT_AUDIT_2026-07-20.md), and the [capability matrix](./docs/architecture/CAPABILITY_MATRIX.md) before describing maturity or support.

## Production-claim guardrails

- Never describe a simulated, mock, software-only, structural, or placeholder path as production-supported.
- Require a traceable **requirement → code → test → CI → artifact** evidence chain before making a security, readiness, compatibility, or release claim.
- Fail closed for value-bearing signing, settlement, attestation, policy, and release decisions when evidence or configuration is missing.
- Keep public documentation ZSE-safe: never expose private endpoints, credentials, privileged identifiers, custody procedures, key-recovery details, or incident operational secrets.
- Use `conxius-enclave-sdk` when a stable technical identifier is required and “the SDK” otherwise. Do not invent or revive a deprecated public product name. Use “Conclave” only for the secure hardware layer where an existing canonical document requires it.

---

## 🚨 MANDATORY SESSION INITIALIZATION

**Execute these commands IMMEDIATELY at the start of EVERY session, in this exact order:**

```bash
# 1. Setup Rust if not available
source ~/.cargo/env 2>/dev/null || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source ~/.cargo/env

# 2. Sync issues and PRs from GitHub (auto-updates tracking)
./scripts/sync_issues.sh

# 3. Verify build state (BLOCKS all further work until passing)
cargo fmt --all -- --check && cargo clippy --all-features -- -D warnings && cargo test

# 4. Read current issues: cat ISSUES_INDEX.md

# 5. ONLY AFTER all above pass: proceed with session work
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
> 3. Read `ISSUES_INDEX.md` for current open issues
> 4. Only then proceed with new work
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
- Cargo metadata currently declares 2.0.12; the latest visible GitHub release/tag evidence is v2.0.11
- Documentation must distinguish package metadata from a verified release
- ✅ Researched BIP-110 Reduced Data Softfork
- ✅ Fixed CI failures: Rust 2024 let chains, missing struct fields, WASM mutable borrow
- Action pins were updated historically; verify current workflow/toolchain compatibility before making a release claim
- WASM bindings expose multiple module surfaces; runtime/platform/hardware support remains conditional
- Hardware attestation unit suite includes 25 simulated tests; vendor coverage remains open

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
The SDK provides a secure foundation for hardware-backed security (TEE, StrongBox), non-custodial orchestration, and multi-chain integrations. These are goals and interfaces, not blanket production-support claims.

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

The following surfaces are exposed or planned; each requires a row in the capability matrix before production support is claimed:

- Lightning, Settlement Service, Solver, Swap Router, ZKML, DLC
- Stablecoin Orchestrator, Job Card (ISO20022), MMR, Opportunity, Business logic

## CI and release claims

Workflow definitions are not evidence of a successful release. Verify the exact workflow run, artifact, provenance, and support decision before making a CI or release claim. Do not modify workflows as part of a documentation-only audit correction unless the task explicitly requires it.

---

*Knowledge Base Version: v0.4.2 | Last Updated: 2026-07-20*
