# Next Session Plan

> **For**: OpenHands AI Agent
> **Context**: Continuing Conxius Enclave SDK v2.0.14 development
> **Priority Order**: Remaining P0 gates → P1 → P2
> **Knowledge Base**: v0.6.0 (Session 55-57, Aug 2026)
> **Last Session**: Session 57 — FROST attestation gating, version aligned at 2.0.14

---

## Session 58 — Planned (2026-08-06)

### P0: Live Nitro Enclave Deployment Evidence
- Deploy SDK enclave binary to AWS Nitro instance (via lib-conxian-core Nitro CI)
- Run `AwsNitroVerifier.verify()` against real attestation document
- Complete cryptographic certificate-path validation, then capture attestation doc → COSE → configured PCR/workload identity → release/KMS binding → `VerifiedProofReceipt`
- Store as CI artifact with SHA-256 digest

### P0: Core Adapter ↔ SDK v2.0.14+ Integration
- The core adapter now pins SDK v2.0.14 (git tag), up from =2.0.11
- Wire adapter's `CoreEnclaveAdapter` to use `ProofVerifierRegistry::production()`
- Keep the default registry route unavailable until adapter → explicitly configured `AwsNitroVerifier` → real attestation → verified receipt is evidenced
- Compatibility: 28 adapter tests pass with v2.0.14 (verified 2026-08-05)

### P1: Distributed Replay Design
- Select backend: DynamoDB (preferred for Nitro co-location) or PostgreSQL
- Design `ReplayStore` trait with conditional-write primitive
- Binding-key schema, trusted-clock source, TTL boundary
- Document in `docs/architecture/DURABLE_REPLAY_CONFORMANCE.md`

### P1: CARGO_REGISTRY_TOKEN + Tagged Release
- Configure `$CARGO_REGISTRY_TOKEN` in GitHub `release` environment
- Tag v2.0.15, run `release-strict.yml`
- Verify: crates.io publication, GH release, SBOM, provenance

### P2: Full Workspace `cargo test --all-features`
- Run frost-crypto, cryptoki, webauthn feature gates together
- Fix any compilation errors from feature interaction
- Verify all verifier tests pass with real backends

### P2: Fedimint + Groth16 Deferral Decision
- Fedimint: Document as deferred (no audited Fedimint crypto impl available)
- Groth16: Document as deferred (no audited BLS12-381 ZK pairing backend for WASM)

### Housekeeping
- Bump Cargo.toml to 2.0.15, tag, and release (bumped then reverted in Session 57; pending in Session 58)
- Update all KB artifacts (NEXT_SESSION_PLAN, SESSION_HISTORY, AGENTS.md, DEBT_INVENTORY, PRODUCTION_READINESS, TRACKING)
- Core adapter SDK dep aligned to v2.0.14 (done: 2026-08-05)

---

## Session 55-57 Completed (2026-08-03 → 2026-08-05)

### P0: AwsNitroVerifier structural groundwork (Session 55; production gate still open)
- `NitroCertificateTrustBoundary` performs structural certificate-linkage and Nitro Root CA G1 pin checks (`a6772fc`)
- `ProofVerifierRegistry::production()` intentionally keeps the TEE route unavailable
- Complete cryptographic certificate-path validation plus configured PCR/workload and release/KMS bindings remain required

### ✅ P1: PKCS#11 + OIDC Verifiers Wired (Session 55-56)
- `cryptoki` v0.10 feature flag → Pkcs11Verifier sign/verify (`c460bd0`)
- `jsonwebtoken` v10 → OidcVerifier JWT verification, JWK kid matching (`5850619`)
- `secrecy` v0.8 for PKCS#11 PIN management

### P2: WebAuthn API + FROST Attestation Gating (Session 55-57)
- `webauthn-rs` v0.5 feature flag and WebauthnVerifier API added (`cc98177`); verification remains stubbed/incomplete
- FROST DKG/signing gated behind enclave attestation policy (`1a2199c`)

### ✅ CVE Patches
- Dependabot #6: playwright 1.54.2 → 1.55.1 (CVE-2025-59288)
- Dependabot #7: jsonwebtoken 9 → 10 (CVE-2026-25537)

### ✅ Clippy + cargo-deny Clean
- 0 clippy warnings in both feature modes
- 4 stale advisory ignores removed from deny.toml

### Remaining Production Gates
1. Live Nitro deployment evidence (P0 — Session 58)
2. Distributed replay authorization (P1 — Session 58 design)
3. Core adapter ↔ SDK v2.0.14 verifier integration (P0 — Session 58)
4. Fedimint real crypto or documented deferral (P2)
5. Groth16 ZK pairing backend or documented deferral (P2)
6. Independent security review (#202)
7. WASM runtime/platform evidence (#200)
8. Tagged release with SBOM + provenance (#199)

---

## Remaining Gates (from Session 53)

1. Fedimint real crypto or documented deferral
2. Groth16 ZK pairing backend for actual verification
3. Real provider verifier (Android/Nitro hardware integration) ← P0 Session 56
4. Independent security review (#202)
5. WASM runtime/platform evidence completion (#200)

---

## 2026-07-26 durable replay deployment decision gate (#191 / #240)

The active `enclave::replay_guard::ReplayStore` now has a backend-neutral
conformance/fault model and canonical requirements in
[`docs/architecture/DURABLE_REPLAY_CONFORMANCE.md`](docs/architecture/DURABLE_REPLAY_CONFORMANCE.md).
This is contract evidence only and does not select a backend or justify a
capability/status change.

The exact next decision is: **choose one deployment-scoped durable replay
adapter and consistency topology, or explicitly defer deployment**. Before
implementation or promotion, record the candidate product/version, region and
replica topology, conditional-write/transaction primitive, complete binding-key
schema, trusted-clock source, exclusive-retention enforcement, timeout and
uncertain-commit mapping, and backup/failover ownership.

The evidence gate is one reviewed requirement → adapter code → real-adapter
conformance test → crash/restart/failover/restore test → exact CI run → exact
artifact/provenance chain. It must include single-key and overlapping-batch
contention, before/after-commit faults, retained high-water rollback state, TTL
boundary behavior independent of asynchronous deletion, and independent
security review. Until that chain exists, keep `capability-evidence.json` and
all production-support decisions unchanged.

## 2026-07-22 Issue #240 Phase A handoff

Phase A is the provider-neutral trust and durable-replay contract slice. It
adds bounded/versioned transport types, deterministic non-JSON canonical
encodings, explicit status semantics, constructor-controlled verified material,
privacy-minimized normalized results/audit metadata, and a contract-only
durable replay wrapper. It does **not** provide an Android or Nitro verifier,
provider registration, a durable backend, WASM support, settlement dispatch,
independent review, release artifacts, or production support.

The final-head review boundary is explicit: the normalized public result is
`SingleMechanismAttestationResult` with `TrustScope::SingleMechanism`, and
durable replay returns only `SingleMechanismReplayAuthorization`. Exact
`ProofPolicy::production()` and verifier binding remain contextual requirements;
they do not let one mechanism satisfy the six-factor policy. Complete
all-required authorization remains on the composed proof-bundle path, and the
provider extension seam is crate-private/test-only until a supported adapter
contract exists.

Current residual gates:

1. Select and pin one provider (Android or Nitro), its official verifier/root/
   collateral/status inputs, runtime, and independent vectors.
2. Implement provider-specific verification and hardware/runtime integration;
   keep `productionSupport` unchanged until the full evidence chain exists.
3. Select and review a durable replay deployment with atomicity, restart,
   replica, regional recovery, and uncertain-commit evidence. The Phase A
   interface and local fake store are not a backend.
4. Consolidate the duplicate WASM workflow/Playwright evidence paths only in
   the dedicated #200/#199 lane; compilation and negative runtime tests remain
   non-promotion evidence.
5. Attach exact CI, artifact, SBOM/provenance, and independent-review evidence
   for the exact code ref before changing any capability support decision.

The canonical contract is
[`docs/architecture/ISSUE-240_PHASE_A_CONTRACT.md`](docs/architecture/ISSUE-240_PHASE_A_CONTRACT.md).

## 2026-07-22 PR #237 follow-up

The proof-policy hardening and provider research boundary are recorded in
[`docs/architecture/PROOF_POLICY_SPEC.md`](docs/architecture/PROOF_POLICY_SPEC.md)
and
[`docs/audits/PR-237_HARDWARE_ATTESTATION_RESEARCH_2026-07-22.md`](docs/audits/PR-237_HARDWARE_ATTESTATION_RESEARCH_2026-07-22.md).
PR #237 was already merged before the branch continuation; do not create a
replacement PR or force-push its recreated source branch. Keep all provider
rows unsupported until exact provider/runtime/roots/collateral/replay/review
and artifact evidence is available.

Immediate next work is provider-specific evidence only: choose one provider
scope, pin its official verifier/runtime and roots/collateral, add independent
vectors and negative tests, and attach exact CI/artifact/review evidence before
changing any production-support status. Phase A's contract is a prerequisite,
not evidence that this provider work is complete.

## Historical ordered end-of-sprint follow-up (2026-07-20)

This sequence advances [issue #191](https://github.com/Conxian/conxius-enclave-sdk/issues/191) while keeping containment evidence separate from production-readiness claims:

1. Obtain review and merge [PR #214](https://github.com/Conxian/conxius-enclave-sdk/pull/214), which recorded the fail-closed containment slice at that snapshot.
2. After #214 was reviewed, preserve and selectively reconcile the valuable provider-wrapper changes from [PR #205](https://github.com/Conxian/conxius-enclave-sdk/pull/205); PR #205 is now merged and must not be recreated or force-pushed.
3. Keep WASM secret-boundary and runtime/platform evidence under [issue #200](https://github.com/Conxian/conxius-enclave-sdk/issues/200) and [PR #211](https://github.com/Conxian/conxius-enclave-sdk/pull/211); do not move that lane into the containment or tracking PR.
4. Implement the typed operation/provider envelope and complete key/algorithm/provider binding under [issue #195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), preserving fail-closed behavior while provider verification and hardware evidence are incomplete. This containment slice is now recorded by the follow-up code commit below.
5. Once the implementation and provider evidence are independently reviewable, pursue the independent security review and release acceptance gate in [issue #202](https://github.com/Conxian/conxius-enclave-sdk/issues/202). Do not treat passing local or GitHub checks as a substitute for this gate.

### Historical capability evidence-index ownership note

At that snapshot, open [PR #210](https://github.com/Conxian/conxius-enclave-sdk/pull/210) owned `docs/architecture/capability-evidence.json` and the generated `docs/architecture/CAPABILITY_MATRIX.md`; open [PR #211](https://github.com/Conxian/conxius-enclave-sdk/pull/211) owned the WASM documentation lane. The current follow-up has since updated the evidence files, keeps `productionSupport` unsupported or conditional as appropriate, and regenerates the matrix through the validator.

Do not change workflows or unrelated release lanes; the repository remains Beta / conditional. `PRODUCTION_READINESS.md` is updated in the focused containment follow-up only to keep its public claim boundary accurate.

## Current Follow-up

The machine-first capability evidence follow-up now records merged PR #205, merged PR #216 signer identity binding, and the reconciled typed-settlement containment checkpoint `5a936ba97373ebdbd809580c5e9c9f4df1966b40` in `docs/architecture/capability-evidence.json`, generated into `docs/architecture/CAPABILITY_MATRIX.md`. The next session must continue with evidence work, not infer production support from API rows, unit tests, WASM builds, or historical closed issues.

Remaining gates are already tracked by GitHub #195–#202. PR #205 and the typed-settlement follow-up are containment/evidence-boundary work only; issue #195 remains open. Do not create duplicate issues.

## Immediate blockers to prioritize

1. Define and integrate the real provider verifier/signer contract, including hardware-generated keys, provider response/key binding, vendor roots, and collateral.
2. Replace process-local replay containment with independently reviewed distributed replay authorization for the deployment scope.
3. Add provider-backed hardware/runtime integration tests, including WASM runtime/platform evidence where supported; compilation is not runtime evidence.
4. Obtain independent security/cryptographic review for the exact reviewed code and attach the findings.
5. Produce exact release artifacts with digests, SBOM, provenance, retained CI results, and a scoped support decision.

Keep `UnavailableEnclave`, simulator exclusion, typed settlement propagation, and raw-dispatch rejection fail closed until all gates are evidenced.

---

## Current handoff: PR #209 protocol foundation

The 2026-07-21 PR #209 update is a foundation-plus-quarantine change. The
typed FROST, Fedimint, Ark, and BitVM2 models and idempotency helpers are
structural only; every value-bearing operation remains `ProtocolUnsupported`.
The canonical next steps are in
[`docs/architecture/PROTOCOL_IMPLEMENTATION_ROADMAP.md`](docs/architecture/PROTOCOL_IMPLEMENTATION_ROADMAP.md).

### Required next work

1. Select and pin one external implementation/revision per protocol before
   adding cryptographic, network, script, or persistence code.
2. Add official and independent vectors, mutation/negative tests, provider and
   attestation binding, and durable operation/recovery evidence.
3. Review the exact artifact, SBOM/provenance, CI results, and independent
   security findings before changing any capability row or support decision.
4. Keep all four protocol rows at `Production: No`; do not infer support from
   local tests, WASM compilation, historical issue closure, or typed APIs.

Historical “complete” sections below are retained for continuity and are
superseded as current status by the quarantine roadmap.

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

## Historical completion records (superseded for current support decisions)

### ARCH-001 - WASM Bindings Completeness Audit (historical API inventory)
- All 12+ modules now have WASM bindings
- Lightning, Swap Router, Settlement Service, Solver, ZKML, DLC
- Stablecoin Orchestrator, MMR, Opportunity, Business Logic, A2P
- All CI checks passing ✅

### G-002 - Ark BitVM2 Challenge Orchestration (historical structural work)
- Initial implementation complete
- `WasmBitVm2Orchestrator` with RefCell for interior mutability
- Challenge lifecycle management working

---

---

## Historical: DOC-002 - Examples Directory

### Implementation Complete (Cycle 6)
- `examples/` directory created with 6 practical examples
- `basic_signing.rs` - Bitcoin address formats, transaction intents, MuSig2, BIP-322
- `attestation_verification.rs` - Trust tiers, verification flow, freshness validation
- `ark_vutxo_derivation.rs` - vTXO key derivation, stateless recovery, tree construction
- `fedimint_federation.rs` - Federation join, e-cash mint/spend, threshold BLS
- `multi_chain_signing.rs` - 30+ chain support, cross-chain intents, ERC-7579
- `wasm_integration.rs` - All 14 WASM clients, JavaScript usage examples

---

## Historical: G-002 - Ark BitVM2 Challenge Orchestration

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
