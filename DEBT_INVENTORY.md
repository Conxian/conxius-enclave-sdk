# Technical Debt Inventory

This document tracks known technical debt in the `conxius-enclave-sdk` repository.

The [capability evidence JSON](docs/architecture/capability-evidence.json) is the canonical cross-check for whether a debt item affects API presence, implementation, integration, independent review, or production support. Simulation and API completeness are not production evidence.

## Classification Schema

| Priority | Description |
|----------|-------------|
| **P1 - Critical** | Blocks production use, security implications, or release |
| **P2 - High** | Significant impact on maintainability or developer experience |
| **P3 - Medium** | Moderate impact, should be addressed in next sprint |
| **P4 - Low** | Nice to have, can be addressed opportunistically |

| Category | Description |
|----------|-------------|
| **Security** | Potential security vulnerabilities or hardening needs |
| **Dependency** | Third-party dependency issues (beta versions, unmaintained) |
| **Documentation** | Missing or outdated documentation |
| **Testing** | Insufficient test coverage |
| **Architecture** | Design or structural improvements needed |
| **Tooling** | Development/maintenance tool improvements |

## Active Debt Items

### P1 - Critical

#### DEP-001: Yanked `secp256k1 0.32.0-beta.2` dependency ✅ RESOLVED (2026-08-30)
- **Category**: Dependency
- **Priority**: P1 - Critical
- **Description**: `Cargo.toml` pinned `secp256k1 = "0.32.0-beta.2"` (a hard, non-optional dependency), which is **yanked** from crates.io. Any fresh dependency resolution (`cargo generate-lockfile`, downstream `cargo add`) failed, blocking `conxian-nexus` CI and merge of nexus PR #250.
- **Tracking**: [#320](https://github.com/Conxian/conxius-enclave-sdk/issues/320)
- **Resolution**: `bitcoin 0.33.0-beta` → `0.32.102` (converging on the stable `bdk_wallet` line) and `secp256k1 0.32.0-beta.2` → `0.33.1` (`recovery`,`std`). The yanked crate is fully removed from the lockfile; `frost-crypto` is unaffected (ZF FROST uses `k256`, not `secp256k1`). **Complete (2026-08-30)**: v2.0.17 released to crates.io, `lib-conxian-core` converged (#281/#280 merged), `conxian-nexus` re-pinned (#255), GitHub Releases backfilled for v2.0.16 + v2.0.17.


#### CI-004: crates.io release verification 403 + recovery tag gate
- **Category**: CI/CD / Release
- **Priority**: P1 - Critical
- **Description**: `verify-registry-artifact.sh` `curl`ed the published `.crate` from crates.io **without a `User-Agent`**, so crates.io returned HTTP 403 and every release since v2.0.16 failed `Publish to crates.io` → no GitHub Release was created (crate was still published). Secondary: the recovery mode (`recover_existing_registry`) hard-required `GITHUB_REF_TYPE=tag`, so it could never run on `main` (where the fixed script lives).
- **Tracking**: PR #326 (User-Agent) + PR #327 (recovery tag gate)
- **Resolution**: #326 merged — `curl` now sends a `User-Agent`; #327 **merged** (skips the tag gate in recovery mode; approved by `admin-conxian-labs` 2026-08-30). GitHub Releases for v2.0.16 + v2.0.17 were backfilled manually in the interim (without SBOM/provenance assets, which the automated recovery will add on next run).


#### PROTO-001: Protocol implementation boundaries and evidence
- **Category**: Architecture / Security / Testing
- **Priority**: P1 (downgraded from P0 — major progress Session 53)
- **Description**: FROST, Fedimint, Ark, and BitVM2 require typed boundaries and
  an explicit requirement → code → vector/test → CI → artifact chain before any
  value-bearing implementation can be enabled.
- **Current (2026-08-03)**:
  - **FROST**: ✅ Real ZF FROST v3.0.0 crypto backend (#264), FrostSigningContext bridge (#275), ROAST coordinator (Session 53). DKG, signing, aggregation all backed by real crypto.
  - **Ark**: ✅ VTXO Merkle tree construction + FROST signing bridge (#278).
  - **BitVM2**: ✅ Groth16 proof/verification key/public inputs/verifier boundary (Session 53). Disprove envelope types modeled. Verifier returns `VerificationUnavailable` without ZK backend.
  - **DLC**: ✅ Oracle attestation verification + CET template construction (#279).
  - **CCTP**: ✅ ECDSA attestation verification via k256 (#277).
  - **Covenant**: ✅ BIP-119 CTV and BIP-118 APO patterns (#276).
  - **Fedimint**: ✅ Real BLS12-381 e-cash blinding + Chaum-Pedersen DLEQ verification implemented in `src/protocol/nexus/fedimint_crypto.rs` and wired in `src/protocol/nexus/fedimint.rs` (`DleqProof::verify`, `create_dleq_proof`, `create_blind_signature_request` gated behind `fedimint-crypto`). Full threshold mint/network integration is provider-gated.
- **Risk**: Fedimint full threshold mint/network integration remains provider-gated. Groth16 verifier now has a real BLS12-381 pairing backend (`groth16` feature, Session 61), but BitVM2 protocol-conformance/live-bridge/review evidence remains open.
- **Recommendation**: Fedimint DLEQ + blinding crypto is now real (`fedimint-crypto`, Session 63). The remaining full threshold mint (guardian partial-signature aggregation + network) is deferred to provider integration.
- **Status**: Active; FROST/Ark/CCTP/DLC/Covenant production support `No` pending independent review. Fedimint crypto layer real, threshold mint provider-gated.

#### DEP-001: Beta/Release Candidate Dependencies
- **Category**: Dependency
- **Priority**: P1
- **Description**: Multiple critical cryptographic dependencies use beta/RC versions
- **Affected Dependencies**:
  - `bitcoin = "0.33.0-beta"` - Bitcoin protocol support → ✅ RESOLVED: downgraded to stable `0.32.102` (2026-08-30)
  - `secp256k1 = "0.32.0-beta.2"` - ECDSA/Schnorr signatures → ✅ RESOLVED: bumped to stable `0.33.1` (2026-08-30)
  - `k256 = "0.14.0"` - K-256 elliptic curve (stable release)
- **Risk**: Breaking changes on stable release, potential compatibility issues
- **Recommendation**: Pin to stable versions as they become available; monitor upstream releases
- **Tracking**: Monitor RustSec advisories for these crates

#### DOC-001: No Published Releases ✅ RESOLVED (2026-07-14)
- **Category**: Documentation
- **Priority**: P1
- **Description**: README states "no published GitHub releases" but CHANGELOG documents releases
- **Resolution**: v2.0.14 is the current tagged release; Cargo.toml is aligned at 2.0.14. Active release process.
- **Related Issue**: #154

#### SEC-002: Real Provider Verifier and Signer Integration
- **Category**: Security
- **Priority**: P1
- **Description**: The typed value-bearing boundary now fails closed and requires provider-verified hardware provenance, but the repository does not contain an authenticated real hardware/provider verifier or signer implementation.
- **Risk**: Software fixtures, simulated attestation, or an unverified provider could otherwise be mistaken for value-bearing production authorization.
- **Session 57 Progress (2026-08-05)**: Phase 3 verifier framework built with 4 backends (Nitro, PKCS#11, WebAuthn, OIDC). All verifiers implement the `ProofVerifier` trait. 14 verifier tests pass. Verifier framework complete (Session 55-57). Blocked on: live Nitro deployment evidence (P0), core adapter integration (P0), distributed replay (P1).
- **Recommendation**: Define and integrate the provider response/key-binding contract, vendor roots and collateral, hardware-generated keys, deployment checks, and provider-backed positive/negative integration tests. Keep `UnavailableEnclave` as the default until that evidence exists.
- **Tracking**: [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195)

#### SEC-003: Distributed Replay Authorization
- **Category**: Security
- **Priority**: P1
- **Description**: Typed settlement authorization and attestation replay checks are contained by process-local `ReplayGuard` instances; distributed deployment coordination is not implemented or evidenced.
- **Risk**: A process-local replay cache cannot establish single-use authorization across replicas, restarts, or independent provider/runtime boundaries.
- **Session 57 Progress (2026-08-05)**: Phase 3 verifier framework built with 4 backends (Nitro, PKCS#11, WebAuthn, OIDC). All verifiers implement the `ProofVerifier` trait. 14 verifier tests pass. Verifier framework complete (Session 55-57). Blocked on: live Nitro deployment evidence (P0), core adapter integration (P0), distributed replay (P1).
- **Session 62 Progress (2026-08-29)**: Added `DurableFileReplayStore` (`src/enclave/replay_store_file.rs`), the first `ReplayStore` adapter advertising `ReplayStoreDurability::DurableProvider`, with `fsync`-ed O_EXCL records, all-or-nothing `consume_once_batch`, and a persisted anti-rollback high-water clock; passes the backend-neutral consume-once conformance suite (10 cases). This closes the restart-durability portion of the gap. The multi-replica/multi-region distributed coordination backend (DynamoDB/PostgreSQL) remains open and is a production deployment concern.
- **Session 62 Cross-repo (2026-08-29)**: The real Postgres backend is built in `conxian-nexus` (`IdempotencyStore` → PR #250 **merged** 2026-08-29, follow-up #251), using `INSERT … ON CONFLICT DO NOTHING` + transactional all-or-nothing batch against the Neon `Conxian Nexus` project. This moves the "distributed replay coordination" gap from this SDK to the service that actually needs it.
- **Recommendation**: Specify and independently review deployment-safe replay semantics, then add provider-backed and distributed integration tests with failure-closed behavior.
- **Tracking**: [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195)

#### SEC-004: Provider-Specific Proof Verification and Policy Evidence
- **Category**: Security / Architecture / Testing
- **Priority**: P1
- **Description**: Phase A now binds the complete proof policy through the rail and final-dispatch boundaries, but provider-specific verification, roots, collateral/revocation, runtime integration, and exact artifact evidence remain unavailable.
- **Risk**: Research specifications or typed taxonomy could be mistaken for an authenticated TLS/WebAuthn/FIDO/TPM/mobile/TEE provider claim.
- **Session 57 Progress (2026-08-05)**: Phase 3 verifier framework built with 4 backends (Nitro, PKCS#11, WebAuthn, OIDC). All verifiers implement the `ProofVerifier` trait. 14 verifier tests pass. Verifier framework complete (Session 55-57). Blocked on: live Nitro deployment evidence (P0), core adapter integration (P0), distributed replay (P1).
- **Recommendation**: Select one provider scope at a time, implement its authenticated verifier and exact policy namespace, add official vectors and provider-backed negative tests, then attach CI, independent-review, provenance, and release-artifact evidence.
- **Tracking**: [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202)

#### SEC-005: Branch protection documented but not GitHub-enforced ✅ RESOLVED (2026-08-30)
- **Category**: Security / Governance
- **Priority**: P1
- **Description**: `docs/BRANCH_PROTECTION.md` (STRICT) and `docs/BRANCH_POLICY.md` (CON-520) mandate direct-commit prohibition, mandatory CODEOWNERS review, and required CI checks on `main`, but the GitHub branch-protection API reported `main` as **unprotected**. Direct pushes and merges without review/CI were not blocked.
- **Resolution**: Applied branch protection on `main` via the API: `enforce_admins=true`, `required_approving_review_count=1`, `require_code_owner_reviews=true`, `dismiss_stale_reviews=true`, `allow_force_pushes=false`, `allow_deletions=false`, and required status checks `Rust Tests`, `Linting`, `WASM Build`, `Repository Hygiene`, `Security Checks`, `Coverage Threshold (>= 70%)`, `WASM Runtime Evidence`, `Gitleaks History Scan`. Note: the PR author cannot self-approve; CODEOWNERS approval must come from `@admin-conxian-labs` for changes by `@botshelomokoka`.
- **Status**: Resolved — Session 63.

#### EVID-001: Provider, Runtime, and Artifact Evidence
- **Category**: Testing
- **Priority**: P1
- **Description**: WASM compilation and simulated attestation demonstrate build or structural behavior only. Provider/runtime integration, independent review, exact release artifacts, SBOM, provenance, and support decisions remain uncollected.
- **Risk**: A green local or CI build could be misread as hardware, runtime, deployment, or release evidence.
- **Session 57 Progress (2026-08-05)**: Phase 3 verifier framework built with 4 backends (Nitro, PKCS#11, WebAuthn, OIDC). All verifiers implement the `ProofVerifier` trait. 14 verifier tests pass. Verifier framework complete (Session 55-57). Blocked on: live Nitro deployment evidence (P0), core adapter integration (P0), distributed replay (P1).
- **Recommendation**: Attach exact provider/runtime test results, reviewed artifact digests, provenance/SBOM, independent findings, and a scoped support decision before promotion.
- **Tracking**: [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202)

### P2 - High

#### DEP-002: Unmaintained Dependencies with Exceptions
- **Category**: Dependency
- **Priority**: P2
- **Description**: Some dependencies have documented exceptions in `.cargo/audit.toml`/`deny.toml`
- **Ignored Advisories** (`.cargo/audit.toml` + `deny.toml`; verified live 2026-08-31 — `cargo audit` 0 vulns + `cargo deny` ok, 562 deps):
  - `RUSTSEC-2023-0089`: atomic-polyfill is unmaintained (in tree, frost→heapless)
  - `RUSTSEC-2024-0436`: paste is unmaintained (in tree)
  - `RUSTSEC-2024-0388`: derivative is unmaintained (in tree)
  - `RUSTSEC-2026-0173`: proc-macro-error2 is unmaintained (no longer in tree)
  - `RUSTSEC-2026-0009`: time stack exhaustion (patched — tree has time 0.3.55 ≥ 0.3.47)
  - `RUSTSEC-2026-0220`: ruint shift-overflow DoS (patched — tree has ruint 1.20.0)
- **Risk**: Potential future vulnerabilities in unmaintained code
- **Recommendation**: Review alternatives for unmaintained crates, document rationale for exceptions

#### DEP-003: Stale pre-rebrand `lib-conclave-sdk` crate on crates.io
- **Category**: Dependency / Documentation
- **Priority**: P2 - High
- **Description**: The SDK was rebranded "Conxius Enclave SDK" → "Conxius Enclave SDK" (PR #292), and the crates.io package was renamed to `conxius-enclave-sdk` (currently 2.0.17, owned by `botshelomokoka`, not yanked). The pre-rebrand `lib-conclave-sdk` crate (2.0.8, last published 2026-07-13) remains live on crates.io with the *same* description ("Hardware-backed security primitives for the broader Conxian ecosystem") and its `repository` field pointing at the same `Conxian/conxius-enclave-sdk` repo — nine versions behind.
- **Risk**: Downstream users searching crates.io may resolve the stale, pre-rebrand `lib-conclave-sdk` (2.0.8) instead of `conxius-enclave-sdk` (2.0.17), missing nine versions of security/crypto hardening.
- **Recommendation**: Yank `lib-conclave-sdk` 2.0.8 (or publish a final stub README pointing at `conxius-enclave-sdk`) and mark it deprecated.
- **Status**: **Resolved (Session 64, 2026-08-31)** — `lib-conclave-sdk@2.0.8` yanked via crates.io API; crate now reports `yanked=true` and `max_version 0.0.0` (no non-yanked versions).

#### TEST-001: Hardware Attestation Testing Gaps
- **Category**: Testing
- **Priority**: P2
- **Description**: Hardware-backed logic (enclave/) lacks comprehensive hardware testing
- **Current Coverage**: Software simulation tests only
- **Risk**: Changes to hardware attestation may break production flows
- **Recommendation**: Add integration tests with mock hardware; block production Trust Tiers without hardware tests
- **AGENTS.md Reference**: "Hardware-backed logic should be tested with both simulated and software attestation"
- **Status**: Unit/simulation evidence and typed fail-closed caller containment recorded (2026-07-21); real hardware/provider evidence, distributed replay, and production support remain open in [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195) and [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202)

### P3 - Medium

#### ARCH-001: WASM API coverage versus runtime evidence
- **Category**: Architecture
- **Priority**: P3
- **Description**: WASM API coverage must remain distinct from runtime, platform, provider, hardware, and JavaScript secret-boundary evidence
- **Current**: Required WASM sub-client API rows are explicit in the canonical capability evidence; exact counts are not readiness evidence
- **Risk**: Incomplete web/mobile integration surface
- **Status**: API inventory recorded (2026-07-15); runtime/platform/secret-boundary evidence remains open in [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200)
- **Related Issue**: Historical #172 is context only; current evidence work is #200

#### ARCH-002: Multiple `secp256k1` versions coexist and bridge by serialization
- **Category**: Architecture / Dependency
- **Priority**: P3 - Medium
- **Description**: Four `secp256k1` versions resolve simultaneously (`0.29.1` via `bitcoin 0.32.102`, `0.30.0` via `alloy-consensus`, `0.31.1` via `musig2`/`alloy-primitives`, `0.33.1` direct). `src/protocol/musig2.rs` bridges the direct `0.33.1` types to `musig2`'s `0.31.1` types via `from_slice(&pk.serialize())` / `from_byte_array(secret_key.to_secret_bytes())`.
- **Risk**: Type-fragmentation across a security-critical primitive; byte-serialization bridges are a subtle correctness surface and block eventual type-level convergence.
- **Recommendation**: Track upstream convergence (alloy/musig2 moving to `0.33.x`, or stable `bitcoin 0.33.x`) and replace serialization bridges with type-identical calls once a single version dominates.
- **Status**: Active; no correctness issue observed, tests green.

#### DOC-002: Missing Examples
- **Category**: Documentation
- **Priority**: P3
- **Description**: No examples directory or usage examples
- **Impact**: Developer onboarding friction
- **Recommendation**: Add `examples/` directory with common use cases
- **Affected Files**: Documentation only

### P4 - Low

#### TOOL-001: Cargo.lock Not Tracked
- **Category**: Tooling
- **Priority**: P4
- **Description**: Cargo.lock was not committed to version control
- **Current Practice**: `Cargo.lock` is tracked and all CI/release dependency commands use `--locked`
- **Impact**: Resolved for the committed dependency graph; release acceptance still requires exact-artifact evidence
- **Recommendation**: Keep the lockfile synchronized with intentional dependency changes and review lockfile diffs
- **Status**: ✅ RESOLVED (2026-07-20; issue #199 hardening)

#### DOC-003: CHANGELOG Formatting
- **Category**: Documentation
- **Priority**: P4
- **Description**: CHANGELOG lacks [Unreleased] section for tracking pending changes
- **Current**: Only documented releases, no unreleased changes section
- **Recommendation**: Add `[Unreleased]` section for tracking changes before release
- **Status**: ✅ RESOLVED (2026-07-13)

#### AUDIT-001: Untested Protocol Modules (Capability Audit 2026-08-07)
- **Category**: Testing
- **Priority**: P2
- **Description**: Capability audit identified 4 protocol modules with zero test coverage (`frost.rs`, `musig2.rs`, `cctp.rs`, `sidecar.rs`). Additionally, 26 out of 95 Rust source files have no dedicated test module.
- **Impact**: Behavioral regressions in these modules may not be caught by CI.
- **Recommendation**: Add targeted integration tests for the 4 untested modules and a minimum 3-4 test cases for each untested signing module.
- **Status**: MONITORING

#### AUDIT-002: Large File Maintainability Risk (Capability Audit 2026-08-07)
- **Category**: Architecture
- **Priority**: P3
- **Description**: Three source files exceed 2,000 lines (`protocol/frost.rs` at 3,041 lines, `signing/threshold.rs` at 2,326 lines, `enclave/nitro.rs` at 2,086 lines). These are well-covered by tests but present maintenance challenges.
- **Impact**: Onboarding friction; merge conflict surface; potential for cyclic imports.
- **Recommendation**: Consider extraction of helper modules (e.g., `frost_serde.rs`, `threshold_pedersen.rs`, `nitro_parser.rs`). Non-breaking as long as `pub use` re-exports from parent modules are maintained.
- **Status**: MONITORING

#### AUDIT-003: Taproot Utility Return Type (Capability Audit 2026-08-07) ✅ RESOLVED
- **Category**: Code Quality
- **Priority**: P0
- **Description**: `src/signing/taproot.rs` used `expect()` calls in `taproot_output_key` (violates no-panic policy).
- **Resolution**: Return type changed to `ConclaveResult<XOnlyPublicKey>` with proper error mapping (Session 57+).
- **Status**: ✅ RESOLVED (2026-08-07)

## Burn-Down Tracking

| Item | Identified | Target | Status | Updated |
|------|------------|--------|--------|---------|
| DEP-001 | 2026-07-08 | Next stable deps | ✅ Resolved (2026-08-30) — bitcoin 0.32.102 + secp256k1 0.33.1 | 2026-08-30 |
| DOC-001 | 2026-07-08 | v2.0.7 release | ✅ Resolved | 2026-07-14 |
| DEP-002 | 2026-07-08 | Q3 2026 | Planned | 2026-07-14 |
| TEST-001 | 2026-07-08 | Hardware/provider evidence | Reclassified — simulation/unit evidence only; #195 open | 2026-07-20 |
| SEC-002 | 2026-07-21 | Real provider verifier/signer | In Progress — 4 backends wired (Nitro, PKCS#11, WebAuthn, OIDC); blocked on live Nitro deployment evidence (P0), core adapter integration (P0) | 2026-08-05 |
| SEC-003 | 2026-07-21 | Distributed replay authorization | In Progress — design planned for Session 58; backend selection pending (DynamoDB vs PostgreSQL) | 2026-08-05 |
| SEC-004 | 2026-07-21 | Provider-specific proof verification | In Progress — 4 backends wired; blocked on live Nitro deployment evidence (P0), independent review (#202) | 2026-08-05 |
| EVID-001 | 2026-07-21 | Provider/runtime/artifact evidence | In Progress — Phase 3 verifier framework built (4 backends, 14 tests); real provider/runtime evidence still open; #200/#202 open | 2026-08-05 |
| SEC-001 | 2026-07-12 | Structural FROST validation | ✅ Resolved (structural validation only; production cryptography open) | 2026-07-20 |
| DOC-003 | 2026-07-08 | CHANGELOG [Unreleased] | ✅ Resolved | 2026-07-14 |
| ARCH-001 | 2026-07-14 | Runtime/platform/secret boundary | Reclassified — API inventory only; #200 open | 2026-07-20 |
| DOC-002 | 2026-07-14 | v2.0.11 | ✅ Resolved | 2026-07-15 |
| CI-001 | 2026-07-14 | v2.0.11 | ✅ Resolved | 2026-07-15 |
| PROTO-001 | 2026-07-08 | FROST/BitVM2/DLC/CCTP/Covenant hardened; Fedimint real crypto | ✅ Resolved — 7/7 crypto sub-items (Fedimint DLEQ + blinding real via `fedimint-crypto`); full threshold mint remains provider-gated | 2026-08-30 |
| BIP-110 | 2026-07-15 | v2.0.13 | ✅ Resolved | 2026-07-15 |

## Resolved Debt

- **BIP-110**: Added BIP-110 compliant message validation and chunking validation into BIP-322 message verification, hardened compact size serialization, and added comprehensive commitment segmentation tests (Resolved: 2026-07-15).
- **SEC-001**: Historical structural FROST DKG validation wording is superseded by the foundation-plus-quarantine boundary in `src/protocol/frost.rs`. Typed package/session validation remains; RFC 9591-compatible DKG, authenticated encryption, one-use nonces, secure share storage, signing, and aggregation remain open (reclassified: 2026-07-21).
- **TEST-001**: Comprehensive hardware attestation simulation/unit suite in `src/enclave/hardware_attestation_tests.rs` covering trust tiers, freshness, replay protection, cryptographic verification, and trust enforcement with 25 tests (evidence recorded: 2026-07-14; production hardware/provider gate remains open in #195).
- **ARCH-001**: WASM API inventory updated with explicit required sub-client rows (API evidence recorded: 2026-07-15; runtime/platform/secret-boundary gate remains open in #200).
- **DOC-002**: Examples directory created with 6 practical usage examples (Resolved: 2026-07-15).
- **PROTO-001**: Historical Ark/BitVM2/Fedimint/FROST “implemented” or “complete” wording is retained only as history and is superseded by the typed foundation/quarantine roadmap (reclassified: 2026-07-21).
- **CI-001**: Node.js 24 compliance - Updated all GitHub Actions to compatible versions (Resolved: 2026-07-15).
- **Session 54 Cleanup**: Clippy warnings resolved (0 warnings, both feature modes), cargo-deny cleaned (4 stale advisory ignores removed), Dependabot CVE-2025-59288 patched (playwright 1.55.1) (Resolved: 2026-08-04).

## Maintenance Notes

- This inventory should be reviewed monthly
- New debt items should be added during code review
- Items should be resolved or reclassified quarterly
- High-priority items should be addressed before major releases

---

*Inventory initiated by OpenHands AI agent - 2026-07-08*
*Maintained by: SDK Team*

---

## Session 59 — Expanded Research & Candidate 75-Point Scoring Matrix (2026-08-07)

### Research & Candidate Scoring Synthesis
In accordance with the 75-point weighted gap scoring rubric (Security: 3x, Blocker: 3x, Unlock: 2x, Evidence: 2x, Confidence: 2x, Efficiency: 1x, External: 1x, Doc Risk: 1x), the remaining candidates are evaluated:

| Gap / Candidate | Sec | Blocker | Unlock | Evidence | Confidence | Efficiency | External | Doc Risk | Formula Score | Status |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `#267` BitVM2 Groth16 Proof Verification | 5 | 5 | 4 | 5 | 5 | 4 | 5 | 5 | 73 / 75 | **Selected Candidate (Session 59)** |
| `#242` AWS Nitro Live Enclave Attestation | 5 | 4 | 4 | 2 | 3 | 3 | 4 | 4 | 56 / 75 | Next Sprint Target |
| `#200` WASM Secret Isolation & Memory Boundary | 4 | 5 | 4 | 3 | 4 | 4 | 4 | 4 | 61 / 75 | Next Sprint Target |

## Session 61 — Groth16 Real Pairing Verification Resolved (2026-08-29)

- **`#267` (73/75)**: ✅ Implemented. The structural-only Groth16 verifier (Session 59) was a fail-open gap; it now performs the real BLS12-381 pairing equation behind the `groth16` feature and fails closed otherwise. Closed as a code-gap; BitVM2 protocol-conformance/live-bridge/review evidence remains open (`#202`).
- **`G240-RP` durable replay backend (66/75)**: ✅ Reference backends implemented — `FileBackedDurableReplayStore` (higher-level `DurableReplayStore`) and `DurableFileReplayStore` (lower-level `ReplayStore` with `DurableProvider`, passes the backend-neutral conformance suite incl. 32-thread + overlapping-batch contention). Both use `O_EXCL` atomic conditional writes (`ON CONFLICT DO NOTHING`), `fsync`-before-commit, all-or-nothing batches, and a persisted high-water anti-rollback clock. The production multi-replica backend (DynamoDB/PostgreSQL) remains outside the crate.
- **Remaining scored candidates (Session 62 targets)**:
  - `#200` WASM runtime/platform evidence (61/75) — external-blocked (headless browser/Node).
  - `#242` AWS Nitro live attestation (56/75) — external-blocked (AWS deployment).
  - `#241` Android KeyMint/StrongBox (59/75) — external-blocked (real device).
  - `#202` independent review + release acceptance (44/75) — external-blocked (reviewer).
