# Production Enablement Checklist

> This is a gated checklist, not a production-readiness claim.
> Status: Beta / conditional | Last Updated: 2026-07-21

The 2.x line is not approved for unqualified production signing or settlement. Use the [production-enablement audit](./docs/audits/PRODUCTION_ENABLEMENT_AUDIT_2026-07-20.md), [capability matrix](./docs/architecture/CAPABILITY_MATRIX.md), [machine-readable evidence](./docs/architecture/capability-evidence.json), and [protocol implementation roadmap](./docs/architecture/PROTOCOL_IMPLEMENTATION_ROADMAP.md) as the canonical evidence record. The latest visible GitHub release/tag is `v2.0.11`; `Cargo.toml` declaring `2.0.12` does not establish a supported release.

Merged PR [#205](https://github.com/Conxian/conxius-enclave-sdk/pull/205), merged PR [#216](https://github.com/Conxian/conxius-enclave-sdk/pull/216), and the typed-settlement follow-up code checkpoint are containment and evidence-boundary work only. They make missing provider evidence fail closed and preserve signer-identity binding; they do not establish real hardware/provider integration, distributed replay, runtime support, independent review, release artifacts, or production readiness. Issue [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195) remains open.

Issue #145 is a **historical CI/CD baseline**, not current release-acceptance evidence. Residual toolchain, dependency, publisher, scanning, SBOM, provenance, and exact-artifact work is tracked by [issue #199](https://github.com/Conxian/conxius-enclave-sdk/issues/199). Historical issues #145, #154, #169, #172, #173, #174, and #180 provide context only and must not be used as current production proof.

---

## Pre-Release Checklist

### 📋 Documentation Requirements

- [x] README.md updated with conditional status
- [x] CHANGELOG.md has `[Unreleased]` section
- [x] SECURITY.md policy documented
- [x] LICENSE is present (MIT)
- [x] GOVERNANCE.md defined
- [x] RELEASING.md documented
- [x] AGENTS.md for AI assistant context
- [x] TRACKING.md for issue management

### 🔒 Security Requirements

- [x] Historical CI/CD baseline recorded (issue #145); residual release evidence remains open in [#199](https://github.com/Conxian/conxius-enclave-sdk/issues/199)
- [x] Code quality hardening complete (issue #146)
- [ ] Hardware-backed attestation integration and vendor evidence (P0)
- [ ] Replay protection verified on every value-bearing path (P0/P1)
- [x] Typed error surface exists (`ConclaveResult`); production fail-closed behavior remains gated
- [x] Typed value-bearing settlement containment enforces settlement purpose/domain/context and raw-dispatch rejection; Opportunity preflight is validation-only and all built-in adapter dispatch is disabled pending a versioned wire contract and gateway compatibility evidence; this remains containment rather than provider or production evidence
- [ ] FROST treasury DKG and signing production readiness (issue #180; current `src/protocol/frost.rs` is a typed boundary/quarantine, not production FROST cryptography)
- [x] Protocol boundary quarantine for FROST, Fedimint, Ark, and BitVM2 (typed models and exact unsupported errors; see roadmap)
- [ ] Protocol implementation, vector, provider, persistence, independent-review, and exact-artifact gates (issue #197 and roadmap)
- [ ] Independent security audit (for >= 1.0.0)
- [ ] Dependency audit passes (cargo audit)
- [x] No hardcoded secrets or credentials

### 🧪 Testing Requirements

- [x] Unit/structural tests for core modules (scope-limited)
- [ ] Integration tests against real protocol and vendor boundaries
- [ ] Cross-chain tests with verified addresses and live/testnet evidence
- [ ] **Hardware attestation integration tests** (P0/P1)
- [ ] WASM runtime integration tests
- [x] WASM private-key export path removed; provider/runtime support remains fail-closed
- [x] Negative tests cover missing provider evidence, simulator exclusion, typed binding mismatches, and raw settlement dispatch rejection
- [x] WASM FROST/Fedimint/Ark/BitVM2 quarantine methods propagate typed unsupported errors without secret-bearing outputs
- [ ] Fuzz testing for critical paths

### 📦 Dependency Requirements

- [x] Dependencies are declared in Cargo.toml
- [x] Cargo.lock and the release dependency graph are committed and checked with `--locked` (implementation evidence; release acceptance remains open)
- [x] Toolchain/MSRV is pinned and compatible with the resolved graph (Rust 1.94.1 MSRV / Rust 1.97.1 CI pin)
- [ ] Unmaintained and security-sensitive dependency review (P1/P2)

### 🌐 Platform Integration

- [x] WASM binding API surface is inventoried in the capability evidence record
- [x] WASM secret-boundary policy and migration note are documented
- [ ] WASM runtime/platform/hardware matrix (P1)
- [ ] Multi-chain support with verified address provenance (P1)
- [ ] Settlement rails implemented without placeholders and backed by integration evidence (P0)

### 📚 Examples & Documentation

- [ ] `examples/` and operational runbooks aligned with the matrix (DOC-002 - P2)
- [x] Public-safe telemetry privacy and delivery runbook (`docs/operations/TELEMETRY_OPERATIONS.md`)
- [x] API documentation via rustdoc
- [x] Architecture documentation
- [x] Gap scorecard maintained
- [x] Technical debt inventory current

### 🚀 Release Process

- [ ] Reconcile package metadata with a verified release tag (latest visible: `v2.0.11`)
- [x] Select one authoritative release/publish workflow (`release-strict.yml`; one automatic tag publisher with manual recovery)
- [ ] Verify CI gates and retain their results for the exact artifact
- [ ] Attach registry, SBOM, provenance, and release-note evidence

### 🔧 Environment Setup

- [ ] `CARGO_REGISTRY_TOKEN` configured in GitHub `release` environment
- [ ] crates.io account verified
- [ ] NPM account for WASM publishing (optional)
- [ ] Domain ownership for WASM package

---

## CI/CD Gates Status

| Gate | Repository evidence | Production decision |
|------|----------------------|---------------------|
| Tests | CI definitions and unit/structural tests exist | Not sufficient without protocol/vendor integration evidence |
| Lint/Format | CI definitions exist; local format check is separate | Required, but not a production gate by itself |
| WASM Build | `ci.yml` and `ci-strict.yml` build WASM | Runtime/platform/hardware matrix is still open |
| Security Audit | Security workflows are defined | Independent review evidence is not attached |
| CodeQL | Workflow is defined | Workflow presence is not a release artifact |
| Release Validation | Multiple release workflows exist | Consolidation and durable artifact evidence remain open in #199; workflow presence is not a release artifact |

---

## Version Readiness

| Version | Status | Notes |
|---------|--------|-------|
| 2.x line | Beta / conditional | Production enablement remains blocked by CON-1506 P0/P1 gates and protocol roadmap milestones |
| v2.0.11 | Latest visible GitHub release/tag | Verify artifacts and capability scope before use |
| 2.0.12 | Cargo metadata only at audit time | No matching visible tag/release evidence was found |

---

## Known Technical Debt

| ID | Priority | Status | Blocking Release |
|----|----------|--------|------------------|
| CON-1506 / P0 | P0 | Open — production claim and value-bearing paths blocked | Yes |
| CON-1506 / P1 | P1 | Open — supply chain, release, matrix, privacy, and operations evidence; implementation tracking is #199–#201 | Yes |
| TEST-001 | P2 | Planned — broader hardware/runtime evidence | Yes for affected capability |
| DEP-002 | P2 | Planned — unmaintained crate review | Conditional |
| ARCH-001 | P2 | Planned — WASM API coverage is recorded; runtime/platform/secret-boundary evidence is tracked by #200 | Yes for WASM support |
| DOC-002 | P2 | Planned — examples and runbooks | No, but public claims must remain accurate |

---

## Release Procedure

No release procedure below authorizes production enablement by itself. A candidate release must pass the audit gates and attach evidence for the exact tag, target, runtime, and deployment scope.

```bash
# 1. Verify all checks pass
cargo fmt --all -- --check
cargo clippy -- -D warnings
cargo test
cargo audit --file Cargo.lock

# 2. Reconcile Cargo.toml, Cargo.lock, the tag, CHANGELOG, and registry state

# 3. Create a release commit only after the capability matrix and independent review are current
git add -A
git commit -m "chore: prepare reviewed 2.x release"

# 4. Push and create tag
git push origin main
git tag -s vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z

# 5. Trigger the single authoritative release workflow only after artifact review
```

## Post-Release Checklist

- [ ] Verify the exact GitHub release and tag
- [ ] Verify registry publication for the exact package/version
- [ ] Retain CI, SBOM, provenance, and independent-review artifacts
- [ ] Verify README, SECURITY, matrix, and changelog scope
- [ ] Publish only public-safe operational notes
- [ ] Record rollback owner and tested rollback procedure

---

## Support & Maintenance

| Resource | Contact |
|----------|---------|
| Support Email | support@conxian-labs.com |
| Security Email | security@conxian-labs.com |
| GitHub Issues | https://github.com/Conxian/conxius-enclave-sdk/issues |
| crates.io | https://crates.io/crates/conxius-enclave-sdk |

---

*Checklist maintained by: SDK Team*
*Last reviewed: 2026-07-20*
