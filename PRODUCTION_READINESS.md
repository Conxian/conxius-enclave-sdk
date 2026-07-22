# Production Enablement Checklist

> This is a gated checklist, not a production-readiness claim.
> Status: Beta / conditional | Last Updated: 2026-07-22

The 2.x line is not approved for unqualified production signing or settlement. Use the [production-enablement audit](./docs/audits/PRODUCTION_ENABLEMENT_AUDIT_2026-07-20.md), [capability matrix](./docs/architecture/CAPABILITY_MATRIX.md), [machine-readable evidence](./docs/architecture/capability-evidence.json), [public operations runbook](./docs/operations/PUBLIC_OPERATIONS_RUNBOOK.md), [release recovery runbook](./docs/operations/RELEASE_RECOVERY_RUNBOOK.md), and [protocol implementation roadmap](./docs/architecture/PROTOCOL_IMPLEMENTATION_ROADMAP.md) as the canonical evidence record. The latest visible GitHub release/tag is `v2.0.11`; `Cargo.toml` declaring `2.0.12` does not establish a supported release.

Merged PR [#205](https://github.com/Conxian/conxius-enclave-sdk/pull/205), merged PR [#216](https://github.com/Conxian/conxius-enclave-sdk/pull/216), and the typed-settlement follow-up code checkpoint are containment and evidence-boundary work only. They make missing provider evidence fail closed and preserve signer-identity binding; they do not establish real hardware/provider integration, distributed replay, runtime support, independent review, release artifacts, or production readiness. Issue [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195) remains open.

Phase A of CON-1512 adds an explicit proof-factor taxonomy and fail-closed composition boundary for server identity, user authorization, phone/device attestation, TEE attestation, FIDO2/WebAuthn assertions, and TPM quotes. The canonical `ProofBoundValueBearingAuthorization` is now required by the value-bearing settlement rail boundary; the production verifier registry is intentionally unavailable, test fixtures are test-only, and no category is production-supported until concrete provider roots/collateral, runtime integration, replay coordination, independent review, and exact release artifacts exist. Existing `DeviceIntegrityReport` and legacy `ProofSetPolicy`/`VerifiedProofSet` types are not silently promoted into the canonical proof authorization.

Issue #240 Phase A additionally defines the provider-neutral trust/collateral,
single-mechanism normalized-result, audit-redaction, and durable-replay
contracts. A normalized result and replay authorization are explicitly scoped
to one mechanism; exact `ProofPolicy::production()` and verifier binding are
contextual requirements, not six-factor authorization. Complete all-required
authorization remains exclusively the composed proof-bundle path. The new
transport types and negative/fixture tests are containment evidence only. The
production authenticator, provider verifier, and durable replay store remain
explicitly unavailable; the contract's revision/rollback fields are stateless,
and the local fake replay store is test-only. No Android, Nitro, provider,
hardware, persistent rollback, distributed replay, WASM, release, independent
review, or production-support gate is checked by this phase.

Issue #145 is a **historical CI/CD baseline**, not current release-acceptance evidence. Repository-control work for toolchain, dependency, publisher, scanning, SBOM, provenance, and exact-artifact evidence is tracked by [issue #199](https://github.com/Conxian/conxius-enclave-sdk/issues/199); independent review and release acceptance remain open in [issue #202](https://github.com/Conxian/conxius-enclave-sdk/issues/202). Historical issues #145, #154, #169, #172, #173, #174, and #180 provide context only and must not be used as current production proof.

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
- [x] Provider-neutral collateral, secret-free replay, durable-replay, and release-evidence contracts are implemented and tested; provider authentication, durable deployment, authority, and promotion decisions remain open ([CON-1543](https://linear.app/conxian-labs/issue/CON-1543/p0-operationalize-attestation-roots-collateral-revocation-and), [#240](https://github.com/Conxian/conxius-enclave-sdk/issues/240))
- [x] Typed error surface exists (`ConclaveResult`); production fail-closed behavior remains gated
- [x] Typed value-bearing settlement containment enforces settlement purpose/domain/context, canonical six-proof authorization, process-local replay, and raw-dispatch rejection; Opportunity preflight is validation-only, the no-proof path rejects before provider key lookup, the explicit proof path stops at the unavailable production verifier, and all built-in adapter dispatch remains disabled pending a versioned wire contract and gateway compatibility evidence; this remains containment rather than provider or production evidence
- [x] Phase A composer-level typed proof-factor taxonomy and explicit all-required proof-set behavior are bounded, independently diagnosable, and fail closed; single-mechanism trust normalization/replay is not complete authorization, and actual providers/runtimes, vendor roots/collateral, distributed replay, independent review, and release artifacts remain unsupported, so server, user, phone/device, TEE, FIDO2/WebAuthn, and TPM categories are not production-supported
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
- [x] Tracked WASM runtime execution harness covers Node, browser, bundler, and worker lanes; passing negative/runtime tests do not establish provider, hardware, or production support
- [x] WASM private-key export path removed; provider/runtime support remains fail-closed
- [x] Negative tests cover missing provider evidence, simulator exclusion, typed proof-factor/context mismatches, incomplete proof sets, typed binding mismatches, and raw settlement dispatch rejection
- [x] WASM FROST/Fedimint/Ark/BitVM2 quarantine methods propagate typed unsupported errors without secret-bearing outputs; legacy BitVM challenge signing/aggregation also fail with `PROTOCOL_UNSUPPORTED` before decoding
- [ ] Fuzz testing for critical paths

### 📦 Dependency Requirements

- [x] Dependencies are declared in Cargo.toml
- [x] Cargo.lock and the release dependency graph are committed and checked with `--locked` (implementation evidence; release acceptance remains open)
- [x] Toolchain/MSRV is pinned and compatible with the resolved graph (Rust 1.94.1 MSRV / Rust 1.97.1 CI pin)
- [ ] Unmaintained and security-sensitive dependency review (P1/P2)

### 🌐 Platform Integration

- [x] WASM binding API surface is inventoried in the capability evidence record
- [x] WASM secret-boundary policy and migration note are documented
- [x] WASM runtime execution matrix is documented; provider, platform, attestation, artifact/provenance, and production-support gates remain open (P1)
- [ ] Multi-chain support with verified address provenance (P1)
- [ ] Settlement rails implemented without placeholders and backed by integration evidence (P0)

### 📚 Examples & Documentation

- [ ] `examples/` and operational runbooks aligned with the matrix (DOC-002 - P2)
- [x] SDK-local telemetry privacy and delivery contract (`docs/operations/TELEMETRY_OPERATIONS.md`)
- [x] Public-safe operations and release-recovery runbooks (`docs/operations/PUBLIC_OPERATIONS_RUNBOOK.md`, `docs/operations/RELEASE_RECOVERY_RUNBOOK.md`)
- [ ] Deployment monitoring, named person/on-call assignment, service retention policy, rollback drill, and exact-release evidence (documentation alone does not check this gate)
- [x] API documentation via rustdoc
- [x] Architecture documentation
- [x] Gap scorecard maintained
- [x] Technical debt inventory current

### 🚀 Release Process

- [ ] Reconcile package metadata with a verified release tag (latest visible: `v2.0.11`)
- [x] Select one authoritative release/publish workflow (`release-strict.yml`; one automatic tag publisher with manual recovery)
- [ ] Verify the exact tagged registry artifact and retain all release-gate results for that artifact
- [ ] Attach registry, SBOM, provenance, lockfile, checksum, and release-note evidence from a live tagged run
- [ ] Complete independent release/security acceptance (issue #202)
- [ ] Verify service-side telemetry retention/access/deletion, aggregate monitoring, named on-call assignment, and a rollback drill for the exact deployment scope

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
| Release Validation | One authoritative `release-strict.yml` workflow owns publication and release creation; tag paths reuse the full-history secret scan and compare the crates.io artifact digest | Live tagged registry/provenance evidence and independent acceptance remain open in #199 and #202; workflow presence is not a release artifact |
| Telemetry operations | SDK-local redaction, endpoint, timeout/retry, disablement, and failure-isolation controls are tested and documented | Service-side monitoring, retention/access/deletion, named on-call assignment, rollback drill, independent review, and exact release evidence remain unchecked |

---

## Version Readiness

| Version | Status | Notes |
|---------|--------|-------|
| 2.x line | Beta / conditional | Production enablement remains blocked by CON-1506 P0/P1 gates and protocol roadmap milestones |
| v2.0.11 | Latest visible GitHub release/tag | Verify artifacts and capability scope before use |
| 2.0.12 | Cargo metadata only at the 2026-07-21 review | No matching visible tag/release or registry evidence was found |

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

The release workflow now contains repository controls for full-history secret scanning, attestation identity retention, registry-artifact digest comparison, and post-publication GitHub Release ordering. These controls are not live release evidence: issue [#199](https://github.com/Conxian/conxius-enclave-sdk/issues/199) and independent acceptance issue [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) remain open until a tagged run produces reviewable artifacts and the required acceptance decision.

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
- [ ] Verify service-side telemetry monitoring and retention/access/deletion evidence for the exact deployment
- [ ] Confirm named deployment/on-call assignment; role documentation alone is not assignment evidence

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
*Last reviewed: 2026-07-22*
