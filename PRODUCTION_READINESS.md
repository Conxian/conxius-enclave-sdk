# Production Readiness Checklist

> Comprehensive checklist for deploying Conclave SDK to production
> Version: 1.0.0 | Last Updated: 2026-07-13

---

## Pre-Release Checklist

### 📋 Documentation Requirements

- [x] README.md updated with production status
- [x] CHANGELOG.md has `[Unreleased]` section
- [x] SECURITY.md policy documented
- [x] LICENSE is production-ready (MIT)
- [x] GOVERNANCE.md defined
- [x] RELEASING.md documented
- [x] AGENTS.md for AI assistant context
- [x] TRACKING.md for issue management

### 🔒 Security Requirements

- [x] CI/CD baseline hardened (issue #145)
- [x] Code quality hardening complete (issue #146)
- [x] Hardware attestation implemented
- [x] Replay attack protection in place
- [x] Zero-dependency error handling (ConclaveResult)
- [x] FROST DKG Round 2 verification (issue #168)
- [ ] Independent security audit (for >= 1.0.0)
- [ ] Dependency audit passes (cargo audit)
- [x] No hardcoded secrets or credentials

### 🧪 Testing Requirements

- [x] Unit tests for core modules
- [x] Integration tests for protocol flows
- [x] Cross-chain tests (30+ assets)
- [ ] **Hardware attestation tests** (TEST-001 - P2)
- [ ] WASM integration tests
- [ ] Fuzz testing for critical paths

### 📦 Dependency Requirements

- [x] All dependencies declared in Cargo.toml
- [x] Cargo.lock generated (ephemeral per RELEASING.md)
- [x] No yanked dependencies
- [ ] **Stable versions for beta deps** (DEP-001 - P1)
  - [ ] bitcoin 0.33.x stable
  - [ ] secp256k1 0.32.x stable
  - [ ] k256 0.14.x stable
- [ ] Unmaintained crate review (DEP-002 - P2)

### 🌐 Platform Integration

- [x] WASM bindings generated
- [ ] WASM bindings completeness audit (ARCH-001 - P3)
- [x] Multi-chain support (30+ assets)
- [x] Settlement rails implemented

### 📚 Examples & Documentation

- [ ] `examples/` directory (DOC-002 - P3)
- [x] API documentation via rustdoc
- [x] Architecture documentation
- [x] Gap scorecard maintained
- [x] Technical debt inventory current

### 🚀 Release Process

- [ ] Create release tag (v2.0.9)
- [ ] Push tag to trigger Release workflow
- [ ] Verify CI gates pass
- [ ] Run manual publish workflow
- [ ] Verify crates.io publication
- [ ] Create GitHub release notes

### 🔧 Environment Setup

- [ ] `CARGO_REGISTRY_TOKEN` configured in GitHub `release` environment
- [ ] crates.io account verified
- [ ] NPM account for WASM publishing (optional)
- [ ] Domain ownership for WASM package

---

## CI/CD Gates Status

| Gate | Status | Workflow |
|------|--------|----------|
| Tests | ✅ Pass | `CI.yml` |
| Lint/Format | ✅ Pass | `CI.yml` |
| WASM Build | ✅ Pass | `CI.yml` |
| Security Audit | ✅ Pass | `Security.yml` |
| CodeQL | ✅ Pass | `CodeQL.yml` |
| Release Validation | ✅ Pass | `Release.yml` |

---

## Version Readiness

| Version | Status | Notes |
|---------|--------|-------|
| v2.0.9 | ✅ Ready for Release | All issues closed |
| v2.0.8 | 🔄 In Progress | Fedimint + Ark hardening |

---

## Known Technical Debt

| ID | Priority | Status | Blocking Release |
|----|----------|--------|------------------|
| DEP-001 | P1 | ⚠️ In Progress | Yes |
| DOC-001 | P1 | ✅ Resolved | No |
| TEST-001 | P2 | 📋 Planned | No |
| DEP-002 | P2 | 📋 Planned | No |
| ARCH-001 | P3 | 📋 Planned | No |
| DOC-002 | P3 | 📋 Planned | No |

---

## Release Procedure

### Option 1: Release v2.0.9 Now

```bash
# 1. Verify all checks pass
cargo fmt --all -- --check
cargo clippy -- -D warnings
cargo test
cargo audit --file Cargo.lock

# 2. Update CHANGELOG (already done)
# Ensure [Unreleased] section is current

# 3. Create release commit (if needed)
git add -A
git commit -m "chore: prepare v2.0.9 release"

# 4. Push and create tag
git push origin main
git tag -s v2.0.9 -m "Release v2.0.9"
git push origin v2.0.9

# 5. Trigger manual publish via GitHub Actions
# Actions → Release → Run workflow → v2.0.9 → publish_to_crates_io: true
```

### Option 2: Wait for Stable Dependencies

```bash
# Monitor upstream releases:
# - https://crates.io/crates/bitcoin
# - https://crates.io/crates/secp256k1  
# - https://crates.io/crates/k256

# When stable versions available, update Cargo.toml and create v2.0.8
```

---

## Post-Release Checklist

- [ ] Verify GitHub release created
- [ ] Verify crates.io package published
- [ ] Verify README version badge updated
- [ ] Notify stakeholders
- [ ] Update documentation links
- [ ] Close tracking issues
- [ ] Schedule v2.0.8 planning

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
*Last reviewed: 2026-07-13*
