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

#### DEP-001: Beta/Release Candidate Dependencies
- **Category**: Dependency
- **Priority**: P1
- **Description**: Multiple critical cryptographic dependencies use beta/RC versions
- **Affected Dependencies**:
  - `bitcoin = "0.33.0-beta"` - Bitcoin protocol support
  - `secp256k1 = "0.32.0-beta.2"` - ECDSA/Schnorr signatures
  - `k256 = "0.14.0"` - K-256 elliptic curve
- **Risk**: Breaking changes on stable release, potential compatibility issues
- **Recommendation**: Pin to stable versions as they become available; monitor upstream releases
- **Tracking**: Monitor RustSec advisories for these crates

#### DOC-001: No Published Releases
- **Category**: Documentation
- **Priority**: P1
- **Description**: README states "no published GitHub releases" but CHANGELOG documents releases
- **Impact**: Confusing for new developers, misalignment between documentation and reality
- **Recommendation**: Publish v2.0.7 as first release, update README status
- **Related Issue**: #154

### P2 - High

#### DEP-002: Unmaintained Dependencies with Exceptions
- **Category**: Dependency
- **Priority**: P2
- **Description**: Some dependencies have documented exceptions in audit.toml/deny.toml
- **Ignored Advisories**:
  - `RUSTSEC-2024-0436`: paste is unmaintained
  - `RUSTSEC-2026-0173`: proc-macro-error2 is unmaintained
  - `RUSTSEC-2024-0388`: derivative is unmaintained
  - `RUSTSEC-2026-0009`: time stack exhaustion
- **Risk**: Potential future vulnerabilities in unmaintained code
- **Recommendation**: Review alternatives for unmaintained crates, document rationale for exceptions

#### TEST-001: Hardware Attestation Testing Gaps
- **Category**: Testing
- **Priority**: P2
- **Description**: Hardware-backed logic (enclave/) lacks comprehensive hardware testing
- **Current Coverage**: Software simulation tests only
- **Risk**: Changes to hardware attestation may break production flows
- **Recommendation**: Add integration tests with mock hardware; block production Trust Tiers without hardware tests
- **AGENTS.md Reference**: "Hardware-backed logic should be tested with both simulated and software attestation"
- **Status**: Unit/simulation evidence recorded (2026-07-14); production hardware/provider evidence and caller enforcement remain open in [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195) and [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202)

### P3 - Medium

#### ARCH-001: WASM API coverage versus runtime evidence
- **Category**: Architecture
- **Priority**: P3
- **Description**: WASM API coverage must remain distinct from runtime, platform, provider, hardware, and JavaScript secret-boundary evidence
- **Current**: Required WASM sub-client API rows are explicit in the canonical capability evidence; exact counts are not readiness evidence
- **Risk**: Incomplete web/mobile integration surface
- **Status**: API inventory recorded (2026-07-15); runtime/platform/secret-boundary evidence remains open in [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200)
- **Related Issue**: Historical #172 is context only; current evidence work is #200

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

## Burn-Down Tracking

| Item | Identified | Target | Status | Updated |
|------|------------|--------|--------|---------|
| DEP-001 | 2026-07-08 | Next stable deps | In Progress | 2026-07-14 |
| DOC-001 | 2026-07-08 | v2.0.7 release | ✅ Resolved | 2026-07-14 |
| DEP-002 | 2026-07-08 | Q3 2026 | Planned | 2026-07-14 |
| TEST-001 | 2026-07-08 | Hardware/provider evidence | Reclassified — simulation/unit evidence only; #195 open | 2026-07-20 |
| SEC-001 | 2026-07-12 | Structural FROST validation | ✅ Resolved (structural validation only; production cryptography open) | 2026-07-20 |
| DOC-003 | 2026-07-08 | CHANGELOG [Unreleased] | ✅ Resolved | 2026-07-14 |
| ARCH-001 | 2026-07-14 | Runtime/platform/secret boundary | Reclassified — API inventory only; #200 open | 2026-07-20 |
| DOC-002 | 2026-07-14 | v2.0.11 | ✅ Resolved | 2026-07-15 |
| CI-001 | 2026-07-14 | v2.0.11 | ✅ Resolved | 2026-07-15 |
| BIP-110 | 2026-07-15 | v2.0.13 | ✅ Resolved | 2026-07-15 |

## Resolved Debt

- **BIP-110**: Added BIP-110 compliant message validation and chunking validation into BIP-322 message verification, hardened compact size serialization, and added comprehensive commitment segmentation tests (Resolved: 2026-07-15).
- **SEC-001**: Added structural FROST DKG Round 2 verification in `src/protocol/frost.rs` to validate received shares against expected polynomial commitments and identifiers. This resolves the placeholder validation only; production RFC 9591-compatible DKG, signing, secure share storage, and real aggregation remain open (reclassified: 2026-07-20).
- **TEST-001**: Comprehensive hardware attestation simulation/unit suite in `src/enclave/hardware_attestation_tests.rs` covering trust tiers, freshness, replay protection, cryptographic verification, and trust enforcement with 25 tests (evidence recorded: 2026-07-14; production hardware/provider gate remains open in #195).
- **ARCH-001**: WASM API inventory updated with explicit required sub-client rows (API evidence recorded: 2026-07-15; runtime/platform/secret-boundary gate remains open in #200).
- **DOC-002**: Examples directory created with 6 practical usage examples (Resolved: 2026-07-15).
- **CI-001**: Node.js 24 compliance - Updated all GitHub Actions to compatible versions (Resolved: 2026-07-15).

## Maintenance Notes

- This inventory should be reviewed monthly
- New debt items should be added during code review
- Items should be resolved or reclassified quarterly
- High-priority items should be addressed before major releases

---

*Inventory initiated by OpenHands AI agent - 2026-07-08*
*Maintained by: SDK Team*
