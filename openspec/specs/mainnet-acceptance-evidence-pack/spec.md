# Mainnet Acceptance Evidence Pack Specification

## Purpose
This specification defines the mandatory governance, technical evidence, and verification standards for candidate promotions targeting the `main` branch (`staged` -> `main` branch promotions). Every pull request targeting `main` MUST contain a complete, non-placeholder Mainnet Acceptance Evidence Pack adhering to the requirements set forth in this document and enforced by `scripts/branch_promotion_policy.py`.

---

## Requirements

### Requirement: Promotion Metadata
Every promotion PR targeting `main` MUST record explicit commit lineage metadata under the `#### Promotion metadata` heading.
- The metadata MUST contain:
  1. `Promotion source SHA`: The exact 40-character commit SHA on the source branch (`staged` or `promotion/staged-to-main-<sha>`).
  2. `Promotion target-base SHA`: The exact 40-character commit SHA on `main` at candidate creation time.
  3. `Promotion commit window`: The commit range in `target_sha..source_sha` format.
  4. Reference to this specification file (`openspec/specs/mainnet-acceptance-evidence-pack/spec.md`).

#### Scenario: Validating promotion metadata
- **WHEN** a promotion PR to `main` is evaluated by `scripts/branch_promotion_policy.py`
- **THEN** the policy parser verifies that source SHA, target-base SHA, and commit window match the PR head/base refs without placeholders.

---

### Requirement: Mainnet-Only Production Scope
Every promotion PR targeting `main` MUST verify and record production scope constraints under the `#### Mainnet-only production scope` heading.
- The evidence MUST explicitly assert:
  1. Network parameter boundaries are constrained strictly to production mainnet execution.
  2. Zero testnet, devnet, or debug fail-open fallbacks exist in release candidate configurations.
  3. Network context fail-closed invariants are active across all protocol bridges and enclave verifiers.

#### Scenario: Verifying production network scope
- **WHEN** evaluating release readiness for mainnet promotion
- **THEN** all production configuration parameters are confirmed mainnet-isolated and fail-closed against non-mainnet environments.

---

### Requirement: Contamination and Residue Proof
Every promotion PR targeting `main` MUST provide proof of zero contamination under the `#### Contamination and residue proof` heading.
- The evidence MUST confirm:
  1. Zero hardcoded test credentials, mock keys, private secrets, or internal management tokens in the candidate diff.
  2. Zero staging artifacts, temporary debug instrumentation, or transient test data.
  3. Complete adherence to Zero Sensitivity Exposure (ZSE) principles across codebase and workflows.

#### Scenario: Audit for credentials and residue
- **WHEN** scanning candidate commits for mainnet promotion
- **THEN** automated secret checks and hygiene validation confirm no sensitive credentials or mock artifacts are present.

---

### Requirement: Successful Production Validation
Every promotion PR targeting `main` MUST document test suite execution and evidence validity under the `#### Successful production validation` heading.
- The evidence MUST include:
  1. Confirmation that all unit, integration, and security test suites executed and passed cleanly in CI.
  2. Confirmation that capability evidence (`scripts/validate_capability_evidence.py`) is current with zero drift.
  3. Automated workflow check confirmation across cargo audit, cargo test, and hygiene pipelines.

#### Scenario: Confirming automated test suite pass
- **WHEN** reviewing candidate promotion evidence
- **THEN** CI run status and capability matrix check confirm 100% test pass rate and capability evidence validity.

---

### Requirement: Release-Readiness Sign-off
Every promotion PR targeting `main` MUST record governance and security sign-off under the `#### Release-readiness sign-off` heading.
- The evidence MUST record:
  1. Assessment of security posture, threat model impact, and governance controls.
  2. Verification that required CODEOWNERS reviews and policy gates have been satisfied.
  3. SemVer release compliance and documentation alignment.

#### Scenario: Obtaining release readiness sign-off
- **WHEN** preparing a mainnet promotion PR for final review
- **THEN** security posture impact is assessed and CODEOWNERS governance controls are satisfied.

---

### Requirement: Owner Accountability
Every promotion PR targeting `main` MUST identify the accountable entity under the `#### Owner accountability` heading.
- The evidence MUST record:
  1. The designated release engineer, team, or automated promotion workflow actor responsible for candidate creation.
  2. The accountable team role (e.g., `@Conxian/release-team`).

#### Scenario: Verifying candidate ownership
- **WHEN** auditing mainnet promotion candidates
- **THEN** owner accountability is explicitly documented and attributed to authorized release maintainers.
