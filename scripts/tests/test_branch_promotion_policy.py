#!/usr/bin/env python3

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import branch_promotion_policy as policy  # noqa: E402


class BranchPromotionPolicyTests(unittest.TestCase):
    def test_bootstrap_exception_is_accepted(self) -> None:
        ctx = policy.PullRequestContext(
            number=971,
            base_ref="main",
            head_ref="promotion/con-1571-governance-bootstrap",
            base_sha="1111111111111111111111111111111111111111",
            head_sha="2222222222222222222222222222222222222222",
            base_repo="Conxian/conxius-enclave-sdk",
            head_repo="Conxian/conxius-enclave-sdk",
            body="",
            actor="admin",
        )
        errors = policy.validate_pull_request(ctx)
        self.assertEqual(errors, [])

    def test_dev_promotion_from_valid_work_branch(self) -> None:
        body = """PROMOTION:FEATURE->DEV
### Feature -> dev promotion checklist
- [x] Security assessed.
- [x] No secrets introduced.
"""
        ctx = policy.PullRequestContext(
            number=100,
            base_ref="dev",
            head_ref="feat/my-new-feature",
            base_sha="1111111111111111111111111111111111111111",
            head_sha="2222222222222222222222222222222222222222",
            base_repo="Conxian/conxius-enclave-sdk",
            head_repo="Conxian/conxius-enclave-sdk",
            body=body,
            actor="developer",
        )
        errors = policy.validate_pull_request(ctx)
        self.assertEqual(errors, [])

    def test_dev_promotion_from_invalid_branch_name_rejected(self) -> None:
        ctx = policy.PullRequestContext(
            number=101,
            base_ref="dev",
            head_ref="random-branch-name",
            base_sha="1111111111111111111111111111111111111111",
            head_sha="2222222222222222222222222222222222222222",
            base_repo="Conxian/conxius-enclave-sdk",
            head_repo="Conxian/conxius-enclave-sdk",
            body="PROMOTION:FEATURE->DEV",
            actor="developer",
        )
        errors = policy.validate_pull_request(ctx)
        self.assertTrue(any("must use feat/, feature/, fix/, docs/, chore/" in error for error in errors))

    def test_dev_promotion_from_main_branch_rejected(self) -> None:
        ctx = policy.PullRequestContext(
            number=102,
            base_ref="dev",
            head_ref="main",
            base_sha="1111111111111111111111111111111111111111",
            head_sha="2222222222222222222222222222222222222222",
            base_repo="Conxian/conxius-enclave-sdk",
            head_repo="Conxian/conxius-enclave-sdk",
            body="PROMOTION:FEATURE->DEV",
            actor="developer",
        )
        errors = policy.validate_pull_request(ctx)
        self.assertTrue(any("must come from an ordinary work branch" in error for error in errors))

    def test_dev_promotion_dependabot_exempt_from_checklist(self) -> None:
        ctx = policy.PullRequestContext(
            number=103,
            base_ref="dev",
            head_ref="dependabot/cargo/tokio-1.38.0",
            base_sha="1111111111111111111111111111111111111111",
            head_sha="2222222222222222222222222222222222222222",
            base_repo="Conxian/conxius-enclave-sdk",
            head_repo="Conxian/conxius-enclave-sdk",
            body="Bumps tokio",
            actor="dependabot[bot]",
        )
        errors = policy.validate_pull_request(ctx)
        self.assertEqual(errors, [])

    def test_staged_promotion_valid_candidate(self) -> None:
        source_sha = "2222222222222222222222222222222222222222"
        target_sha = "1111111111111111111111111111111111111111"
        body = f"""PROMOTION:DEV->STAGED
### Dev -> staged promotion checklist

- Promotion source SHA: `{source_sha}`
- Promotion target-base SHA: `{target_sha}`
- Promotion commit window: `{target_sha}..{source_sha}`

- [x] Wallet boundary checks verified.
- [x] Signer boundary checks verified.
- [x] Treasury boundary checks verified.
- [x] Deployment boundary checks verified.
"""
        ctx = policy.PullRequestContext(
            number=200,
            base_ref="staged",
            head_ref=f"promotion/dev-to-staged-{source_sha}",
            base_sha=target_sha,
            head_sha=source_sha,
            base_repo="Conxian/conxius-enclave-sdk",
            head_repo="Conxian/conxius-enclave-sdk",
            body=body,
            actor="github-actions[bot]",
        )
        errors = policy.validate_pull_request(ctx)
        self.assertEqual(errors, [])

    def test_staged_promotion_missing_boundary_keyword_rejected(self) -> None:
        source_sha = "2222222222222222222222222222222222222222"
        target_sha = "1111111111111111111111111111111111111111"
        body = f"""PROMOTION:DEV->STAGED
### Dev -> staged promotion checklist

- Promotion source SHA: `{source_sha}`
- Promotion target-base SHA: `{target_sha}`
- Promotion commit window: `{target_sha}..{source_sha}`

- [x] Wallet boundary checks verified.
- [x] Deployment boundary checks verified.
"""
        ctx = policy.PullRequestContext(
            number=201,
            base_ref="staged",
            head_ref=f"promotion/dev-to-staged-{source_sha}",
            base_sha=target_sha,
            head_sha=source_sha,
            base_repo="Conxian/conxius-enclave-sdk",
            head_repo="Conxian/conxius-enclave-sdk",
            body=body,
            actor="github-actions[bot]",
        )
        errors = policy.validate_pull_request(ctx)
        self.assertTrue(any("must record the signer check" in error for error in errors))

    def test_main_promotion_valid_candidate(self) -> None:
        source_sha = "2222222222222222222222222222222222222222"
        target_sha = "1111111111111111111111111111111111111111"
        window = f"{target_sha}..{source_sha}"
        body = f"""## Staged -> main promotion

### Exact promotion evidence

- Promotion source SHA: `{source_sha}`
- Promotion target-base SHA: `{target_sha}`
- Promotion commit window: `{window}`

<!-- PROMOTION:STAGED->MAIN -->
### Mainnet acceptance evidence pack

#### Promotion metadata
- Source SHA: `{source_sha}`
- Target Base SHA: `{target_sha}`
- Commit Window: `{window}`
- Specification: `openspec/specs/mainnet-acceptance-evidence-pack/spec.md`

#### Mainnet-only production scope
- Verified mainnet production boundary parameters and network isolation.
- Scope isolated to production mainnet execution with zero testnet/devnet fail-open fallbacks.

#### Contamination and residue proof
- Verified zero test credentials, mock keys, or staging residue in candidate commits.
- All secrets, tokens, and private keys checked and verified clean.

#### Successful production validation
- Automated CI test suite passed across unit, integration, and security checks.
- Capability evidence matrix verified with zero drift (`scripts/validate_capability_evidence.py`).

#### Release-readiness sign-off
- Security posture, threat model, and governance controls assessed and satisfied.
- CODEOWNERS review and policy checks satisfied for mainnet promotion.

#### Owner accountability
- Immutable candidate generated and verified by automated promotion workflow.
- Designated owner: Conxian Release Engineering (`@Conxian/release-team`).
"""
        ctx = policy.PullRequestContext(
            number=300,
            base_ref="main",
            head_ref=f"promotion/staged-to-main-{source_sha}",
            base_sha=target_sha,
            head_sha=source_sha,
            base_repo="Conxian/conxius-enclave-sdk",
            head_repo="Conxian/conxius-enclave-sdk",
            body=body,
            actor="github-actions[bot]",
        )
        errors = policy.validate_pull_request(ctx)
        self.assertEqual(errors, [])

    def test_main_promotion_placeholder_evidence_rejected(self) -> None:
        source_sha = "2222222222222222222222222222222222222222"
        target_sha = "1111111111111111111111111111111111111111"
        window = f"{target_sha}..{source_sha}"
        body = f"""## Staged -> main promotion

- Promotion source SHA: `{source_sha}`
- Promotion target-base SHA: `{target_sha}`
- Promotion commit window: `{window}`

<!-- PROMOTION:STAGED->MAIN -->
### Mainnet acceptance evidence pack

#### Promotion metadata
Complete all fields required by `openspec/specs/mainnet-acceptance-evidence-pack/spec.md`.

#### Mainnet-only production scope
Complete before review.

#### Contamination and residue proof
Complete before review.

#### Successful production validation
Complete before review.

#### Release-readiness sign-off
Complete before review.

#### Owner accountability
Complete before review.
"""
        ctx = policy.PullRequestContext(
            number=301,
            base_ref="main",
            head_ref=f"promotion/staged-to-main-{source_sha}",
            base_sha=target_sha,
            head_sha=source_sha,
            base_repo="Conxian/conxius-enclave-sdk",
            head_repo="Conxian/conxius-enclave-sdk",
            body=body,
            actor="github-actions[bot]",
        )
        errors = policy.validate_pull_request(ctx)
        self.assertTrue(any("must be completed (not placeholder) for" in error for error in errors))

    def test_main_promotion_direct_dev_prohibited(self) -> None:
        ctx = policy.PullRequestContext(
            number=302,
            base_ref="main",
            head_ref="dev",
            base_sha="1111111111111111111111111111111111111111",
            head_sha="2222222222222222222222222222222222222222",
            base_repo="Conxian/conxius-enclave-sdk",
            head_repo="Conxian/conxius-enclave-sdk",
            body="",
            actor="developer",
        )
        errors = policy.validate_pull_request(ctx)
        self.assertTrue(any("Direct dev -> main promotion is prohibited" in error for error in errors))

    def test_main_promotion_dependabot_prohibited(self) -> None:
        ctx = policy.PullRequestContext(
            number=303,
            base_ref="main",
            head_ref="dependabot/cargo/tokio-1.38.0",
            base_sha="1111111111111111111111111111111111111111",
            head_sha="2222222222222222222222222222222222222222",
            base_repo="Conxian/conxius-enclave-sdk",
            head_repo="Conxian/conxius-enclave-sdk",
            body="",
            actor="dependabot[bot]",
        )
        errors = policy.validate_pull_request(ctx)
        self.assertTrue(any("Dependabot PRs must target 'dev'" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
