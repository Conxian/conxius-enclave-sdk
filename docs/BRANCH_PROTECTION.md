# Branch Protection Policy (STRICT)

> Enforced strict branch protection for production-ready CI/CD
> Version: 1.0.0 | Last Updated: 2026-07-13

---

## Overview

This document defines the strict branch protection rules enforced across all branches in the Conclave SDK repository.

## Protected Branches

| Branch | Protection Level | Required Checks |
|--------|-----------------|-----------------|
| `main` | **STRICT** | All CI Strict checks |
| `master` | **STRICT** | All CI Strict checks |
| `release/*` | **STRICT** | Release Strict checks only |
| Feature branches | Standard | CI checks required |

---

## Required Status Checks

### For `main` and `master`

All of the following checks must pass before merging:

| Check | Workflow | Timeout |
|-------|----------|---------|
| `Rust Tests` | `ci-strict.yml` | 30 min |
| `Linting` | `ci-strict.yml` | 20 min |
| `WASM Build` | `ci-strict.yml` | 45 min |
| `Hygiene Check` | `ci-strict.yml` | 10 min |
| `Security Checks` | `ci-strict.yml` | 30 min |

### For Release Tags (`v*.*.*`)

| Check | Workflow | Timeout |
|-------|----------|---------|
| `Validate Release Metadata` | `release-strict.yml` | 45 min |
| `SBOM + Provenance` | `release-strict.yml` | 30 min |

---

## Enforcement Rules

### ✅ Enforced

1. **Up-to-date before merge**
   - Branches must be rebased on latest `main` before merging
   - No merge commits to `main` (squash/rebase only)

2. **Required reviewers**
   - Minimum 1 approval from CODEOWNERS
   - CODEOWNERS approval required for security-sensitive paths

3. **Status checks**
   - All required checks must pass
   - No bypasses allowed

4. **Linear history**
   - Squash and merge preferred
   - Merge commits not allowed on `main`

### 🚫 Not Enforced (By Design)

1. **Signed commits**
   - Currently not enforced via GitHub settings
   - See "Signed Commits Policy" below

---

## Signed Commits Policy

### Current State
Signed commits are **recommended but not enforced** at the GitHub branch protection level.

### How to Enforce (Manual Step)

To enforce signed commits, navigate to:
```
Repository Settings → Branches → Branch protection rules → Edit main
→ Check "Require signed commits"
```

### Commit Signing Setup

```bash
# Generate a new signing key (Ed25519 recommended)
ssh-keygen -t ed25519 -C "your_email@example.com" -f ~/.ssh/sign_ed25519

# Configure git to use signing key
git config --global commit.gpgsign true
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/sign_ed25519.pub

# Add signing key to GitHub
# Settings → SSH and GPG keys → New SSH key → "Signing Key"
```

### Why Not Enforced Yet
- Requires all contributors to set up signing keys
- May cause friction for new contributors
- Can be enabled after team-wide adoption

---

## Skip Conditions (REMOVED)

All workflows are configured with `concurrency.cancel-in-progress: false` to prevent accidental skips.

### Previous Skip Conditions (Now Disabled)
- ~~Path filters on docs-only changes~~ → Now runs full CI
- ~~Skip on certain file patterns~~ → Now runs all checks
- ~~Conditional `if:` statements~~ → Removed or made stricter

---

## Workflow Configuration

### CI Strict (`ci-strict.yml`)

```yaml
# Key configurations
concurrency:
  group: ci-strict-${{ github.ref }}
  cancel-in-progress: false  # NEVER cancel CI
```

### Release Strict (`release-strict.yml`)

```yaml
# Key configurations
concurrency:
  group: release-strict-${{ github.ref }}
  cancel-in-progress: false  # NEVER cancel releases
```

---

## Failure Handling

### On Check Failure

1. **Do NOT bypass checks**
2. **Fix the root cause**
3. **Push a new commit to retrigger CI**
4. **All checks must pass before merge**

### Emergency Procedures

For critical hotfixes with failing checks:
1. Create a dedicated `hotfix/*` branch
2. Get explicit approval from @botshelomokoka
3. Document the exception in the PR
4. Fix the check failure in a follow-up PR

---

## Monitoring

### Workflow Status
Monitor workflow runs at:
```
https://github.com/Conxian/conxius-enclave-sdk/actions
```

### Alerts
- Failed workflows trigger notifications to CODEOWNERS
- Dependency vulnerabilities trigger security alerts

---

## Review Schedule

This policy is reviewed:
- Monthly
- After any security incident
- After any CI/CD bypass

---

## Questions

Contact: @botshelomokoka or open a GitHub Discussion.

---

*Policy maintained by: SDK Team*
*Last reviewed: 2026-07-13*
