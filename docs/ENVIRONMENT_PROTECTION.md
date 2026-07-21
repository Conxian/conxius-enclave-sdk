# Environment Protection Configuration

This document describes the required GitHub repository settings for environment protection on the `release` environment.

## Overview

The `release` environment is used only by `.github/workflows/release-strict.yml` to gate its single crates.io publication job. The job runs automatically for validated release tags and can be invoked manually for recovery. No other workflow is authorized to publish or create a release.

## Required Configuration

### GitHub Settings Path

```
Repository → Settings → Environments → release
```

### Protection Rules

The following protection rules should be configured for the `release` environment:

#### Required Reviewers

| Role | Requirement |
|------|-------------|
| Repository Admins | At least 1 approval required |
| CODEOWNERS | SDK Team approval recommended |

#### Deployment Branches

| Setting | Value |
|---------|-------|
| Allowed branches | `main` (or tag-triggered only) |
| Branch restriction | ✅ Enabled |

#### Wait Timer

| Setting | Value |
|---------|-------|
| Wait timer | 0 minutes (immediate after approval) |

## Setup Instructions

### 1. Navigate to Environment Settings

1. Go to repository **Settings**
2. Select **Environments** in the left sidebar
3. Click on **release** environment (or create if not exists)

### 2. Configure Protection Rules

```yaml
protection_rules:
  required_reviewers:
    - description: "SDK Release Manager"
      types: ["write"]
  deployment_branch_policy:
    name: "main"
    protected: true
  wait_timer: 0
```

### 3. Configure Environment Secrets

| Secret Name | Description | Required |
|-------------|-------------|----------|
| `CARGO_REGISTRY_TOKEN` | crates.io API token | ✅ Yes |

#### Creating crates.io Token

1. Go to [crates.io/settings/tokens](https://crates.io/settings/tokens)
2. Create a new token with `publish` scope
3. Add to GitHub: `Settings → Environments → release → Secrets → Add secret`

## Workflow Execution

After environment is configured:

1. **Tag creation** triggers automatic validation and the single publisher path:
   ```bash
   git tag -s v2.0.7 -m "Release v2.0.7"
   git push origin v2.0.7
   ```

2. **Automatic publish** requires:
   - Validation job and release-evidence job must pass
   - Required reviewers must approve (if configured)

3. **Manual recovery publish** requires:
   - The same release tag and version to be selected in Actions → Release Strict
   - Validation job and release-evidence job must pass
   - Required reviewers must approve (if configured)

## Verification

Verify environment protection is active:

```bash
gh api repos/{owner}/{repo}/environments
```

Expected response should include `release` environment with protection rules.

## Troubleshooting

### Publish Job Stuck

If the `publish-crates-io` job waits indefinitely:
1. Check environment protection rules are configured
2. Verify `CARGO_REGISTRY_TOKEN` secret exists in `release` environment
3. Ensure workflow is triggered against a release tag

### Token Expired

If crates.io publish fails with auth error:
1. Regenerate token at crates.io
2. Update `CARGO_REGISTRY_TOKEN` in environment secrets

---

*Document created by OpenHands AI agent - 2026-07-08*
