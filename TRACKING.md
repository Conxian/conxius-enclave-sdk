# Conclave SDK Repository Tracking

> **✅ PRODUCTION READY** - v2.0.7

This document provides a comprehensive overview of the Conclave SDK repository status, including issues, pull requests, and branches.

## Quick Links

| Document | Purpose |
|----------|---------|
| [PRODUCTION_READINESS.md](./PRODUCTION_READINESS.md) | **Release checklist** |
| [REPOSITORY_ANALYSIS.md](./REPOSITORY_ANALYSIS.md) | Capabilities, gaps, roadmap |
| [ISSUES_INDEX.md](./ISSUES_INDEX.md) | GitHub issues (synced) |
| [PRS_INDEX.md](./PRS_INDEX.md) | Pull requests (synced) |
| [BRANCHES_INDEX.md](./BRANCHES_INDEX.md) | Branch overview |
| [DEBT_INVENTORY.md](./DEBT_INVENTORY.md) | Technical debt tracking |
| [Gap Scorecard](./docs/architecture/GAP_SCORECARD.md) | Technical resolutions |

## Repository Information

| Property | Value |
|----------|-------|
| **Repository** | Conxian/conxius-enclave-sdk |
| **Default Branch** | main |
| **Language** | Rust |
| **Latest Tag** | v2.0.10 |
| **Current Version** | v2.0.10 |
| **Production Status** | ✅ Production Ready |
| **Test Coverage** | 121 tests (25 hardware attestation) |
| **Last Updated** | 2026-07-14 |

## Related Repositories

| Repository | Description |
|------------|-------------|
| conxius-platform | Main platform services |
| conxius-orbit | Orbit services |
| conxius-wallet | Wallet implementation |
| lib-conxian-core | Core library |
| conxian-gateway | Gateway services |

## Syncing Issues and PRs

To sync issues and PRs from GitHub to local tracking:

```bash
./scripts/sync_issues.sh
```

This will:
1. Fetch all issues and PRs from GitHub API
2. Create markdown files in `issues/` and `prs/` directories
3. Update `ISSUES_INDEX.md` and `PRS_INDEX.md`

## Issue Labels

Common labels used in this repository:

| Label | Description |
|-------|-------------|
| P1 | Critical priority |
| enhancement | New feature request |
| bug | Bug report |
| documentation | Documentation changes |
| dependencies | Dependency updates |
| ci-cd | CI/CD related |
| security | Security related |
| quality | Code quality |
| technical-debt | Technical debt items |

## Recent Activity

### Latest Commits on main

```
$(git log --oneline -5 origin/main)
```

### Latest Merged PRs

See [PRS_INDEX.md](./PRS_INDEX.md) for the complete list.

## Local Development

### Setting Up

```bash
# Clone and setup
git clone https://github.com/Conxian/conxius-enclave-sdk.git
cd conxius-enclave-sdk

# Install dependencies
cargo build

# Run tests
cargo test
```

### Creating a New Branch

```bash
git checkout -b feature/your-feature-name
git push -u origin feature/your-feature-name
```

## Workflow

1. Create a branch from `main`
2. Make changes and commit
3. Push and create a PR
4. Address review feedback
5. Squash and merge when approved

## Support

- **Documentation**: See `docs/` directory
- **Issues**: https://github.com/Conxian/conxius-enclave-sdk/issues
- **Security**: See SECURITY.md
