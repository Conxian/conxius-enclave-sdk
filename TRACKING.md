# `conxius-enclave-sdk` Repository Tracking

> **BETA / CONDITIONAL** - 2.x production support is capability- and artifact-specific.

This document provides a comprehensive overview of the repository status, including issues, pull requests, branches, and production-enablement evidence.

## Quick Links

| Document | Purpose |
|----------|---------|
| [PRODUCTION_READINESS.md](./PRODUCTION_READINESS.md) | **Release checklist** |
| [Production-enablement audit](./docs/audits/PRODUCTION_ENABLEMENT_AUDIT_2026-07-20.md) | Findings, gates, unknowns, and public-safe evidence |
| [Capability matrix](./docs/architecture/CAPABILITY_MATRIX.md) | API, implementation, integration, review, and support status |
| [Capability evidence JSON](./docs/architecture/capability-evidence.json) | Canonical machine-readable capability inventory and evidence chain |
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
| **Latest visible release/tag** | v2.0.16 (git tag); Cargo.toml 2.0.16 |
| **Cargo package metadata** | 2.0.16 (aligned with release tag) |
| **Production Status** | Beta / conditional; value-bearing enablement blocked by CON-1506 gates |
| **Test Coverage** | Historical source count; not an independent release gate |
| **Last Updated** | 2026-08-29 (Session 61) |

## Production-enablement backlog map

The current implementation and acceptance backlog spans GitHub issues across multiple priority levels. This map is a navigation aid only; it does not create, reopen, or duplicate issues.

| GitHub issue | Evidence gate | Priority | Status |
| --- | --- | --- | --- |
| [#267](https://github.com/Conxian/conxius-enclave-sdk/issues/267) | BitVM2 Groth16 SNARK verification | P0 | Implemented (Session 61) |
| [#242](https://github.com/Conxian/conxius-enclave-sdk/issues/242) | AWS Nitro attestation + KMS boundary | P0 | Blocked |
| [#241](https://github.com/Conxian/conxius-enclave-sdk/issues/241) | Android KeyMint/StrongBox + Play Integrity | P0 | Blocked |
| [#240](https://github.com/Conxian/conxius-enclave-sdk/issues/240) | Attestation roots, collateral, revocation, distributed replay | P0 | In Progress (items 1-5,7 code-complete; item 6 external-blocked on #202) |
| [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) | Independent security review and release acceptance | P0 | Blocked |
| [#271](https://github.com/Conxian/conxius-enclave-sdk/issues/271) | Lightning LDK payment execution | P1 | In Progress (route-finding + channel state machine done; live LND/LDK integration external) |
| [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200) | WASM secret boundary and runtime/platform evidence | P1 | In Progress (boundary hardened) |
| [#272](https://github.com/Conxian/conxius-enclave-sdk/issues/272) | BitVM SNARK proof validation | P2 | Closed |

### Resolved (Session 57)
**#196** (Bitcoin/Ethereum verification), **#198** (CCTP fail-closed), **#199** (reproducible toolchain), **#201** (telemetry, #210), **#197** (threshold settlement, mostly resolved except Fedimint), **#195** (hardware attestation, Phase 3 verifiers built)

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
