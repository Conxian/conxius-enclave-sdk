# `conxius-enclave-sdk` Repository Tracking

> **STABLE (CONDITIONAL)** - 2.x production status is capability- and artifact-specific per the 2026-09-29 redo audit.
>
> **Alignment note (2026-11-21):** this page was reconciled with `README.md`, `Cargo.toml` and the live
> GitHub tracker. The repository version is **2.1.0**; the earlier 2.0.17 values were stale. Volatile
> counts live in [ISSUES_INDEX.md](./ISSUES_INDEX.md), [PRS_INDEX.md](./PRS_INDEX.md) and
> [BRANCHES_INDEX.md](./BRANCHES_INDEX.md), which are dated snapshots - GitHub remains authoritative.

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
| **Latest visible release/tag** | v2.1.0 (git tag); Cargo.toml 2.1.0 |
| **Cargo package metadata** | 2.1.0 (aligned with release tag) |
| **Production Status** | Stable (conditional); value-bearing enablement blocked by CON-1506 gates |
| **Test Coverage** | Historical source count; not an independent release gate |
| **Last Updated** | 2026-11-21 (tracker alignment) |

## Production-enablement backlog map

The current implementation and acceptance backlog spans GitHub issues across multiple priority levels. This map is a navigation aid only; it does not create, reopen, or duplicate issues.

| GitHub issue | Evidence gate | Priority | Status |
| --- | --- | --- | --- |
| [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) | Independent security review and release acceptance | P0 | Open - no independent acceptance evidence |
| [#240](https://github.com/Conxian/conxius-enclave-sdk/issues/240) | Attestation roots, collateral, revocation, distributed replay | P0 | Open - service-owned transactional backend not qualified |
| [#241](https://github.com/Conxian/conxius-enclave-sdk/issues/241) | Android KeyMint/StrongBox + Play Integrity | P0 | Open - real-device evidence outstanding |
| [#509](https://github.com/Conxian/conxius-enclave-sdk/issues/509) | Turnkey KMaaS: pre-attested TEE compute + threshold signing | P1 | Open - research/qualification |
| [#559](https://github.com/Conxian/conxius-enclave-sdk/issues/559) | Decentralized signing with community-verifiable evidence | P0 | Open - ceremony participation outstanding |
| [#583](https://github.com/Conxian/conxius-enclave-sdk/issues/583) | Live hardware provider collateral and StrongBox offline boundaries | P0 | Open - provider collateral not qualified |
| [#676](https://github.com/Conxian/conxius-enclave-sdk/issues/676) | Adopt org-wide business operations evidence contract | P1 | Open |
| [#701](https://github.com/Conxian/conxius-enclave-sdk/issues/701) | Foundation donation package (FINOS/LFDT anchor) | P4 | Open |
| [#720](https://github.com/Conxian/conxius-enclave-sdk/issues/720) | Open call: independent co-signer for the 2-of-3 FROST release key | - | Open - participation call |

Closed since the previous snapshot: #200, #242, #267, #271, #272, #320 (see [ISSUES_INDEX.md](./ISSUES_INDEX.md)).

### Resolved (Session 57)
**#196** (Bitcoin/Ethereum verification), **#198** (CCTP fail-closed), **#199** (reproducible toolchain), **#201** (telemetry, #210), **#197** (threshold settlement, mostly resolved except Fedimint), **#195** (hardware attestation, Phase 3 verifiers built)

## Related Repositories

| Repository | Description |
|------------|-------------|
| conxius-platform | Control plane and orchestration |
| conxius-wallet | Wallet implementation |
| lib-conxian-core | Shared protocol primitives |
| conxian-gateway | Gateway services |
| conxian-nexus | Observation and proof layer |
| conxian_market | Market SDK and settlement calculations |
| conxian-business | BOS governance and portfolio wiring |

`conxius-orbit` is retired (deleted) and is no longer part of the ecosystem map; see the org
[repository taxonomy](https://github.com/Conxian/.github/blob/main/repository-taxonomy.md).

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

Read the live history with `git log --oneline -5 origin/main`; this page does not pin commit SHAs.

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

---

## Session 86 Tracking Update (2026-10-27)
- Expanded Knowledge Base (`RESEARCH_LOG.md`) with production readiness strategy for open issues (#200, #202, #240, #241, #242, #271), T1-T4 decentralized systems interoperability matrix, and Conxian Nexus business opportunities (Turnkey KMaaS, WASM Compute, Autonomous SLA 80/10/10 yield splitting, x402 payment escrows).
- Created `docs/architecture/DECENTRALIZED_SYSTEMS_BUSINESS_OPPORTUNITIES.md` and updated `PRODUCTION_READINESS.md`.
- Regenerated `CAPABILITY_MATRIX.md` via capability script; verified zero evidence drift.
- **#621**: Expand research on production readiness and business opportunities with decentralized systems (Open / Assigned: CharlieHelps)
