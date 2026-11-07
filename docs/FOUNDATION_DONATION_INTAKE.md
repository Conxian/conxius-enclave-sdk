# Foundation donation intake — `conxius-enclave-sdk`

**Status**: draft for owner review · **Date**: 2026-11-07 · **Tracking**: `conxius-enclave-sdk#701`, parent `conxian-business#1790`

## Why this project

`conxius-enclave-sdk` is the **adoption anchor** for the revenue-safe open-source program: it is MIT-licensed, already published on crates.io, and has **zero revenue conflict** — per `ADR-009 §4`, the SDK is free; the *managed* trust services (attestation, threshold signing, SLA) are the Enterprise tier.

Donating it to a neutral foundation buys the community, governance and credibility benefits **without** giving away any monetization surface.

## Target foundation

| Option | Fit | Note |
|---|---|---|
| **FINOS (Labs)** | Recommended first step | Apache-2.0 is the norm; MIT is acceptable for Labs intake. Free Associate tier; CLA via EasyCLA is optional for Labs. |
| **LF Decentralized Trust (LFDT)** | Alternative | Apache-2.0 recommended, other licences on exception basis. |
| **Community project** (e.g. an enclave/TEE or Bitcoin infra project) | Fallback | Lower overhead; less neutral governance. |

## Project proposal (FINOS Labs template)

### 1. Project name and description
`conxius-enclave-sdk` — a hardware-backed trust SDK (TEE attestation, threshold signing, capability gating) for high-integrity operations in Bitcoin/Stacks-adjacent systems.

### 2. Business problem
Hardware-backed key custody and attestation are hard to integrate correctly. The SDK provides a single, well-tested surface so integrators do not each re-implement TEE verification.

### 3. Proposed scope (in)
- The SDK crate (`conxius-enclave-sdk`), its interfaces, tests, and examples.
- Documentation, security policy, and the DCO contribution policy.

### 4. Explicitly out of scope
- Any hosted/managed trust service, SLA, billing or entitlement code (the Enterprise tier; remains company-owned).
- Conxian product/trademark assets beyond the project name (see §6).

### 5. Initial committers
- Conxian Labs maintainers (to be listed at submission time).

### 6. Trademark
Decision required: transfer the project mark to the foundation (true neutrality) **or** retain it with Conxian-Labs and grant a licence. FINOS/LF projects generally require the project mark to transfer.

### 7. Licence
MIT (OSI-approved). Already `license = "MIT"` in `Cargo.toml`.

### 8. Security policy
`SECURITY.md` present; vulnerabilities reported to `security@conxian-labs.com`.

### 9. Roadmap
See `docs/PHASE1_ISSUES_ROADMAP.md` and `CHANGELOG.md`.

## Checklist

- [x] MIT `LICENSE` confirmed
- [x] DCO contribution policy added (`CONTRIBUTING.md`)
- [ ] Lifecycle/stage badge added to `README.md` (after acceptance)
- [ ] Foundation proposal submitted
- [ ] Trademark decision (owner)
- [ ] `NOTICE`/attribution file (if required by the foundation)

## Related

- `.github-private` governance decisions `#103`, `#104`, `#105`; freeze notice `LICENCE_FREEZE_NOTICE_2026_11_07.md`.
- `conxian-business#1790` (program), `conxius-enclave-sdk#701` (this task), `ADR-008` (SDK licensing primitive), `ADR-009 §4`.

---
_This document was created by an AI agent (OpenHands) on behalf of the repository owner._
