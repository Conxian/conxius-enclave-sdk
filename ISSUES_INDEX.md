# Conclave SDK Issues Index

> Auto-generated from GitHub. Last sync: 2026-07-21T03:52:30Z
> **Manual update:** 2026-08-05 (Session 53 sprint review)

> **Snapshot semantics:** Closed and merged entries are point-in-time GitHub outcomes from this sync. They do not establish implementation completeness, production readiness, security review, release acceptance, or support. See [PRODUCTION_READINESS.md](./PRODUCTION_READINESS.md).


## Summary
- **Total Issues**: 23
- **Open Issues**: 6
- **Closed Issues**: 14
- **Resolved in Code (pending GitHub update)**: 3 (#196, #198, #199)

## Open Issues (verified against code 2026-08-05)

- [ ] [**#202**](https://github.com/Conxian/conxius-enclave-sdk/issues/202): [P0] Complete independent security review and release acceptance evidence
  - Labels: documentation, release, provenance, quality, priority-critical
  - Status: **BLOCKED** — depends on #195, #200, #197 resolution + external reviewer

- [ ] [**#201**](https://github.com/Conxian/conxius-enclave-sdk/issues/201): [P1] Define telemetry privacy, monitoring, and public-safe operational runbooks
  - Labels: documentation, P1, quality, privacy
  - Status: **CODE COMPLETE** — telemetry hardened in #210; runbooks still needed

- [ ] [**#200**](https://github.com/Conxian/conxius-enclave-sdk/issues/200): [P1] Harden the WASM secret boundary and add runtime/platform evidence
  - Labels: enhancement, P1, wasm, architecture
  - Status: **IN PROGRESS** — #211 closed key/provider boundary; runtime evidence workflows exist (wasm-runtime.yml, wasm-runtime-evidence.yml)

- [ ] [**#197**](https://github.com/Conxian/conxius-enclave-sdk/issues/197): [P0] Replace or quarantine threshold and settlement protocol placeholders
  - Labels: enhancement, ark, bitvm2, fedimint, cryptography, frost-dkg, priority-critical
  - Status: **MOSTLY RESOLVED** — FROST real crypto (#264), FrostSigningContext (#275), ROAST coordinator (Session 53), Ark VTXO (#278), DLC (#279), CCTP (#277), Covenant (#276), BitVM2 Groth16 (Session 53). Fedimint remains structural-only.

- [ ] [**#195**](https://github.com/Conxian/conxius-enclave-sdk/issues/195): [P0] Enforce hardware-backed signing and mandatory attestation for value-bearing operations
  - Labels: enhancement, cryptography, priority-critical
  - Status: **IN PROGRESS** — enclave trust contracts (#249), Nitro (#248), Android (#243), replay (#247), proof policy (#244). Real provider verifier still needed.

- [ ] [**#194**](https://github.com/Conxian/conxius-enclave-sdk/issues/194): Architecture: align SDK policy types with Core control-model contracts
  - Labels: enhancement, architecture
  - Status: **OPEN** — control_model_adapter exists but full alignment pending

## Resolved in Code (close on GitHub)

- [x] [**#199**](https://github.com/Conxian/conxius-enclave-sdk/issues/199): [P1] Make toolchain, dependencies, and release evidence reproducible
  - **Resolved by**: PR #213 (release), rust-toolchain.toml, CI workflows pinned, `--locked` everywhere

- [x] [**#198**](https://github.com/Conxian/conxius-enclave-sdk/issues/198): [P0] Make CCTP, account abstraction, and asset metadata fail closed
  - **Resolved by**: PR #212 (fail-closed adapters), PR #277 (ECDSA attestation for CCTP)

- [x] [**#196**](https://github.com/Conxian/conxius-enclave-sdk/issues/196): [P0] Implement canonical Bitcoin and Ethereum verification and derivation
  - **Resolved by**: PR #208 (canonical Bitcoin/Ethereum validation), PR #276 (BIP-119/BIP-118), PR #279 (DLC oracle attestation)

## Closed Issues
- [x] [**#191**](https://github.com/Conxian/conxius-enclave-sdk/issues/191): production enablement
- [x] [**#180**](https://github.com/Conxian/conxius-enclave-sdk/issues/180): [SDK-001] FROST DKG Treasury Integration Guide
  - Labels: frost-dkg, treasury, priority-critical

- [x] [**#179**](https://github.com/Conxian/conxius-enclave-sdk/issues/179): [BIP-110] Add bip110_compliant feature flag
  - Labels: enhancement, bitcoin, bip110

- [x] [**#176**](https://github.com/Conxian/conxius-enclave-sdk/issues/176): Fix: Crate version 2.0.11 already published on crates.io
  - Labels: bug, release

- [x] [**#175**](https://github.com/Conxian/conxius-enclave-sdk/issues/175): [P3] ZKML Module Enhancement and Modernization
  - Labels: enhancement, bitcoin, P3, zkml, research, in-progress

- [x] [**#174**](https://github.com/Conxian/conxius-enclave-sdk/issues/174): [P2] Fedimint Cryptographic Blinding Integration
  - Labels: enhancement, P2, fedimint, cryptography, privacy

- [x] [**#173**](https://github.com/Conxian/conxius-enclave-sdk/issues/173): [P1] Ark BitVM2 Challenge Orchestration Integration
  - Labels: enhancement, P1, bitcoin, ark, bitvm2, implemented

- [x] [**#172**](https://github.com/Conxian/conxius-enclave-sdk/issues/172): [P2] WASM Bindings Completeness Audit - 12+ modules missing
  - Labels: enhancement, P2, wasm, architecture, in-progress

- [x] [**#169**](https://github.com/Conxian/conxius-enclave-sdk/issues/169): Fix: Invalid Handlebars syntax in attest-build-provenance subject parameter
  - Labels: bug, github_actions, ci-cd

- [x] [**#154**](https://github.com/Conxian/conxius-enclave-sdk/issues/154): [P1] Publish First Stable Release
  - Labels: documentation, enhancement, release, P1

- [x] [**#146**](https://github.com/Conxian/conxius-enclave-sdk/issues/146): Reduce technical debt and enforce code-quality hardening for the enclave SDK
  - Labels: technical-debt, quality

- [x] [**#145**](https://github.com/Conxian/conxius-enclave-sdk/issues/145): Enforce strict CI/CD baseline for enclave SDK build, verification, and release
  - Labels: sbom, provenance, ci-cd

- [x] [**#104**](https://github.com/Conxian/conxius-enclave-sdk/issues/104): Normalize default branch to main and align branch policy
- [x] [**#92**](https://github.com/Conxian/conxius-enclave-sdk/issues/92): Investigate repo-wide CI baseline failures affecting docs-only PRs
