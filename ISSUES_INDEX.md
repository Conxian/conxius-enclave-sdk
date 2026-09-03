# Conxius Enclave SDK Issues Index

> Auto-generated from GitHub. Last sync: 2026-08-31T09:51:15Z

> **Snapshot semantics:** Closed and merged entries are point-in-time GitHub outcomes from this sync. They do not establish implementation completeness, production readiness, security review, release acceptance, or support. See [PRODUCTION_READINESS.md](./PRODUCTION_READINESS.md).


## Summary
- **Total Issues**: 40
- **Open Issues**: 6
- **Closed Issues**: 34

## Open Issues
- [ ] [**#271**](https://github.com/Conxian/conxius-enclave-sdk/issues/271): P1: lightning — BOLT12 offer & BIP-353 DNS payment domain resolution added
  - Labels: enhancement
  - Assigned: unassigned

- [ ] [**#242**](https://github.com/Conxian/conxius-enclave-sdk/issues/242): [P0] Qualify AWS Nitro attestation and KMS secret-release boundary
  - Labels: enhancement, cryptography, priority-critical
  - Assigned: botshelomokoka

- [ ] [**#241**](https://github.com/Conxian/conxius-enclave-sdk/issues/241): [P0] Qualify Android KeyMint/StrongBox authorization and Play Integrity verification
  - Labels: enhancement, cryptography, priority-critical
  - Assigned: botshelomokoka

- [ ] [**#240**](https://github.com/Conxian/conxius-enclave-sdk/issues/240): [P0] Operationalize attestation roots, collateral, revocation, and distributed replay
  - Labels: enhancement, cryptography, priority-critical
  - Assigned: botshelomokoka

- [ ] [**#202**](https://github.com/Conxian/conxius-enclave-sdk/issues/202): [P0] Complete independent security review and release acceptance evidence
  - Labels: documentation, release, provenance, quality, priority-critical
  - Assigned: CharlieHelps

- [ ] [**#200**](https://github.com/Conxian/conxius-enclave-sdk/issues/200): [P1] Harden the WASM secret boundary and add runtime/platform evidence
  - Labels: enhancement, P1, wasm, architecture
  - Assigned: CharlieHelps


## Closed Issues
- [x] [**#320**](https://github.com/Conxian/conxius-enclave-sdk/issues/320): [P0] secp256k1 0.32.0-beta.2 is yanked — breaks downstream lockfile resolution
- [x] [**#283**](https://github.com/Conxian/conxius-enclave-sdk/issues/283): P2: Gate FROST DKG ceremonies behind enclave attestation verification
  - Labels: enhancement, P2, cryptography, frost, attestation

- [x] [**#274**](https://github.com/Conxian/conxius-enclave-sdk/issues/274): P2: Update AGENTS.md module count 46→57 and add PR #264 status
  - Labels: documentation

- [x] [**#273**](https://github.com/Conxian/conxius-enclave-sdk/issues/273): P2: covenant — implement covenant enforcement (114 lines structural)
  - Labels: enhancement

- [x] [**#272**](https://github.com/Conxian/conxius-enclave-sdk/issues/272): P2: bitvm — implement SNARK proof validation (132 lines structural)
  - Labels: enhancement

- [x] [**#270**](https://github.com/Conxian/conxius-enclave-sdk/issues/270): P1: dlc — implement CET signing with oracle attestation (161 lines structural)
  - Labels: enhancement

- [x] [**#269**](https://github.com/Conxian/conxius-enclave-sdk/issues/269): P1: cctp — implement CCTP attestation verification (1 gated op)
  - Labels: enhancement

- [x] [**#268**](https://github.com/Conxian/conxius-enclave-sdk/issues/268): P1: ark — implement Ark protocol signing (533 lines boundary-only)
  - Labels: enhancement

- [x] [**#267**](https://github.com/Conxian/conxius-enclave-sdk/issues/267): P0: bitvm2 — implement Groth16 SNARK verification (645 lines boundary-only)
  - Labels: enhancement

- [x] [**#266**](https://github.com/Conxian/conxius-enclave-sdk/issues/266): P0: FROST execution context — bridge opaque envelopes to raw ZF FROST bytes
  - Labels: enhancement

- [x] [**#265**](https://github.com/Conxian/conxius-enclave-sdk/issues/265): P0: Implement FROST DKG (part1/part2/part3) wrappers
  - Labels: enhancement

- [x] [**#260**](https://github.com/Conxian/conxius-enclave-sdk/issues/260): P1: Implement FROST-based cryptographic statechain operations
  - Labels: enhancement, P1, crypto, statechain

- [x] [**#256**](https://github.com/Conxian/conxius-enclave-sdk/issues/256): [ALIGNMENT] Update control_model_adapter.rs to mirror Core v0.3.0 48-chain taxonomy
  - Labels: enhancement, dependencies, protocol

- [x] [**#201**](https://github.com/Conxian/conxius-enclave-sdk/issues/201): [P1] Define telemetry privacy, monitoring, and public-safe operational runbooks
  - Labels: documentation, P1, quality, privacy

- [x] [**#199**](https://github.com/Conxian/conxius-enclave-sdk/issues/199): [P1] Make toolchain, dependencies, and release evidence reproducible and single-path
  - Labels: dependencies, release, P1, sbom, provenance, ci-cd

- [x] [**#198**](https://github.com/Conxian/conxius-enclave-sdk/issues/198): [P0] Make CCTP, account abstraction, and asset metadata fail closed
  - Labels: enhancement, cryptography, priority-critical

- [x] [**#197**](https://github.com/Conxian/conxius-enclave-sdk/issues/197): [P0] Replace or quarantine threshold and settlement protocol placeholders
  - Labels: enhancement, ark, bitvm2, fedimint, cryptography, frost-dkg, priority-critical

- [x] [**#196**](https://github.com/Conxian/conxius-enclave-sdk/issues/196): [P0] Implement canonical Bitcoin and Ethereum verification and derivation
  - Labels: enhancement, bitcoin, cryptography, priority-critical

- [x] [**#195**](https://github.com/Conxian/conxius-enclave-sdk/issues/195): [P0] Enforce hardware-backed signing and mandatory attestation for value-bearing operations
  - Labels: enhancement, cryptography, priority-critical

- [x] [**#194**](https://github.com/Conxian/conxius-enclave-sdk/issues/194): Architecture: align SDK policy types with Core control-model contracts
  - Labels: enhancement, architecture

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
