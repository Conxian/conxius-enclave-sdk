# conxius-enclave-sdk

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](SECURITY.md)
[![Version](https://img.shields.io/badge/version-2.x-blue.svg)](CHANGELOG.md)
[![Status](https://img.shields.io/badge/status-beta%20%2F%20conditional-yellow.svg)](PRODUCTION_READINESS.md)

**Hardware-backed security primitives for the broader Conxian ecosystem.**

The SDK provides a high-integrity root of trust for security-sensitive wallet, signing, attestation, and policy flows.

## Status

**Beta / conditional.** The 2.x line exposes the interfaces needed for development and integration work, but the [2026-07-20 production-enablement audit](./docs/audits/PRODUCTION_ENABLEMENT_AUDIT_2026-07-20.md) found P0 evidence gaps. Do **not** enable value-bearing production signing or settlement from this tree.

The latest visible GitHub release/tag is `v2.0.11` as of 2026-07-20. `Cargo.toml` declares package version `2.0.12`, but package metadata is not release or production-support evidence. Review the [capability matrix](./docs/architecture/CAPABILITY_MATRIX.md) for the boundary of each surface.

## Quick Start

```bash
# Pin a reviewed 2.x artifact only after checking its release evidence.
[dependencies]
conxius-enclave-sdk = { git = "https://github.com/Conxian/conxius-enclave-sdk", tag = "v2.0.11" }
```

## Purpose

Provide reusable enclave-facing primitives for signing, attestation, device trust, and hardened key handling across Conxian-aligned applications and services.

## Scope

This repository focuses on:

- enclave and keystore abstractions
- attestation and trust reporting interfaces
- signing primitives and key lifecycle controls
- reusable SDK surfaces for higher-level ecosystem components

This repository does **not** act as a complete wallet, DAO-facing governance surface, or business operating system.

## Relationship to the Conxian stack

- `Conxian` is the protocol and DAO-facing layer.
- `conxius-wallet` is the sovereign wallet and reference client.
- `conxian-gateway` and `conxian-nexus` provide middleware and service-side integration surfaces.
- `lib-conxian-core` provides broader shared primitives across the stack.

## Key Features

| Feature | Status | Description |
|---------|--------|-------------|
| Hardware Attestation | API present; simulated evidence | Vendor-backed production support is not established |
| FROST DKG | Typed boundary; quarantined | RFC 9591 DKG, nonce, ciphersuite, attestation, and signing gates remain open |
| Fedimint | Typed secret-safe boundary; quarantined | Federation, mint, note, TBS/DLEQ, and threshold operations remain unsupported |
| Ark / BitVM2 | Typed foundation; quarantined | Key derivation, recovery, tree/transaction construction, challenge, and settlement remain unsupported |
| CCTP / account abstraction | API present; placeholder behavior | Production protocol integrations are not established |
| Ethereum / Taproot / BIP-322 | API present; correctness gates open | Canonical hashing and cryptographic verification require remediation |
| 30+ Chains | Registry surface present | Address provenance and integration evidence are incomplete |
| WASM | Boundary hardened; runtime support unsupported | Private-key export and software defaults are removed; browser/Node/bundler/worker and provider evidence remain open |

## Development

```bash
# Build
cargo build

# Test
cargo test

# WASM build
wasm-pack build

# WASM support boundary
# See docs/architecture/WASM_SUPPORT_MATRIX.md and
# docs/migrations/wasm-key-boundary.md before integrating signing or recovery.

# Format check
cargo fmt --all -- --check

# Lint
cargo clippy -- -D warnings
```

## Release Discipline

- Use Semantic Versioning for formal releases.
- Publish GitHub releases with annotated tags in the form `vX.Y.Z`.
- Record release-facing changes in [CHANGELOG.md](./CHANGELOG.md).
- Follow the workflow in [RELEASING.md](./RELEASING.md).
- See [PRODUCTION_READINESS.md](./PRODUCTION_READINESS.md) for release checklist.

## Documentation

- [PRODUCTION_READINESS.md](./PRODUCTION_READINESS.md) - Release checklist
- [Production-enablement audit](./docs/audits/PRODUCTION_ENABLEMENT_AUDIT_2026-07-20.md) - Findings, gates, unknowns, and public-safe evidence
- [Capability matrix](./docs/architecture/CAPABILITY_MATRIX.md) - API/evidence/support status by capability
- [Protocol implementation roadmap](./docs/architecture/PROTOCOL_IMPLEMENTATION_ROADMAP.md) - requirements, boundaries, tests, CI/artifact gates, and non-production milestones
- [WASM support matrix](./docs/architecture/WASM_SUPPORT_MATRIX.md) - Runtime/provider boundaries and evidence requirements
- [WASM key-boundary migration](./docs/migrations/wasm-key-boundary.md) - Breaking API changes and migration guidance
- [FROST Treasury Integration Guide](./docs/guides/FROST_TREASURY_INTEGRATION.md) - Design/runbook; production implementation is not yet available
- [TRACKING.md](./TRACKING.md) - Issue and PR tracking
- [REPOSITORY_ANALYSIS.md](./REPOSITORY_ANALYSIS.md) - Capabilities and gaps
- [docs/architecture/](docs/architecture/) - Architecture documentation

## Policies

- [CHANGELOG.md](./CHANGELOG.md)
- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [SECURITY.md](./SECURITY.md)
- [CODEOWNERS](./CODEOWNERS)
- [RELEASING.md](./RELEASING.md)
- [REPO_OWNERSHIP.md](./REPO_OWNERSHIP.md)
- [DEBT_INVENTORY.md](./DEBT_INVENTORY.md)
- [LICENSE](./LICENSE)

## Support

- Support: [support@conxian-labs.com](mailto:support@conxian-labs.com)
- Security: [security@conxian-labs.com](mailto:security@conxian-labs.com)

## License

MIT
