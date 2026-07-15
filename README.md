# Conclave SDK

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](SECURITY.md)
[![Version](https://img.shields.io/badge/version-2.0.10-blue.svg)](CHANGELOG.md)
[![Status](https://img.shields.io/badge/status-production%20ready-green.svg)](PRODUCTION_READINESS.md)

**Hardware-backed security primitives for the broader Conxian ecosystem.**

The Conclave SDK provides a high-integrity root of trust for security-sensitive wallet, signing, attestation, and policy flows.

## Status

**✅ Production Ready** - The SDK is at **v2.0.10** with all P1 issues resolved. See [PRODUCTION_READINESS.md](./PRODUCTION_READINESS.md) for the full readiness checklist.

## Quick Start

```bash
# Add to your Cargo.toml
[dependencies]
conxius-enclave-sdk = "2.0.10"

# Or from git
conxius-enclave-sdk = { git = "https://github.com/Conxian/conxius-enclave-sdk", tag = "v2.0.10" }
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
| Hardware Attestation | ✅ | TEE, StrongBox, Secure Enclave support |
| FROST DKG | ✅ v2.0.10 | Distributed key generation |
| Fedimint | ✅ v2.0.7 | Federation adapter with blinding |
| Ark | ✅ v2.0.7 | vTXO tree construction |
| BitVM2 | ✅ | Optimistic challenge-response |
| MuSig2 | ✅ | Multi-signature aggregation |
| 30+ Chains | ✅ | Multi-chain asset support |
| WASM | ✅ | WebAssembly bindings |

## Development

```bash
# Build
cargo build

# Test
cargo test

# WASM build
wasm-pack build

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
