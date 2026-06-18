# Conclave SDK

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](SECURITY.md)

**Hardware-backed security primitives for the broader Conxian ecosystem.**

The Conclave SDK provides a high-integrity root of trust for security-sensitive wallet, signing, attestation, and policy flows.

## Purpose

Provide reusable enclave-facing primitives for signing, attestation, device trust, and hardened key handling across Conxian-aligned applications and services.

## Status

**Active development.** This repository contains both security-oriented implementation work and software-backed development paths used for local integration and interface validation.

There are currently **no published GitHub releases** for this repository. Until the first formal release is published, operators and integrators should treat the codebase as evolving implementation work rather than a stable production SDK.

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

## Release discipline

- Use Semantic Versioning for formal releases.
- Publish GitHub releases with annotated tags in the form `vX.Y.Z`.
- Record release-facing changes in [CHANGELOG.md](./CHANGELOG.md).
- Follow the workflow in [RELEASING.md](./RELEASING.md).
- Keep README status language aligned with the latest release and actual driver maturity.

## Development

```bash
cargo build
cargo test
wasm-pack build
```

## Policies

- [CHANGELOG.md](./CHANGELOG.md)
- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [SECURITY.md](./SECURITY.md)
- [CODEOWNERS](./CODEOWNERS)
- [RELEASING.md](./RELEASING.md)
- [REPO_OWNERSHIP.md](./REPO_OWNERSHIP.md)
- [LICENSE](./LICENSE)

## Support

- Support: [support@conxian-labs.com](mailto:support@conxian-labs.com)
- Security: [security@conxian-labs.com](mailto:security@conxian-labs.com)

## License

MIT
