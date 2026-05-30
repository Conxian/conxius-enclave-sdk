# Conxius Enclave SDK

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](SECURITY.md)

Hardware-security-oriented SDK components for building Conxian applications and integrations.

## Purpose

Provide SDK interfaces for hardware-backed signing, attestation, policy enforcement, and secure transaction coordination.

## Status

Beta / active development.

## Scope

This repository contains developer-facing SDK logic and bindings. It should not contain business administration, private partner records, or unrelated application UI logic.

## Governance relation

This repository is maintained by Conxian Labs as reusable infrastructure for the public Conxian ecosystem.

## Key security note

The default software enclave drivers are for development use only. Production use requires hardware-bound drivers and appropriate attestation levels.

## Development

```bash
cargo build
cargo test
wasm-pack build
```

## Support

- Support: [support@conxian-labs.com](mailto:support@conxian-labs.com)
- Security: [security@conxian-labs.com](mailto:security@conxian-labs.com)

## License

MIT
