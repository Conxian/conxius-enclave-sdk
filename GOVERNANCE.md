# Governance — lib-conclave-sdk

This document defines the business role, ownership, and operational standards for the Conclave SDK.

## Role

The Conclave SDK (`lib-conclave-sdk`) is the canonical high-integrity integration surface for hardware-backed operations in the Conxian ecosystem.

## Ownership

- **Primary Owner**: [Conxian](https://github.com/Conxian)
- **Support Channel**:
  - Technical issues and feature requests should be tracked via [GitHub Issues](https://github.com/Conxian/conxius-enclave-sdk/issues).
  - Security vulnerabilities MUST be reported to `security@conxian-labs.com` as per [SECURITY.md](SECURITY.md).
- **Service Level**: The SDK is currently in **Beta** (`0.x`). Support is provided on a best-effort basis by the core engineering team.

## Release Discipline

- Semantic Versioning (SemVer) is required.
- All releases must update [CHANGELOG.md](CHANGELOG.md).
- Production-significant changes require CODEOWNERS review.
