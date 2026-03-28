# Security Policy

## Supported Versions

Only the latest version of the SDK is supported for security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability, please report it via one of the following:

- **Email**: security@conxian.com
- **Linear**: If you have access to the Conxian-Labs workspace, create an issue with the "Security" label.

Please do not disclose vulnerabilities publicly until we have had a chance to remediate them.

## Core Security Principles

1. **Zero Secret Egress**: Private keys must never leave the hardware enclave.
2. **Hardware Attestation**: High-value operations require cryptographic proof of device integrity.
3. **Sovereign Handshake**: Non-custodial signing is mandatory for all cross-chain operations.
