# Security Policy

## Supported Versions

Only the latest version of the SDK is supported for security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability, please report it via one of the following:

- **Email**: security@conxian-labs.com
- **Linear**: If you have access to the Conxian-Labs workspace, create an issue with the "Security" label.

Please do not disclose vulnerabilities publicly until we have had a chance to remediate them.

## Core Security Principles

1. **Zero Secret Egress**: Private keys must never leave the hardware enclave.
2. **Hardware Attestation**: High-value operations require cryptographic proof of device integrity.
3. **Sovereign Handshake**: Non-custodial signing is mandatory for all cross-chain operations.

## Simulation Policy

The default SDK enclave drivers (`CoreEnclaveManager` and `CloudEnclave`) report `AttestationLevel::Software`. High-value operations requiring `AttestationLevel::StrongBox` or `AttestationLevel::CloudTEE` will fail by default when using these drivers. This ensures that simulated environments cannot be used to bypass production hardware security requirements.
