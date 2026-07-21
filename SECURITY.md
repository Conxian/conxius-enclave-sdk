# Security Policy for `conxius-enclave-sdk`

## Security status

The 2.x line is **Beta / conditional**. The repository contains security-sensitive APIs, but the production-enablement audit found simulated signers, incomplete attestation enforcement, placeholder protocol behavior, and missing independent/release evidence. Do not use this status page as approval for value-bearing production signing or settlement.

- [Production-enablement audit](./docs/audits/PRODUCTION_ENABLEMENT_AUDIT_2026-07-20.md)
- [Capability and evidence matrix](./docs/architecture/CAPABILITY_MATRIX.md)
- [Public operations and incident runbook](./docs/operations/PUBLIC_OPERATIONS_RUNBOOK.md)

## Supported Versions

Only the latest maintained SDK release lines are supported.

| Version line | Support boundary |
| ----------- | ---------------- |
| 2.x | Conditional support only for capabilities and artifacts that satisfy the matrix; no unqualified production support |
| 0.x | Not a maintained line under this policy |

## Reporting a Vulnerability

Do **not** disclose vulnerabilities publicly.

Report privately using one of these channels:

1. GitHub private vulnerability reporting for this repository.
2. Email [security@conxian-labs.com](mailto:security@conxian-labs.com).

## Security principles

1. Private keys must not leave the intended trust boundary.
2. Value-bearing operations must require appropriate, fully verified attestation.
3. Simulated, mock, software-only, and placeholder drivers must not be treated as production-grade security controls.
4. Missing evidence must fail closed rather than being interpreted as support.
5. Public documentation must remain ZSE-safe: do not publish credentials, private endpoints, privileged identifiers, custody procedures, key-recovery details, or incident secrets.
