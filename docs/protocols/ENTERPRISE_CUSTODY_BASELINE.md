# Enterprise Custody Baseline

Standardized requirements for institutional custody within the Conxian Sovereign Autonomous Business (SAB) framework.

## 1. Core Requirements

- **Zero Secret Egress (ZSE)**: Private keys MUST never leave the secure hardware enclave.
- **Hardware Attestation**: Every signing operation MUST be accompanied by a verifiable device integrity report.
- **Role-Based Access Control (RBAC)**: Multi-signature orchestration for high-value transfers.

## 2. Settlement Validation

Institutional settlement requires P2 support tier or higher. Validation pilots last 45 days by default to account for ERP integration and egress auditing.

## 3. Compliance & Audit

All enterprise transactions must be recorded in the Merkle Mountain Range (MMR) for immutable audit trails.
