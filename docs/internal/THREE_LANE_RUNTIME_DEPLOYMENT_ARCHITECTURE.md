# Three-Lane Runtime Deployment Architecture

This document defines the canonical runtime lane discipline for the Conxian ecosystem, ensuring clear boundaries between Managed, Enterprise, and Operator environments.

## 1. Lane Definitions

| Lane | Target Audience | Key Characteristics | Governance |
| -- | -- | -- | -- |
| **Managed** | Retail / High-Velocity | Conxian-Labs managed infrastructure. Fastest release cycle. | High-Integrity / Automated |
| **Enterprise** | Institutional Partners | Self-hosted or dedicated infrastructure. Stable release cycles. | Joint-Governance |
| **Operator** | Protocol Validators | Decentralized node operators. Long-term stability. | Decentralized Consensus |

## 2. Priority & Routing

Lane priority is strictly enforced: **Managed -> Enterprise -> Operator (defer)**.

### Managed Lane
The testing ground for all new features. High-frequency updates with automated rollback triggers.

### Enterprise Lane
Requires explicit sign-off gates. Focuses on settlement finality and auditability.

### Operator Lane
Deferred until the protocol reaches decentralized maturity.

## 3. Deployment Flow

1. **Source**: `main` branch on protected repositories.
2. **Attestation**: Hardware-backed integrity check on all build artifacts.
3. **Routing**: Gateway routes traffic based on partner ID and lane policy.
