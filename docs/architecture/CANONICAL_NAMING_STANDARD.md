# Canonical Naming Standard (CON-778)

This document defines the naming standard for Conxian public, operator, and BOS (Sovereign Autonomous Business) surfaces.

## 1. Governing Doctrine
- **Open-Core First**: Public names should reflect the open, non-custodial nature of the platform.
- **Universal Support**: Use "Adapters" or "Rails" to describe multi-chain capabilities.
- **Sovereign-First**: Emphasize hardware-backed security (TEE, StrongBox) as the "Sovereign" layer.

## 2. Repo Role Standard
| Repo | Canonical Description | Audience |
| --- | --- | --- |
| `lib-conclave-sdk` | Secure foundation for hardware-backed signing and attestation. | Developers |
| `conxian-gateway` | High-performance middleware for intent declaration and settlement routing. | Integrators |
| `conxian-nexus` | Decentralized state-layer and ZK-verifiable compute orchestrator. | Operators |
| `conxius-wallet` | Reference implementation for sovereign, non-custodial Bitcoin apps. | End-users |

## 3. Surface-Specific Naming
- **Public Product**: Use "Conxian" for the ecosystem and "Conclave" for the secure hardware layer.
- **Operator/Advanced**: Use "Citadel" for onsite server deployments and "Nexus Node" for state verifiers.
- **Internal Ops**: Use "BOS" (Sovereign Autonomous Business) for private orchestration and "Lane" for deployment environments.

## 4. Forbidden Terminology
- Avoid: "Custody", "Exchange", "Centralized", "Broker".
- Prefer: "Orchestration", "Settlement", "Non-Custodial", "Relay".
