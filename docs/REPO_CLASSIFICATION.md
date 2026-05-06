# Repository Classification Portfolio (CON-634)

In alignment with the "Unified Vault SDK Pivot", the Conxian repository portfolio is classified into three strategic buckets.

## 1. Core (SDK-First GTM)
*Repositories essential to the primary company story: Hardware-secure Bitcoin application infrastructure.*

- **lib-conclave-sdk**: The canonical hardware security interface and signing orchestration core.
- **lib-conxian-core**: Home for shared protocol primitives, data schemas (ISO 20022), and core business registries.
- **conxian-labs-site**: The public interface for the "Native Bitcoin App" narrative and documentation.

## 2. Demote (Proof or Supporting Infrastructure)
*Repositories that serve as proof-of-concept, reference implementations, or downstream consumers.*

- **conxius-wallet**: **Demoted to Reference Application**. Used to demonstrate SDK capabilities but no longer the primary product focus.
- **conxian-gateway**: **Demoted to Supporting Infrastructure**. Orchestration middleware for liquidity rails and settlement verification.
- **conxian-nexus**: Supporting decentralized orchestration layer.

## 3. Separate (Legacy or Experimental)
*Repositories to be separated or archived to maintain narrative clarity.*

- **Conxian**: Legacy broad DeFi system (Stacks-based). Retain as technical debt/maintenance but separate from the primary SDK-first GTM.
- **Experimental/POC Repos**: Any repository not listed above should be treated as experimental or non-production.

## Summary Table

| Repository | Classification | Rationale |
| :--- | :--- | :--- |
| `lib-conclave-sdk` | **CORE** | The "Sellable Primitive" for secure signing. |
| `lib-conxian-core` | **CORE** | Shared standards and protocol schemas. |
| `conxius-wallet` | **DEMOTE** | UX validator for the SDK; avoid direct competition. |
| `conxian-gateway` | **DEMOTE** | Backend-for-Frontend (BFF) and settlement logic. |
| `Conxian` | **SEPARATE** | Legacy protocol sprawl; maintain for existing users. |
