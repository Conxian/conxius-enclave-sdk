# SDK Boundary Contract (CON-628)

This document defines the module boundaries and interface contracts for the Conclave SDK, ensuring a clean separation between core security logic and application-level (Wallet/Gateway) concerns.

For the cycle-safe shared control-model boundary with `lib-conxian-core`, see
[Core Control-Model Adapter Boundary](./CONTROL_MODEL_ADAPTER_BOUNDARY.md).

## Phase A trust and replay boundary

The provider-neutral trust contract lives in `src/enclave/trust.rs` and is
separate from provider adapters and the existing proof modules. Untrusted
`TrustAnchor`, `TrustBundle`, `CollateralSnapshot`, and `AttestationEvidence`
transport uses bounded/versioned fields and deterministic SHA-256 encodings;
JSON is never a signed or digest encoding. The public aggregates are
`Serialize`-only: bounded JSON helpers reject the 256 KiB outer transport limit
before private `deny_unknown_fields` wire parsing. Exact production policy and
verifier identity are checked before normalization, while one fail-closed
signer-anchor check enforces provider/profile/algorithm, status, inclusive
validity, revision/rollback-floor, and configured constraint requirements for
bundle, collateral, and evidence signatures. Only normalized,
privacy-minimized `SingleMechanismAttestationResult` data may cross into the
single-mechanism policy/replay boundary. It carries an explicit
`TrustScope::SingleMechanism`; exact production policy and verifier binding are
contextual requirements, not proof that one mechanism satisfies the complete
six-factor policy. Only `ProofVerifierRegistry::verify_bundle` (or an equally
explicit composed proof type) can produce complete all-required authorization.
The provider traits, verified material, and normalization factories are
crate-private test seams in Phase A, so external provider adapters are not yet
enabled.

`src/enclave/durable_replay.rs` defines a backend-neutral synchronous
`consume_once` contract. `DurableReplayAuthorizer` accepts only a
`SingleMechanismAttestationResult` and returns only
`SingleMechanismReplayAuthorization`; it does not replace the process-local
`ReplayGuard`, does not implement a durable backend, and does not call
`EnclaveManager`, `RailProxy`, signing, or settlement. The wrapper uses a
trusted internal clock with process-global/per-authorizer monotonic high-water
checks and authorizes only a consumed or backend-confirmed same-request
idempotent outcome. A private/test-only clock seam is used for deterministic
rollback and expiry regressions. Production trust authentication, provider
verification, and durable replay are unavailable until provider/runtime,
deployment, independent-review, and exact-artifact evidence is complete.

The adapter API distinguishes wire representation from authorization: tier
round trips use the explicitly named representation helpers, while
`project_production_rail_policy` requires a Core verification class and
enforces Core's `Strict` → `LightClient` invariant. Core-compatible BIP-110
DTOs remain available without `bip110_compliant`; that feature gates executable
SDK validation only.

## 1. Core Module Boundaries

### A. Signing Core (Hardware Enforcer)
- **Scope**: Key generation, derivation, signing (ECDSA/Schnorr), and hardware attestation.
- **Interface**: `EnclaveManager` trait.
- **Boundary**: No awareness of transaction semantics beyond signing hashes and verifying nonces.
- **Constraint**: **Zero Secret Egress**. Private keys never leave this boundary.

### B. Routing Orchestration (Intent Layer)
- **Scope**: Pathfinding logic, intent construction, and liquidity rail selection.
- **Interface**: `FiatRouterService`, `A2pRouterService`, `RailProxy`.
- **Boundary**: Consumes `Signing Core` to sign generated intents.
- **Constraint**: Stateless. Does not persist user balance or state; strictly handles transformation and broadcast.

### C. Chain Adapters (Protocol Layer)
- **Scope**: Chain-specific encoding (Bitcoin Taproot, Stacks, EVM, Solana).
- **Interface**: `AssetRegistry`, `Chain` enum, `TaprootManager`.
- **Boundary**: Decoupled from specific liquidity rails. Provides the "language" for cross-chain interaction.

## 2. Interface Contracts (WASM/Binding Layer)

The `ConclaveWasmClient` serves as the canonical entry point for external integrators.

### In-Scope (SDK Goals)
- Cryptographic identity management.
- Multi-chain transaction signing.
- Hardware-backed attestation reporting.
- Cross-chain swap orchestration (Sovereign Handshake).
- ZKML and PSI shared services.

### Out-of-Scope (Wallet/UX Concerns)
- **UI State**: The SDK does not manage transaction history, contact lists, or "active" wallet state.
- **Balance Tracking**: The SDK does not cache or track account balances; it provides the signing logic to move them.
- **Secret Recovery UI**: Biometric or PIN prompt UIs are handled by the consumer application, using SDK callbacks.

## 3. Extensibility Model
- Partners add new liquidity rails by implementing the `SovereignRail` trait in `src/protocol/rails/`.
- New chains are added to the `AssetRegistry` and `Chain` enum in `src/protocol/asset.rs`.
