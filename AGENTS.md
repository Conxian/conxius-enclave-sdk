# Conclave SDK: Agent Directives (v0.3.1 — Session 48, Aug 2026)

## Core Ethos
The Conclave SDK is the definitive **Sovereign Rails** infrastructure for native Bitcoin applications. We prioritize hardware-backed security (TEE, StrongBox), non-custodial orchestration, and universal asset support.

## Coding Standards
- **SDK-First**: Prioritize modularity and clear boundaries between enclave, protocol, and bindings.
- **Fail-Closed**: Always ensure a 'fail-closed' security posture for high-value operations. Hardware attestation must be mandatory in production.
- **No-Panic**: Avoid `panic!`, `unwrap()`, and `expect()` in production paths. Use `ConclaveResult` for error handling.
- **Zeroization**: Sensitive data must be zeroed out when no longer needed.

## Protocol Module Catalog (Session 53 — Aug 2026) — 47 Modules

### Blockchain Protocols (21 modules)

| Module | Path | Description | Status |
|--------|------|-------------|--------|
| bitcoin | `src/protocol/bitcoin.rs` | Core Bitcoin primitives, PSBT, script | ✅ |
| bip322 | `src/protocol/bip322.rs` | BIP-322 message signing | ✅ |
| bitvm | `src/protocol/bitvm.rs` | BitVM proof primitive types | ✅ |
| bitvm2 | `src/protocol/bitvm2.rs` | BitVM2 protocol boundary (roles, commitments, challenges) | ✅ |
| dlc | `src/protocol/dlc.rs` | Discreet Log Contracts | ✅ |
| frost | `src/protocol/frost.rs` | FROST DKG, threshold signing, envelope types | ✅ |
| frost_crypto | `src/protocol/frost_crypto.rs` | **ZF FROST v3.0.0 real crypto backend** (DKG, signing, aggregation) | ✅ (Session 53) |
| lightning | `src/protocol/lightning.rs` | BOLT 12, BIP-353, LNURL | ✅ |
| musig2 | `src/protocol/musig2.rs` | MuSig2 multisig, nonce aggregation | ✅ |
| stacks | `src/protocol/stacks.rs` | Stacks Nakamoto, Clarity types | ✅ |
| covenant | `src/protocol/covenant.rs` | Bitcoin covenants (OP_CAT) | ✅ |
| ark | `src/protocol/ark.rs` | Ark protocol, VTXOs | ✅ |
| cctp | `src/protocol/cctp.rs` | Cross-chain transfer protocol | ✅ |
| mmr | `src/protocol/mmr.rs` | Merkle mountain range proofs | ✅ |
| ethereum | `src/protocol/ethereum.rs` | EVM chain abstraction, EIP-1559 | ✅ |
| solana | `src/protocol/solana.rs` | Solana program integration | ✅ |
| statechain | `src/protocol/statechain.rs` | Spark statechain protocol boundary (577 lines) | ✅ Structural |
| sidl | `src/protocol/sidl.rs` | Sovereign Interface Definition Lang | ✅ |
| credit | `src/protocol/credit.rs` | Credit facility management | ✅ |
| fiat | `src/protocol/fiat.rs` | Fiat on/off ramp types | ✅ |
| asset | `src/protocol/asset.rs` | Multi-asset registry (42 chains incl. SPARK) | ✅ |

### Cross-cutting Protocols (15 modules)

| Module | Path | Description | Status |
|--------|------|-------------|--------|
| intent | `src/protocol/intent.rs` | Cross-chain intent solving (ERC-7683) | ✅ |
| settlement | `src/protocol/settlement.rs` | Settlement rail abstraction | ✅ |
| settlement_service | `src/protocol/settlement_service.rs` | Settlement orchestration service | ✅ |
| swap_router | `src/protocol/swap_router.rs` | DEX routing, liquidity aggregation | ✅ |
| stablecoin_orchestrator | `src/protocol/stablecoin_orchestrator.rs` | Stablecoin protocol orchestration | ✅ |
| solver | `src/protocol/solver.rs` | Solver network, Fill-or-Kill | ✅ |
| chain_abstraction | `src/protocol/chain_abstraction.rs` | Unified chain interface | ✅ |
| account_abstraction | `src/protocol/account_abstraction.rs` | ERC-4337, smart accounts | ✅ |
| a2p | `src/protocol/a2p.rs` | Agent-to-protocol bridge | ✅ |
| control_model_adapter | `src/protocol/control_model_adapter.rs` | Cycle-safe Core control-model DTO mirror | ✅ |
| identity | `src/protocol/identity.rs` | DID, resolution, verifiable credentials | ✅ |
| economy | `src/protocol/economy.rs` | Machine economy, M2M settlement | ✅ |
| job_card | `src/protocol/job_card.rs` | CJCS integration, SLA enforcement | ✅ |
| business | `src/protocol/business.rs` | Business logic orchestration | ✅ |
| opportunity | `src/protocol/opportunity.rs` | Yield opportunity discovery | ✅ |

### Rails (6 modules)

| Module | Path | Description | Status |
|--------|------|-------------|--------|
| bisq | `src/protocol/rails/bisq.rs` | P2P exchange rail | ✅ |
| boltz | `src/protocol/rails/boltz.rs` | Atomic swap rail | ✅ |
| changelly | `src/protocol/rails/changelly.rs` | Instant exchange rail | ✅ |
| wormhole | `src/protocol/rails/wormhole.rs` | Cross-chain messaging rail | ✅ |
| ntt | `src/protocol/rails/ntt.rs` | Native token transfer rail | ✅ |
| x402 | `src/protocol/rails/x402.rs` | HTTP payment protocol rail | ✅ |

### Nexus Integration

| Module | Path | Description | Status |
|--------|------|-------------|--------|
| fedimint | `src/protocol/nexus/fedimint.rs` | Fedimint consensus integration | ✅ |

### SDK Infrastructure (4 modules)

| Module | Path | Description | Status |
|--------|------|-------------|--------|
| config | `src/config.rs` | SDK runtime configuration | ✅ |
| state | `src/state/mod.rs` | State management abstraction | ✅ |
| telemetry | `src/telemetry.rs` | Observability, metrics, tracing | ✅ |
| wasm_bindings | `src/wasm_bindings.rs` | WASM sub-clients for web integration | ✅ |

## Consumer Wiring (Session 48)

| Consumer | Integration Path | Status |
|----------|-----------------|--------|
| conxius-wallet | Feature-gated via `conxius-silent-payments` → `enclave` feature | ✅ Wired |
| lib-conxian-core | Types referenced in `sdk_compat` module | ✅ Aligned |
| conxian-nexus | Indirect via lib-conxian-core `core_types` re-exports | ✅ Aligned |
| conxian-gateway | Contract bridge + Clarity calls | ✅ Bridge added |

### Market Enhancement Integration (Session 48)

Statechain (Spark) module is now a documented settlement rail in the market layer:

| Market Doc | Statechain Role | Reference |
|------------|----------------|-----------|
| `SETTLEMENT_RAILS.md` §2 | VTXO lifecycle, fees, trust model | T2 Managed tier |
| `trust_tier_pricing.md` | Rail routing by tier | Managed+ access |
| `monitoring.md` | Via gateway adapter metrics | Prometheus endpoint |
| `FUNDING_AND_ECONOMICS.md` §3.4 | VTXO fees in revenue model | Micro revenue stream |

> Statechain struct validation complete (577 lines). Cryptography ops now backed by real ZF FROST v3.0.0 DKG + threshold signing (Session 53, PR #264 merged). MARKET-010 closed with structural evidence.

### TrustTier Enforcement (Session 48)
Enclave attestation is the gating mechanism for Managed/Strict tier auto-execution:
- **Managed**: Enclave attestation required for Statechain, sBTC, RGB, Babylon rails
- **Strict**: TEE + ZK proof required for all rails, institutional SLA
- **Expedient**: Light client verification only (Fedimint, Lightning, ALEX)
- **ObserverOnly**: No verification needed (discovery only)

## Directory Map
- `src/enclave/`: Hardware attestation and secure signing (TEE/StrongBox).
- `src/protocol/`: Core Bitcoin/Multi-chain orchestration logic.
- `src/protocol/rails/`: Modular settlement rails (x402, Wormhole, etc.).
- `src/wasm_bindings.rs`: Modular WASM sub-clients for web integration.
- `docs/architecture/`: Active architectural standards and research.
- `docs/audits/`: Mainnet readiness and security audit artifacts.

## Testing
- Use `cargo test` to verify all protocol changes.
- Ensure all 30+ chains in the `AssetRegistry` are correctly handled.
- Hardware-backed logic should be tested with both simulated and software attestation (for CI) but blocked for production-level Trust Tiers.
