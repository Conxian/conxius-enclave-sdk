# Conclave SDK: Agent Directives (v0.3.0 — Session 47, Aug 2026)

## Core Ethos
The Conclave SDK is the definitive **Sovereign Rails** infrastructure for native Bitcoin applications. We prioritize hardware-backed security (TEE, StrongBox), non-custodial orchestration, and universal asset support.

## Coding Standards
- **SDK-First**: Prioritize modularity and clear boundaries between enclave, protocol, and bindings.
- **Fail-Closed**: Always ensure a 'fail-closed' security posture for high-value operations. Hardware attestation must be mandatory in production.
- **No-Panic**: Avoid `panic!`, `unwrap()`, and `expect()` in production paths. Use `ConclaveResult` for error handling.
- **Zeroization**: Sensitive data must be zeroed out when no longer needed.

## Protocol Module Catalog (Session 47 — Aug 2026)

| Module | Path | Status |
|--------|------|--------|
| bitcoin | `src/protocol/bitcoin/` | ✅ Core Bitcoin primitives |
| bip322 | `src/protocol/bip322/` | ✅ BIP-322 message signing |
| bitvm | `src/protocol/bitvm/` | ✅ BitVM2 proof verification |
| dlc | `src/protocol/dlc/` | ✅ Discreet Log Contracts |
| frost | `src/protocol/frost/` | ✅ FROST DKG |
| lightning | `src/protocol/lightning/` | ✅ BOLT 12, BIP-353 |
| musig2 | `src/protocol/musig2/` | ✅ MuSig2 multisig |
| stacks | `src/protocol/stacks/` | ✅ Stacks Nakamoto |
| zkml | `src/protocol/zkml/` | ✅ Zero-Knowledge ML |
| intent | `src/protocol/intent/` | ✅ Cross-chain intents |
| settlement | `src/protocol/settlement/` | ✅ Settlement rails |
| swap_router | `src/protocol/swap_router/` | ✅ DEX routing |
| stablecoin | `src/protocol/stablecoin/` | ✅ Stablecoin protocols |
| solver | `src/protocol/solver/` | ✅ Solver network |
| rails/bisq | `src/protocol/rails/bisq/` | ✅ P2P exchange |
| rails/boltz | `src/protocol/rails/boltz/` | ✅ Atomic swap |
| rails/changelly | `src/protocol/rails/changelly/` | ✅ Instant exchange |
| rails/wormhole | `src/protocol/rails/wormhole/` | ✅ Cross-chain messaging |
| rails/ntt | `src/protocol/rails/ntt/` | ✅ Native token transfer |
| rails/x402 | `src/protocol/rails/x402/` | ✅ HTTP payment protocol |
| ark | `src/protocol/ark/` | ✅ Ark protocol |
| covenant | `src/protocol/covenant/` | ✅ Bitcoin covenants |
| identity | `src/protocol/identity/` | ✅ DID, resolution |
| economy | `src/protocol/economy/` | ✅ Machine economy |
| chain_abstraction | `src/protocol/chain_abstraction/` | ✅ Chain abstraction |
| account_abstraction | `src/protocol/account_abstraction/` | ✅ Account abstraction |
| a2p | `src/protocol/a2p/` | ✅ Agent-to-protocol |
| job_card | `src/protocol/job_card/` | ✅ CJCS integration |
| mmr | `src/protocol/mmr/` | ✅ Merkle mountain range |
| sidl | `src/protocol/sidl/` | ✅ Sovereign IDL |
| cctp | `src/protocol/cctp/` | ✅ Cross-chain transfer |

## Consumer Wiring (Session 47)

| Consumer | Integration Path | Status |
|----------|-----------------|--------|
| conxius-wallet | Feature-gated via `conxius-silent-payments` → `enclave` feature | ✅ Wired |
| lib-conxian-core | Types referenced in `sdk_compat` module | ✅ Aligned |
| conxian-nexus | Indirect via lib-conxian-core `core_types` re-exports | ✅ Aligned |
| conxian-gateway | Contract bridge + Clarity calls | ✅ Bridge added |

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
