# Settlement Rail vs. Bridge Ontology (G6)

This document reconciles the two overlapping uses of "rail" across the Conxian
repositories, as tracked in the G6 gap (`.github-private` capability audit §5).

## 1. Distinction

| Term | Definition | Owner |
|------|-----------|-------|
| **Settlement rail** | A single-chain value-settlement surface: how value is *settled* (finalized) on one network. | `conxian_market` `SettlementRail` |
| **Bridge / messaging system** | A cross-chain value/message transfer protocol: how value or messages *move between* networks. | `conxius-enclave-sdk` `protocol::bridges` |

The two concepts are orthogonal: a settlement can be denominated on a rail
(e.g. Lightning) while its cross-chain hop is mediated by a bridge (e.g. Wormhole NTT).

## 2. Inventory

### 2.1 `conxian_market` — `SettlementRail` (`src/core_types.ts`)

| Enum member | Wire value |
|-------------|-----------|
| `Statechain` | `STATECHAIN` |
| `Sbtc`       | `SBTC` |
| `Rgb`        | `RGB` |
| `Babylon`    | `BABYLON` |
| `Fedimint`   | `FEDIMINT` |
| `Lightning`  | `LIGHTNING` |
| `AlexStacks` | `ALEX_STACKS` |
| `EvmErc8183` | `EVM_ERC8183` |

### 2.2 `conxius-enclave-sdk` — `protocol::bridges` (`src/protocol/bridges/`)

| Module | System |
|--------|--------|
| `bisq.rs`       | Bisq |
| `boltz.rs`      | Boltz |
| `changelly.rs`  | Changelly |
| `ntt.rs`        | Wormhole NTT |
| `wormhole.rs`   | Wormhole |
| `x402.rs`       | X402 (payment scheme, `pub`) |

## 3. Alignment (completed)

- `protocol/rails` → `protocol/bridges` rename applied to the enclave SDK (the
  module exposes cross-chain bridge adapters, not settlement rails).
- `CANONICAL_NAMING_STANDARD.md` "Rails" terminology now refers only to
  single-chain settlement surfaces; cross-chain adapters are "Bridges".
- Consumers referencing `protocol::rails` were repointed to `protocol::bridges`.

## 4. Trust-Tier Policy

Bridge/messaging trust-tier policy is canonical in
`APPROVED_BRIDGE_AND_MESSAGING_SYSTEMS_BY_TRUST_TIER.md`; settlement-rail fee
modelling is canonical in `conxian_market` ADR-004 (`docs/adr/ADR_004_DYNAMIC_FEE_FLOOR_MODEL.md`).
