# Core Control-Model Adapter Boundary (SDK #194)

## Status and scope

This document records the cycle-safe boundary between `lib-conxian-core` and
`conxius-enclave-sdk`. The SDK remains **Beta / conditional**. The adapter
module is compatibility infrastructure and is not evidence that any rail,
chain, attestation, signing, or settlement path is production-supported.

The public implementation boundary is
[`src/protocol/control_model_adapter.rs`](../../src/protocol/control_model_adapter.rs).
It mirrors reviewed serialized contracts without adding a reverse Cargo
dependency from the SDK to Core.

## Ownership table

| Concern | Core canonical ownership | SDK ownership | Adapter boundary |
| --- | --- | --- | --- |
| Trust taxonomy | `control_model::trust::TrustTier::{Strict, Managed, Expedient, ObserverOnly}` and its policy meaning; `VerificationClass` and its policy invariant | `protocol::rails::TrustTier::{T1, T2, T3, T4}` and rail classification/defaults | `CoreTrustTier`, `CoreVerificationClass`, explicit representation mappings, and a separate fallible production projection |
| Concrete chain taxonomy | Reviewed `control_model` chain enum and exact chain-to-family mapping | `protocol::asset::Chain`, `AssetRegistry`, asset metadata, and chain-specific runtime behavior | `CoreChain`, `CoreChainFamily`, and exact-only SDK-to-Core mapping; SDK-only, generic, or lossy chains are rejected |
| Rail metadata and selection | Core may consume shared control-model values | `RailProxy`, built-in rail implementations, rail trust ordering, dispatch, and static SDK rail metadata | Production projection accepts SDK rail tier only as a validated representation; it does not move rail selection or dispatch into Core |
| Network context | Core has no equivalent network enum in the reviewed contract | `config::Network::{Mainnet, Testnet, Devnet}` and runtime network behavior | Mainnet is the only reviewed production projection; Testnet and Devnet fail closed rather than being invented as Core types |
| Signed-envelope identity | Core `SignedEnvelopeDescriptor` shape and deterministic `publisher:event_id:sequence` identity | Signature verification, signing, attestation, runtime authorization, and replay storage | `CoreSignedEnvelopeDescriptor` provides exact serde fields and deterministic serialization/identity helpers only |
| BIP-110 shared limits and shapes | Core `Bip110Limits` and `Bip110TransactionShape` are the canonical serialized contract | SDK-specific raw transaction/script parsing, BIP-322 integration, witness classification, and Taproot control-block rules | `CoreBip110Limits` and `CoreBip110TransactionShape`; SDK validation derives canonical defaults from the adapter DTO |
| Replay storage and enforcement | Core descriptor identity can identify an operation; it is not persistent replay storage | `ReplayGuard`, rail replay handling, value-bearing replay authorization, and process/runtime enforcement | No replay store is mirrored or replaced by the adapter |
| Parsing and signing | Core consumes platform-neutral control-model inputs | SDK owns parsing, signing, enclave integration, key handling, attestation verification, and provider-specific behavior | No runtime behavior is pulled into the serialized adapter |

The table intentionally separates a shared representation from runtime policy.
Mapping an SDK tier or chain does not authorize a rail, attest a device, verify a
signature, or establish settlement support.

## Immediate cycle-safe boundary

The exact reviewed provenance is:

- Core `main` at `5325860499800ae440e03962605de9dd833e53e1`.
- Core trust and chain contracts under `src/control_model/` at that baseline.
- Core BIP-110 PR #184, merged as `1699cf3b04ee0755756f5e8c38ec37388c89efbd`.
- Core PR #223's companion add-on remains a migration candidate, not a merged
  dependency or release artifact.

At this boundary, Core currently has an optional `enclave` feature that points
to `conxius-enclave-sdk`. The SDK therefore **must not** depend directly on
`lib-conxian-core`; a direct reverse edge would create a Cargo dependency
cycle. The adapter mirrors the current wire contract with exact field names,
snake-case enum values, and fail-closed unknown-field handling where the
boundary is structured.

The adapter deliberately does not claim that its DTOs are a second canonical
implementation. Core remains the source of truth. When a contract changes,
the adapter must be reviewed against the exact Core source and provenance
before compatibility is updated.

## Production projection rules

`project_production_rail_policy` is an explicit, fail-closed authorization
projection from SDK inputs into Core control-model values. It requires a
`CoreVerificationClass` input and:

1. accepts only `Network::Mainnet`;
2. maps SDK `T1`/`T2`/`T3` to Core `Strict`/`Managed`/`Expedient`;
3. maps SDK `T4` to `ObserverOnly` for representation purposes, then rejects
   it for production authorization;
4. enforces Core's exact invariant that `Strict` requires `LightClient`;
5. includes the verification class in the returned projection;
6. derives the Core family from the exact mapped Core chain; and
7. rejects SDK-only, generic, or lossy chains instead of collapsing them to a
   broad family.

The representation-only helpers are intentionally separate:

```rust
let core_tier = sdk_trust_tier_to_core_representation(TrustTier::T1);
assert_eq!(core_tier, CoreTrustTier::Strict);

let projection = project_production_rail_policy(
    TrustTier::T1,
    CoreVerificationClass::LightClient,
    Network::Mainnet,
    Chain::BITCOIN,
)?;
assert_eq!(projection.verification_class, CoreVerificationClass::LightClient);
```

The first call is a wire representation mapping and grants no authorization.
The second is the fallible production boundary. It is not a replacement for
`RailProxy`, attestation policy, `AssetRegistry` validation, signing checks, or
`ReplayGuard`; it prevents an adapter caller from treating an unsupported SDK
context as a reviewed Core production value.

## BIP-110 boundary

The public SDK `protocol::bip110::Bip110Limits` keeps its existing three-field
layout and APIs. Its canonical defaults and validator internals are derived
from the Core-compatible `CoreBip110Limits` DTO, whose exact defaults are
256-byte pushdata, 83-byte OP_RETURN scriptPubKeys, 34-byte non-OP_RETURN
scriptPubKeys, and 256-byte witness elements.

`CoreBip110TransactionShape` validates every vector occurrence, including
witness elements. Both Core-compatible DTOs are intentionally available
regardless of the `bip110_compliant` feature so wire compatibility is always
present; only executable SDK validation remains feature-gated. The SDK still
owns raw script parsing, BIP-322 integration, Taproot control-block structural
checks, and context-specific witness rules.
This issue does not duplicate or change the BIP-322 preimage-vs-digest work
tracked separately under SDK issue #179.

## Migration path

The migration preserves the existing public SDK types and behavior:

1. Keep `rails::TrustTier`, `asset::Chain`, `config::Network`, `RailProxy`,
   `AssetRegistry`, `ReplayGuard`, and all SDK-specific validation public and
   SDK-owned.
2. Use the adapter DTOs at serialized boundaries and use explicit conversion
   functions at policy boundaries.
3. Add Core-backed conversions only after the shared contract is available
   without a reverse dependency.
4. If Core's SDK compatibility facade moves to a third package or a neutral
   leaf crate, the future dependency direction may become `SDK → Core` (or
   `SDK → neutral contract crate`) while the public SDK types continue through
   compatibility adapters.
5. Remove mirrored DTOs only through a separately reviewed migration with
   schema, semver, and downstream compatibility evidence.

## Limitations and conditional wording

These adapters are serialized compatibility and validation helpers. They do
not provide hardware attestation, cryptographic signature verification,
persistent replay coordination, live provider connectivity, consensus
validation, or production settlement evidence. Hardware support, rail support,
network support, and release readiness remain capability- and artifact-
specific and must continue to be described as conditional until the required
requirement → code → test → CI → artifact evidence chain exists.
