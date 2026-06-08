# Approved Bridge and Messaging Systems by Trust Tier

This document defines the canonical policy for bridge and messaging systems approved for use within the Conclave SDK (and by extension, Gateway and Nexus).

## 1. Trust-Tier Taxonomy (Route-Level Policy)

| Tier   | Policy Name        | Required Trust Class                                        | Production Allowance                                                                |
| ------ | ------------------ | ----------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| **T1** | Sovereign Verified | `proof_verified`                                            | Allowed for treasury-critical, governance/control-plane, and canonical asset routes |
| **T2** | Hybrid Verified    | `proof_verified` **plus** independent secondary verifier(s) | Allowed for production value + control-plane when T1 is unavailable                 |
| **T3** | Attester Network   | `attester_verified`                                         | Allowed for capped/non-canonical value routes with strict limits and kill-switches  |
| **T4** | Observer/Weak      | `observer_only` (or equivalent weak/default config)         | **Not allowed** in production (test/sandbox only)                                   |

`native_observation` remains valid for intra-domain/local observation, but does not by itself qualify as a cross-domain bridge/message security guarantee.

## 2. Approved Systems by Tier

| System                       | Default Trust Class                              | Approved Tiers                                               | Approval Status            | Required Conditions                                                                                                       |
| ---------------------------- | ------------------------------------------------ | ------------------------------------------------------------ | -------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **IBC (light-client paths)** | `proof_verified`                                 | **T1**, T2                                                   | **Approved**               | Must use light-client/consensus verification path; no downgrade to committee/observer modes for T1 routes                 |
| **Hyperlane**                | Usually `attester_verified` unless hardened      | **T2**, T3                                                   | **Conditionally Approved** | T2 requires Aggregation/custom ISM with independent verifier domains + strict threshold policy                            |
| **LayerZero**                | Config-dependent (DVN stack)                     | **T2**, T3                                                   | **Conditionally Approved** | T2 requires hardened multi-DVN config, operator diversity, pinned config, and drift checks (no placeholder/dead defaults) |
| **Wormhole NTT**             | `attester_verified` (Guardian network)           | **T3** (T2 only with independent additive verifier controls) | **Conditionally Approved** | Mandatory per-route caps, replay protection, emergency pause, and explicit route allowlists                               |
| **Axelar**                   | `attester_verified` (external PoS validator set) | **T3**                                                       | **Conditionally Approved** | Use for capped corridors; not for sovereign-root treasury/governance pathways                                             |

## 3. Forbidden Usage Patterns

1. Any single-attestor / single-verifier production route for value-bearing traffic.
2. Mutable or default verifier configs treated as production-safe without explicit hardening.
3. Unlimited mint/unlock authority without caps, rate limits, and emergency halt controls.
4. T3/T4 routes used for treasury rebalancing, governance execution, or canonical issuance.
5. Correlated “independent” verifiers (same trust/operator domain) counted as separate guarantees.
6. Silent trust downgrade at runtime (for example `proof_verified` route falling to `observer_only`).

## 4. Gateway Implementation Implications

Gateway route policy should be keyed by at least `(source_chain, destination_chain, system, asset_or_message_class, purpose)` and enforce:

- `minimum_required_tier`
- `allowed_systems`
- `value_caps` (per tx / per window)
- `allowed_message_types`
- `kill_switch` + circuit-breakers
- hard fail on unknown tier, stale evidence, or trust downgrade

## 5. Nexus Metadata Requirements (Canonical Proof Envelope)

Nexus should publish/store (minimum):

- `proof_type`
- `trust_tier`
- `trust_class`
- `finality_class`
- `verifier_set_id`
- `verifier_threshold`
- `freshness_window` + observed age
- `evidence_hash` / `evidence_ref`
- `config_hash` (active security config)
- `decision_reason` + `degrade_status`

This aligns with existing architecture docs that require normalized trust/proof fields and fail-closed behavior.
