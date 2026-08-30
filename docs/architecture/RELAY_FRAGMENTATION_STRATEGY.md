# Relay Fragmentation Strategy

> **Status:** Research note — no value-bearing code path is enabled by this
> document. It maps Bitcoin transaction-relay censorship-resistance into the
> SDK's existing boundary contract; the SDK's role is construction and signing,
> never broadcast policy.

## 1. The load-bearing distinction: consensus vs. policy

Bitcoin transaction propagation is governed by two independent rule sets:

- **Consensus rules** — the "actual math" (sighash, script semantics, tweak
  derivation). A transaction is either consensus-valid or it is not. This is
  non-negotiable.
- **Policy rules** — mempool acceptance, standardness, relay, and package
  limits. These are node-local and censorable (e.g., strict `OP_RETURN`
  filtering, "spam" heuristics, min-fee floors).

Censorship resistance is achieved only by routing around **policy** while
remaining strictly **consensus-valid**. The SDK's obligation ends at producing a
consensus-valid signature and a well-formed transaction; everything that fights
relay policy is downstream of that boundary and must never degrade signing
correctness (fail-closed, `docs/ETHOS.md`).

## 2. Mapping relay strategies onto the SDK boundary

The authoritative boundary is
[`SDK_BOUNDARY_CONTRACT.md`](./SDK_BOUNDARY_CONTRACT.md) (CON-628):

- **A. Signing Core** — "no awareness of transaction semantics beyond signing
  hashes and verifying nonces." Zero Secret Egress.
- **B. Routing Orchestration** — `RailProxy`/`FiatRouterService`/`A2pRouterService`;
  "strictly handles transformation and **broadcast**."
- **C. Chain Adapters** — `TaprootManager`, script/address/tx encoding.

| Relay strategy | Correct home | SDK? |
| --- | --- | --- |
| Direct-to-miner / out-of-band broadcast | **B. Routing Orchestration** (`rails/` `SovereignRail`) + service layer (`conxian-nexus`/`gateway`) | No — enclave must not own broadcast |
| Stratum V2 block-template inclusion | Service/infra layer | No — SDK owes only a correct sighash/tx a template can include |
| Ephemeral anchors / V3 / P2A / CPFP | **C. Chain Adapters** (`TaprootManager`, `Script`/`Address`) | Yes — construction + recognition only |
| Peer diversity / reject-monitoring (Tor/I2P/Clearnet) | Service layer (`gateway`) | No |

The "Sovereign Handshake" ordering in `docs/ETHOS.md` is the load-bearing
constraint: the intent is **signed inside the enclave before broadcast**. The
SDK's contribution to censorship resistance is a signature that is valid by
construction, so *any* permissive miner can include it.

## 3. In-scope for the SDK (construction primitives)

The SDK already recognizes P2A structurally (`src/protocol/bip322.rs`
`is_p2a` → `Bip322InconclusiveReason::P2a`). To support relay-resilient
applications, the SDK should expose **pure construction/recognition** (no
broadcast policy, no peer state):

- P2A / ephemeral-anchor script construction (`OP_1 <0x4e 0x73>`), witness v1.
- V3 package-relay and CPFP child-transaction construction (correct `TxOut.value`,
  `Transaction { input, output }` encoding) so the service layer can fee-bump.
- `Transaction`/`Witness`/`Script` primitives sufficient to emit a
  consensus-valid package.

These are chain-encoding concerns and belong in `C. Chain Adapters`
(`TaprootManager`), consistent with the existing `is_p2a` placement.

## 4. Out-of-scope for the SDK (relay policy)

The following belong to the service layer (`conxian-nexus`/`conxian-gateway`) or,
at most, `B. Routing Orchestration` (`rails/`), and must not enter the signing or
enclave path:

- Direct-to-miner submission and mempool-accelerator APIs.
- CPFP fee strategy and package broadcast.
- Stratum V2 template submission.
- Peer selection, Tor/I2P/Clearnet diversity, and `reject`-message monitoring.

Baking any of these into the TEE signing path would violate fail-closed and
"no TEE-bypass code paths" (`AGENTS.md`).

## 5. Runtime lanes

Per
[`THREE_LANE_RUNTIME_DEPLOYMENT_ARCHITECTURE.md`](./THREE_LANE_RUNTIME_DEPLOYMENT_ARCHITECTURE.md),
relay-resilience features follow lane priority **Managed → Enterprise → Operator
(defer)**. A construction primitive (P2A/V3/CPFP) is lane-agnostic and safe to
land on `main`; a broadcast *strategy* is a service-layer deployment concern.

## 6. References

- `SDK_BOUNDARY_CONTRACT.md` (CON-628) — Signing Core / Routing Orchestration / Chain Adapters.
- `ETHOS.md` — Zero Secret Egress, Sovereign Handshake, Hardware Attestation.
- `THREE_LANE_RUNTIME_DEPLOYMENT_ARCHITECTURE.md` — lane discipline.
- `WASM_SUPPORT_MATRIX.md` — WASM is beta/unsupported; value-bearing signing unsupported.
- `src/protocol/bip322.rs` — `is_p2a` recognition precedent.
