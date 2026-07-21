# Protocol Implementation Roadmap

> **Status:** foundation plus quarantine only, reviewed 2026-07-21.
>
> This roadmap is an acceptance contract, not a production-support claim. The
> current SDK boundaries provide typed identifiers, versioned public metadata,
> secret-safe opaque envelopes, structural validation, and idempotency helpers.
> Value-bearing FROST, Fedimint, Ark, and BitVM2 operations remain fail-closed
> with exact `ConclaveError::ProtocolUnsupported` results.

## Evidence and promotion rules

Each milestone must retain a traceable:

```text
requirement → code boundary → protocol vectors/tests → CI → reviewed artifact
```

The following are mandatory before any operation is reclassified from
quarantined to conditionally usable:

- exact protocol and ciphersuite/version selection;
- pinned external source revision and SDK dependency graph;
- negative, mutation, replay, serialization, and failure-path tests;
- independent cryptographic/protocol review for value-bearing code;
- provider, network/testnet, attestation, persistence, and recovery evidence;
- a reviewed tag, CI run, SBOM/provenance, artifact digest, and explicit support
  decision for the exact target/runtime/hardware scope.

The repository remains **Beta / conditional**. No milestone below authorizes
production signing, custody, settlement, federation operation, or bridge use by
itself.

## Shared local boundary contract

| Requirement | Current SDK boundary | Needed vectors/tests | CI / artifact gate | External versus SDK-local |
| --- | --- | --- | --- | --- |
| Reject malformed identifiers, thresholds, versions, envelopes, duplicate submissions, and replay conflicts without exposing payloads. | `src/lib.rs` typed `BoundaryValidationError`, protocol-specific versioned IDs/envelopes, and focused unit tests in `src/protocol/{frost,nexus/fedimint,ark,bitvm2}.rs`. | Invalid zero values, out-of-range thresholds, duplicate IDs, unsupported versions, conflicting replay IDs, redacted `Debug`/serde/error output, and no mutation after unsupported calls. | `cargo fmt`, Clippy with warnings denied, native all-target tests, WASM compile, secret/public API review, and retained test output for the reviewed ref. | Validation, ledgers, and error taxonomy are SDK-local. Cryptographic proofs, protocol wire formats, provider keys, and chain observations are external dependencies/evidence. |
| Preserve fail-closed behavior at every value-bearing entry point. | Existing `ProtocolUnsupported` paths in the four protocol modules and typed error propagation in `src/wasm_bindings.rs`. | Exact protocol/operation/reason matches; no synthetic output, signing call, network call, or local state mutation on unsupported failure. | Native and WASM tests must exercise each exposed quarantine entry point. | Unsupported decision is SDK-local; support requires external implementation and artifact evidence. |

## FROST / RFC 9591

### Pinned references and scope

- RFC 9591: <https://datatracker.ietf.org/doc/html/rfc9591>
- Zcash Foundation implementation: <https://github.com/ZcashFoundation/frost>
- Inspected `frost-secp256k1/v3.0.0` source revision:
  `2016e44ba4a4757a996300350063b937a2ad33e8`

### Requirement → boundary → acceptance

| Stage | Contract |
| --- | --- |
| Requirement | Select one RFC 9591 ciphersuite and serialization profile; define participant identifiers, threshold bounds, DKG round ownership, commitment/proof encoding, signing-session ownership, and one-use nonce lifecycle. |
| Current code boundary | `src/protocol/frost.rs` provides `FrostCiphersuite`, `FrostParticipantId`, `FrostThreshold`, `FrostSessionId`, `FrostParticipantSet`, versioned `FrostOpaqueEnvelope`, public package metadata, and duplicate/ownership validation. Key generation, DKG, nonce handling, signing, verification, and aggregation return exact `ProtocolUnsupported`. No nonce or share bytes are serialized. |
| Needed vectors/tests | RFC 9591 and pinned Zcash vectors; DKG validation and authenticated encryption; duplicate participant/share rejection; session-owner and session-ID binding; ciphersuite and encoding-version rejection; one-use nonce enforcement; zeroization tests; BIP340/provider/attestation key-binding tests; malformed and mutation negatives. |
| CI gate | Native format, Clippy, all-target tests, serialization/public-API review, dependency/license/audit checks, and a dedicated vector job using the exact pinned implementation revision. |
| Artifact gate | Independent review of DKG, nonce lifecycle, zeroization, ciphersuite serialization, provider key binding, and hardware attestation. Publish reviewed tag, SBOM/provenance, vector report, and support decision. |

### SDK-local versus external

- **SDK-local:** typed boundary models, validation, session ledger, error
  mapping, provider/attestation contract, and fail-closed tests.
- **External:** audited RFC implementation, curve/ciphersuite primitives,
  authenticated encryption, secure nonce generation/storage, hardware-backed
  key provider, and independent vectors/review.
- Do not add a hand-rolled DKG, Schnorr, nonce, or aggregation implementation
  to this crate as an intermediate step.

### Staged milestones

1. **Foundation (current):** typed public metadata and quarantine; production
   status `No`.
2. **Compatibility prototype:** integrate the pinned implementation behind a
   private/provider boundary; pass vectors and negative tests without enabling
   value-bearing callers.
3. **Security review:** verify DKG encryption/authentication, zeroization,
   one-use nonces, ciphersuite encoding, BIP340 binding, attestation, and
   recovery/rotation procedures.
4. **Conditional support decision:** only for a named provider, artifact,
   runtime, and operational scope; never a repository-wide claim.

## Fedimint / Nexus

### Pinned references and scope

- Fedimint source: <https://github.com/fedimint/fedimint>
- Fedimint documentation: <https://docs.fedimint.org/>
- Stable `v0.11.1` revision:
  `2620789610a2c65c1068de973ebb5657d08d549d`
- Prerelease `v0.11.2-alpha.1` revision:
  `b934260695c3a15178df7ddd33db8f66e1c9a153`

### Requirement → boundary → acceptance

| Stage | Contract |
| --- | --- |
| Requirement | Choose the supported Fedimint release/API; cover BLS12-381 threshold blind signatures, client/config/API compatibility, database and operation-log schemas, share verification, unblinding, note state, backup/recovery, and provider ownership. |
| Current code boundary | `src/protocol/nexus/fedimint.rs` provides typed federation/provider IDs, invite fingerprints, versioned opaque envelopes, provider-owned note handles, guardian threshold validation, operation states, and an idempotent request-digest ledger. `EcashNote` has no public serialized `secret: String`. Federation, minting, note verification, TBS/DLEQ, and threshold aggregation remain exact `ProtocolUnsupported`. |
| Needed vectors/tests | Upstream Fedimint client/mint vectors; BLS12-381 share verification and threshold cases; unblinding/note-state transitions; database migration and operation-log replay; backup/restore; duplicate/conflicting operation IDs; provider-handle redaction; malformed invite/config/version inputs. |
| CI gate | Run the selected upstream compatibility/vector suite in an isolated job; run native SDK tests, schema/serialization checks, persistence replay tests, and dependency/audit checks. Do not treat local structural tests as Fedimint integration evidence. |
| Artifact gate | Independent review of threshold signing, note lifecycle, database durability, backup/restore, provider boundary, and privacy behavior; retain exact Fedimint revision, SDK dependency graph, integration logs, SBOM/provenance, and support decision. |

### DLEQ qualification

The current boundary retains a DLEQ-shaped typed envelope because some
deployments and adjacent ecash designs use DLEQ-style proofs. The inspected
current canonical Fedimint mint flow did **not** provide sufficient evidence to
claim that DLEQ is inherently part of every current canonical issuance path.
Future implementation work must verify the selected Fedimint revision and API
instead of copying that claim into the SDK.

### SDK-local versus external

- **SDK-local:** secret-safe note representation, typed federation/config
  validation, operation idempotency, redaction, unsupported error behavior,
  and WASM non-export rules.
- **External:** Fedimint client/mint crates, BLS12-381/TBS implementation,
  federation consensus, database schema, guardian/provider deployment,
  backup/restore, and upstream vectors.
- Do not add a network stack or local blind-signature implementation to make
  the adapter appear complete.

### Staged milestones

1. **Foundation (current):** provider-owned handles and no raw note secret;
   production status `No`.
2. **Pinned client integration:** select stable or prerelease revision,
   integrate behind an explicit provider boundary, and validate config/schema
   compatibility without enabling issuance.
3. **Persistence/privacy review:** prove operation-log idempotency, note-state
   transitions, backup/restore, unblinding, and secret retention/deletion.
4. **Conditional support decision:** name federation/provider/deployment and
   exact artifact; no generic Fedimint support claim.

## Ark

### Pinned references and scope

- Protocol overview: <https://ark-protocol.org/>
- Arkade daemon: <https://github.com/arkade-os/arkd>
- Bitcoin-oriented implementations: <https://gitlab.com/ark-bitcoin>
- Inspected Arkade `v0.9.15`: Alpha; explicitly do not use in production.
- A future implementation milestone must choose and pin either Arkade or
  Second after an interoperability and maintenance review.

### Requirement → boundary → acceptance

| Stage | Contract |
| --- | --- |
| Requirement | Select one implementation and wire format; cover rounds, VTXOs/outpoints, ASP/server identity, connectors, forfeits, transactions, expiry, persistence, recovery, and unilateral exit. |
| Current code boundary | `src/protocol/ark.rs` provides typed version, VTXO/outpoint/round/server/connector/forfeit/operation IDs, backend/state/recovery/exit models, and structural tree/descriptor validation. `ArkManager::new` and the `Unconfigured` backend remain the safe disabled state; `try_with_backend` and compatibility `with_backend` reject `ProviderOwned` with exact `ProtocolUnsupported` until issue #195 supplies the enabling provider and attestation evidence. Generic seed/index APIs, public-key derivation, recovery, tree construction, and forfeit/settlement signing also return exact `ProtocolUnsupported`. |
| Needed vectors/tests | Selected implementation's round/VTXO/outpoint/connector/forfeit/transaction vectors; expiry and unilateral-exit boundary cases; ASP/provider identity; persistence/restart/recovery; duplicate observations; malformed tree/descriptor; no seed/private material in public or WASM payloads. |
| CI gate | Run selected implementation interoperability tests against pinned revisions; native SDK tests, WASM compile/boundary tests, and persistence/restart tests. No simulated ASP responses or hash-only tree fixture counts as integration evidence. |
| Artifact gate | Independent protocol/Bitcoin review, testnet evidence, provider/ASP operational review, recovery and unilateral-exit drill, exact transaction/artifact provenance, and support decision. |

### SDK-local versus external

- **SDK-local:** typed models, bounds, state labels, redacted/provider-owned
  boundaries, and unsupported behavior.
- **External:** selected Ark implementation, Bitcoin transaction/script
  semantics, ASP/provider, persistence, network observations, recovery
  procedures, and hardware-backed signing.
- Do not restore generic Blake2 seed derivation, synthetic tree construction,
  fixture ASP discovery, or local forfeit signing.

### Staged milestones

1. **Foundation (current):** typed quarantine; production status `No`.
2. **Implementation selection:** choose Arkade or Second, pin the revision,
   document interoperability and support exclusions.
3. **Protocol integration:** implement rounds/VTXOs/connectors/forfeits and
   durable recovery behind a provider boundary; pass vectors/testnet tests.
4. **Exit/recovery review:** independently exercise expiry, unilateral exit,
   restart, rollback, and provider failure; only then consider conditional
   support for a named artifact.

## BitVM2

### Pinned references and scope

- BitVM2 overview: <https://bitvm.org/bitvm2>
- Bridge paper: <https://bitvm.org/bitvm_bridge.pdf>
- Implementation repository: <https://github.com/chainwayxyz/bitvm>
- The reviewed BitVM2 material is experimental/research-oriented; the
  inspected implementation states that it is not for production use and has
  incomplete paths.

### Requirement → boundary → acceptance

| Stage | Contract |
| --- | --- |
| Requirement | Define operator/challenger/verifier roles, instance/commitment IDs, bridge graph, transaction templates, commitments, disprove scripts/proofs, timeouts/windows, chain monitoring, and durable idempotent state. |
| Current code boundary | `src/protocol/bitvm2.rs` provides typed roles, instances, commitments, inclusive challenge-window validation, external chain observations, idempotent observation ledger, transaction/disprove envelopes, backend and monitor models. Posting, challenge, resolution, challenge-window execution, transaction construction, and signing return exact `ProtocolUnsupported`. The legacy `WasmBitVmClient::sign_challenge` and `aggregate_challenge_signatures` entry points now fail before input decoding with BitVM2 `ProtocolUnsupported` errors; generic MuSig2 signatures and aggregates are not BitVM2 evidence. |
| Needed vectors/tests | Pinned paper/repository templates and script vectors; role/graph binding; commitment/disprove mutation tests; timeout/window boundary cases; external chain event ordering; duplicate/conflicting observations; durable monitor restart; provider/attestation key binding; no witness/proof secret bytes in serialized WASM models. |
| CI gate | Run selected implementation/script vectors in an isolated job; native boundary tests, WASM compile/tests, monitor persistence/replay tests, and exact unsupported-path tests. Do not treat a local state machine or proof-shaped byte vector as proof verification. |
| Artifact gate | Independent Bitcoin/script/proof review, testnet observation evidence, challenge/timeout drill, monitor durability and rollback evidence, exact artifact provenance, and a named support decision. |

### SDK-local versus external

- **SDK-local:** typed role/instance/commitment/window/observation contracts,
  idempotency, redaction, and fail-closed API behavior.
- **External:** BitVM2 proof/script implementation, bridge graph, Bitcoin
  transactions, chain monitor, provider/attestation, durable database, and
  operational challenge response.
- Do not construct scripts, verify SNARKs, post commitments, or synthesize
  chain observations in this crate boundary.

### Staged milestones

1. **Foundation (current):** external-observation ledger and quarantine;
   production status `No`.
2. **Selection and pinning:** choose a reviewed implementation/template set;
   record research/production exclusions and exact revisions.
3. **Offline/vector integration:** validate roles, templates, commitments,
   disprove paths, and timeout semantics without network or value-bearing use.
4. **Testnet/operations review:** prove chain monitoring, durable idempotency,
   challenge response, rollback, provider attestation, and artifact
   provenance before any conditional support decision.

## Cross-protocol acceptance checklist

- [ ] Current typed boundary tests remain green with exact unsupported errors.
- [ ] No raw seed, nonce, note secret, blinding factor, private share, witness,
      or proof payload is serialized or exposed through WASM.
- [ ] Every modeled mutable transition is either local validation/idempotency or
      driven by an external observation; no synthetic event is generated.
- [ ] Selected external revisions and dependency versions are pinned.
- [ ] Official and independent vectors, negative/mutation/replay tests, and
      provider/attestation tests are retained in CI.
- [ ] Persistence, backup/restore, recovery, rollback, and incident ownership
      are reviewed for the exact deployment scope.
- [ ] Independent review and exact artifact evidence exist before changing any
      capability row from `Production: No`.
