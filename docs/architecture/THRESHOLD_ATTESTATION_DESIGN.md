# Threshold Attestation & EnclaveManager Integration Design

> **Status:** design (unblocks Phase 2 provider integration). Complements
> [DECENTRALIZED_SIGNING_MIGRATION.md](DECENTRALIZED_SIGNING_MIGRATION.md).
> The FROST/MuSig2/ROAST crypto is already implemented and tested
> (621 tests pass with `--features frost-crypto`); this doc specifies the
> remaining provider wiring and its one genuine blocker.

## The blocker: value-bearing attestation

The production value-bearing path is
`EnclaveManager::sign_value_bearing_provider` →
`ValueBearingSignResponse::from_provider_at_time` (`src/enclave/mod.rs:886`),
which requires the returned `SignResponse.device_attestation` to:

1. parse as a `DeviceIntegrityReport` and verify under
   `value_bearing_attestation_policy`;
2. bind `attested_operation_public_key` to the operation signing key;
3. carry a `signer_key_binding` equal to the expected `SignerKeyBindingEvidence`.

FROST (RFC 9591) and MuSig2 (BIP-327) produce a Schnorr secp256k1 signature
over the message digest but **no TEE attestation**. A threshold signer is a
composition of N independent hardware participants, so a single
`DeviceIntegrityReport` must be synthesized from the participants' evidence —
this is the integration's real design problem, not a simple call.

## Design: composed threshold attestation

Each participant attests its own key share using its native mechanism
(Nitro NSM/COSE, Android KeyMint/StrongBox, HSM). The threshold provider then:

1. Collects each participant's per-share integrity report.
2. Verifies each share report against its own provider policy
   (`TrustScope::SingleMechanism` per share).
3. Composes them into a **single threshold `DeviceIntegrityReport`** whose
   `attested_operation_public_key` is the aggregated Schnorr x-only key, under
   a **threshold policy** = M-of-N over the participant policies.

This keeps the existing `from_provider_at_time` verification unchanged: the
composed report must satisfy `value_bearing_attestation_policy`, bind the
aggregated key, and carry the matching `SignerKeyBindingEvidence`.

## Wiring plan

1. **`src/enclave/threshold.rs`** — `ThresholdEnclaveManager` holding
   `Box<dyn ThresholdSigner>` + the participant key packages + the aggregated
   verifying key. Home is `src/enclave/` (the provider is an `EnclaveManager`;
   it may import `crate::signing::{threshold, musig2_signing}`).
2. `signer_capability()` → `SignerCapability::provider_verified(<threshold-policy-id>)`.
3. `sign_value_bearing_provider()`:
   a. FROST: `create_nonces` → `create_signing_package` → `create_signature_share`
      across participants → `aggregate` (Schnorr).
      MuSig2: `new_session` → `generate_nonce` → `partial_sign` → `aggregate`.
   b. Compose the per-share attestations into the threshold report.
   c. Return `SignResponse { signature_hex, public_key_hex (aggregated),
      device_attestation }`.
4. Add a threshold `DeviceIntegrityReport` variant (or a composed-report
   verifier) so `value_bearing_attestation_policy` can accept it.

## Non-goals / gates (must be solved before enabling the path)

- **FROST nonce reuse leaks the secret key** — nonce generation must be
  replay-safe across participants (secure RNG + commitment ordering).
- The **DKG ceremony** must run once per threshold group (Nitro + StrongBox +
  co-signer) with audited share distribution; no party sees the full key.
- Independent cryptographic review (MPC/Threshold = "Restricted, requires
  audit" per `SIGNER_BACKEND_POLICY_MATRIX.md`).

## Implementation order

1. `ThresholdEnclaveManager` scaffold + raw `sign` (FROST aggregate) — no
   attestation yet.
2. Threshold `DeviceIntegrityReport` variant + verifier.
3. `sign_value_bearing_provider` wiring + tests.
4. DKG ceremony runbook + independent audit.
