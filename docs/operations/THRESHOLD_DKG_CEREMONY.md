# Threshold DKG Ceremony Runbook

> **Status:** operational runbook (Phase 2 step 4). Complements
> [DECENTRALIZED_SIGNING_MIGRATION.md](../architecture/DECENTRALIZED_SIGNING_MIGRATION.md)
> and [THRESHOLD_ATTESTATION_DESIGN.md](../architecture/THRESHOLD_ATTESTATION_DESIGN.md).
> The threshold provider wiring (`src/enclave/threshold.rs`) is implemented and
> tested; this runbook specifies the one-time DKG ceremony and the audit gate
> that must complete before the value-bearing path is enabled in production.

## Objective

Split the release-signing authority into a single distributed key held as
**2-of-3** FROST shares by independent, hardware-backed operators, so that no
single key — and no single cloud — can authorize a release alone.

| Share | Operator | Mechanism |
| --- | --- | --- |
| 1 | Conxian infra | AWS Nitro enclave (attested TEE) |
| 2 | Owner | Keystone hardware wallet / Android StrongBox |
| 3 | Co-signer | independent HSM or enclave (separate operator) |

The ceremony must be recorded and independently audited, and **no party may
ever reconstruct the full secret key**.

## Prerequisites

- Rust `1.98.1` (org MSRV) with the `frost-crypto` feature enabled.
- Each operator has an air-gapped, attestable hardware boundary (Nitro / KeyMint
  StrongBox / HSM) with its own FROST participant identity.
- A coordinator channel (out-of-band) for exchanging DKG round messages; the
  coordinator never holds a secret share.
- Baseline verified: `cargo test --features frost-crypto --lib` (627 pass).

## Ceremony (distributed DKG, `ThresholdSigner`)

The `ThresholdSigner` DKG is a three-round protocol. Each operator runs the
same crate against their own secret material and only ever exchanges public
round packages. The concrete methods are in `src/signing/threshold.rs`
(`dkg_round1` / `dkg_round2` / `dkg_round3`).

1. **Round 1 — each operator** (participant `i` in `1..=3`):
   `dkg_round1(participant_id, max_signers = 3, min_signers = 2)` →
   `(secret_bytes, round1_package)`.
   - `secret_bytes` stays on the operator's device; it is **never** transmitted.
   - `round1_package` is published to the coordinator.

2. **Round 2 — each operator**, after receiving every `round1_package`:
   `dkg_round2(secret_bytes, round1_packages)` →
   `(round2_secret_bytes, round2_package)`.
   - `round2_package` is published; `round2_secret_bytes` stays local.

3. **Round 3 — each operator**, after receiving every `round2_package`:
   `dkg_round3(round2_secret_bytes, round1_packages, round2_packages)` →
   `(key_package, public_key_package)`.
   - `key_package` is the operator's FROST share (local).
   - `public_key_package` is identical across operators and is published.

The aggregated Schnorr x-only public key is derived from `public_key_package`
via `frost_crypto::public_key_x_only` (`src/protocol/frost_crypto.rs`).

> **No-full-key invariant:** `secret_bytes` and `key_package` never leave their
> operator's boundary. Only public round packages and the shared
> `public_key_package` are exchanged. A malicious or compromised coordinator
> cannot reconstruct the full key from these public values.

## Attestation

Each operator binds its FROST share to its hardware boundary by producing a
per-share `DeviceIntegrityReport` (Nitro NSM/COSE, KeyMint StrongBox, or HSM)
during signing — see `src/enclave/attestation.rs`. The threshold provider
(`ThresholdEnclaveManager::with_share_report_provider`) verifies each share
report under the single-mechanism policy and composes them into a single
threshold report (`AttestationLevel::Threshold`, M-of-N) that
`ValueBearingSignResponse::from_provider_at_time` accepts.

## Provider assembly

After the ceremony, the coordinator assembles the provider from the published
`public_key_package` and the operators' `key_package`s:

```rust
use crate::enclave::threshold::ThresholdEnclaveManager;
use crate::signing::threshold::FrostThresholdSigner;

let manager = ThresholdEnclaveManager::new(
    Box::new(FrostThresholdSigner::new()),
    key_packages,            // one per operator (2-of-3), distributed out-of-band
    public_key_package,      // published round-3 value
    2,                       // min_signers
)?;
```

Raw (non-value-bearing) signing is available immediately via
`EnclaveManager::sign`. Value-bearing signing additionally requires the
per-share attestation source:

```rust
let manager = manager.with_share_report_provider(Arc::new(|request| {
    // Collect + verify each operator's DeviceIntegrityReport for `request`.
    Ok(share_reports)
}));
```

## Nonce safety

FROST nonce reuse leaks the secret key. Every signing round must use a fresh,
replay-safe nonce from a secure RNG (see `threshold_sign` in
`src/enclave/threshold.rs`, which regenerates nonces per message). Do **not**
cache or reuse `create_nonces` output across requests.

## Audit gate (blocking)

MPC/Threshold is "Restricted (requires audit)" per
`SIGNER_BACKEND_POLICY_MATRIX.md`. Before enabling the value-bearing path in
production:

- The DKG ceremony is recorded end-to-end (participant identities, round
  transcripts, key ceremony hash) and independently reviewed.
- `t-of-n` signing passes the official FROST (RFC 9591) and MuSig2 (BIP-327)
  test vectors; mutated/invalid signatures and share-count violations fail
  closed.
- Independent cryptographic review of the threshold + signing + verification
  paths, including the composed threshold attestation verifier
  (`verify_threshold_composition`).

Phase 1 (KMS 2-of-3 quorum, `scripts/release/quorum-sign.sh`) remains the
tested fallback until this audit completes. On any threshold failure, revert to
the KMS quorum.
