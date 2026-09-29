# Decentralized Signing Migration

> **Status:** Architecture proposal. Supersedes the single-signer posture on
> `alias/conxian-nitro-release`. Aligns with
> [SIGNER_BACKEND_POLICY_MATRIX.md](SIGNER_BACKEND_POLICY_MATRIX.md)
> (MPC/Threshold = "Restricted (requires audit)") and
> [ISSUE-240_PHASE_A_CONTRACT.md](ISSUE-240_PHASE_A_CONTRACT.md).

## Objective

Eliminate the single-signer risk on the AWS KMS release-signing key
`alias/conxian-nitro-release` (RSA_2048) — today a single key that, if
compromised, can authorize a release. Move to an M-of-N threshold scheme so no
single key (and no single cloud) can sign alone.

## Current state

- One RSA_2048 KMS key `alias/conxian-nitro-release` (`kms:Sign`) authorized to
  the `conxian-sdk-signer` principal (soon: the OIDC role from the federation
  migration).
- The SDK signing seam is `EnclaveManager::sign_value_bearing_provider`
  (`src/enclave/mod.rs`); the production provider is still unregistered
  (Beta/conditional per #240).

## Design

Two additive phases converging on "no single key authorizes a release".

### Phase 1 — KMS M-of-N quorum (immediate de-risk, no new crypto)

- Provision N=3 KMS keys (`alias/conxian-release-1/2/3`), each scoped to its
  own IAM principal (separate region and/or account for blast-radius
  isolation).
- A release is valid only with **M=2 of N=3** valid signatures; the release
  workflow collects signatures and enforces the quorum, failing closed below M.
- Use **ECC_NIST_P256** keys so the signature format is already the Phase 2
  shape; or keep RSA_2048 to stay byte-compatible with the current verifier
  (see `## Crypto migration`).

Trade-off: keys still live in AWS (one cloud), but no single key and no single
IAM principal can authorize.

> **Phase 1 status (2026-09-29): provisioned.** Keys `d7e45019…`
> (`alias/conxian-release-1`), `7a2eb775…` (`alias/conxian-release-2`),
> `3f4aa297…` (`alias/conxian-release-3`) — ECC_NIST_P256, SIGN_VERIFY.
> Reference signing/verification: `scripts/release/quorum-sign.sh` and
> `scripts/release/quorum-verify.sh` (2-of-3, ECDSA_SHA_256).

### Phase 2 — FROST / MuSig2 threshold (end-state)

Replace the N independent KMS keys with a **single distributed key split into
t-of-n shares** held by independent, hardware-backed operators:

| Share | Principal | Mechanism |
| --- | --- | --- |
| 1 | Conxian infra | AWS Nitro enclave (attested TEE) |
| 2 | Owner | Keystone hardware wallet / Android StrongBox |
| 3 | Co-signer | independent HSM or enclave (separate operator) |

- Use **FROST (RFC 9591)** or **MuSig2 (BIP-327)**; requires a distributed key
  generation (DKG) ceremony where no party ever reconstructs the full key.
- Threshold signing runs inside each participant's enclave/hardware boundary;
  the SDK's `SignerVerification::ProviderVerified` path verifies each share's
  attestation before accepting a partial signature.

## Crypto migration (RSA → ECC)

FROST and MuSig2 are defined over elliptic-curve groups; they cannot use the
current RSA_2048 key. Therefore:

- The release signature algorithm migrates RSA → ECC (Schnorr via BIP-327 or
  ECDSA/EdDSA via FROST).
- This is a **verifier-coordinated breaking change**: every release verifier
  must accept the new ECC scheme before the old RSA key is retired.
- Phase 1 can adopt ECC_NIST_P256 immediately so the verifier transition happens
  once, before Phase 2 introduces threshold shares.

## Acceptance criteria (MPC/Threshold requires audit)

- DKG ceremony is recorded and independently audited; no single party ever sees
  the full secret key.
- t-of-n signing passes official FROST (RFC 9591) and MuSig2 (BIP-327) test
  vectors; mutated/invalid signatures and share-count violations fail closed.
- Independent cryptographic review of the threshold + signing + verification
  paths.
- Phase 1 (KMS quorum) remains the tested fallback until Phase 2 is audited.

## Migration sequence

1. **Phase 1:** provision 3 KMS keys + quorum enforcement in the release
   workflow; rotate the release verifier to accept 2-of-3.
2. **Phase 2:** DKG ceremony → threshold signing implementation
   (FROST/MuSig2) behind the `EnclaveManager` provider seam.
3. **Audit + promotion:** independent review, then move MPC/Threshold from
   "Restricted" to "Allowed" in the signer matrix with evidence.

## Rollback

Phase 2 is additive to Phase 1: on any threshold failure, revert to the KMS
2-of-3 quorum. The RSA key is retired only after the ECC verifier transition
is complete and green.
