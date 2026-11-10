# Join the ceremony — open call for an independent co-signer

**Status:** open invite (proposal). Tracking: Conxian/conxian-business#1843
(Proof Guild). Runbook: [THRESHOLD_DKG_CEREMONY.md](THRESHOLD_DKG_CEREMONY.md).
Operator workspace: [`ceremony/README.md`](../../ceremony/README.md).

## What this is

Conxian's release-signing authority is a **2-of-3 FROST threshold**: no single
key, and no single cloud, can authorize a release alone. Share 1 is the Conxian
Nitro enclave and share 2 is the owner's hardware wallet. **Share 3 is open** —
we are looking for an **operationally independent** co-signer (and, separately,
an independent auditor for #202).

This is the first public "outside assistance" asset of the Proof Guild: a
concrete, checkable way for an outside operator to contribute real security to
the protocol.

## What you actually do

You never share a secret. You run the SDK's FROST DKG **against your own
device**, and publish only **public** round packages via a pull request:

1. `dkg_round1(participant_id, 3, 2)` → publish `ceremony/round1/pN.pkg`
2. Once every round-1 package is present: `dkg_round2(...)` → publish `ceremony/round2/pN.pkg`
3. `dkg_round3(...)` → hold the resulting `key_package` **locally**; publish the public key package.

The **DKG Ceremony Evidence** workflow (`.github/workflows/dkg-ceremony.yml`)
validates whatever is present on every push (`verify_dkg_round1_package` /
`verify_dkg_round2_package`) and records `operator pickup: X/Y package(s) valid`.
When all packages are present the ceremony is complete and the shared
`public_key_package` becomes the `conxian-release` signer key.

You can rehearse the exact code path first: `examples/dkg_ceremony.rs`.

## Requirements (non-negotiable)

- **Operational independence** — your own custody, your own identity, your own
  hardware boundary (independent HSM / enclave). No shared single point of
  control with Conxian or the other operators; otherwise the scheme collapses to
  an effective single signer (the Ronin/Bybit failure mode).
- **Hardware-backed boundary** — an attestable device (HSM, or Nitro/StrongBox-class).
- **Never commit secrets** — only public round packages and the public key package.

## What you get

- **Attribution** — named as a release signer in the evidence record and release notes.
- **Governance weight** — a say over release-signing integrity.
- **Funding-graph credit** — Btrust/OpenSats/HRF/NLnet/Vintem weigh a real contributor graph (Business #1788).
- **Portfolio value** — a verifiable, attributable contribution to Bitcoin-native infrastructure.

Perks never move anything to `accepted`, and never grant control over truth,
custody or release authority. Acceptance stays system-gated.

## Proof schema (what "valid" means)

Per the ceremony design: an attestation document (Nitro COSE + Nitro root-CA
chain) verifying PCR0/1/2, a nonce bound to the round, the recipient key, and
your identity claim. CI validates it; nothing is trusted on faith.

## How to start

Open an issue titled `Join the ceremony: <your handle>` referencing
Conxian/conxian-business#1843, or comment on the open call issue in this
repository. We will add you to the coordinator channel and confirm your share.

---
*Created by an AI agent (OpenHands) on behalf of the repository owner.*
