# `conxian-release` DKG ceremony - operator workspace

This directory is where the three `conxian-release` signer operators drop their
DKG round packages. The **DKG Ceremony Evidence** workflow validates whatever is
present on every push and records it alongside the always-on rehearsal evidence,
so the ceremony is picked up automatically as operators come online.

## Participants

| Share | Operator | Mechanism | Round-1 package (public) |
|-------|----------|-----------|----------------|
| 1 | Conxian infra | AWS Nitro enclave | `round1/p1.pkg` |
| 2 | Owner | Keystone / Android StrongBox | `round1/p2.pkg` |
| 3 | Co-signer | independent HSM | `round1/p3.pkg` |

## Operator procedure

Each operator runs the SDK's FROST DKG against their own device (the secret
material never leaves it). **Round-1 packages are public by protocol design;
round-2 packages are NOT** - a round-2 package carries a per-recipient secret
`signing_share` and MUST be delivered point-to-point over a confidential,
authenticated channel (never committed, never posted to the PR). See
`docs/audits/ISSUE-726_INDEPENDENT_SIGNING_REVIEW_2026-11-10.md` (F1):

1. `dkg_round1(participant_id, 3, 2)` -> publish `round1/pN.pkg` (the round-1 package only).
2. Once every round-1 package is present, `dkg_round2(...)` -> send each recipient
   their own round-2 package over a **confidential authenticated channel**
   (out-of-band). **Do not publish round-2 packages.**
3. `dkg_round3(...)` -> hold the resulting `key_package` locally; publish the `public_key_package`.

The CI runs with `DKG_OPERATOR_DIR=ceremony` and validates the **round-1**
packages (`verify_dkg_round1_package`), recording a line like
`operator pickup: X/Y package(s) parseable`. Round-1 validation is a structural
(deserialization) check only - it does not verify the proof of knowledge (F2).

When all packages are present the ceremony is complete: the shared
`public_key_package` is the `conxian-release` signer key, and the value-bearing
path can be enabled once the independent audit (#202) passes.

## Rules

- Never commit a `key_package` or any secret material. Round-1 packages are
  public by design; round-2 packages contain a secret share and must never be
  committed or published - deliver them point-to-point.
- The rehearsal in `examples/dkg_ceremony.rs` proves the code path on every
  build; this directory is only for the real ceremony.
- Evidence is published to `s3://conxian-wasm-runtime/dkg-ceremony/{sha}/`
  (and `.../latest/`) by the workflow, and as a 90-day build artifact.
