# `conxian-release` DKG ceremony - operator workspace

This directory is where the three `conxian-release` signer operators drop their
DKG round packages. The **DKG Ceremony Evidence** workflow validates whatever is
present on every push and records it alongside the always-on rehearsal evidence,
so the ceremony is picked up automatically as operators come online.

## Participants

| Share | Operator | Mechanism | Round packages |
|-------|----------|-----------|----------------|
| 1 | Conxian infra | AWS Nitro enclave | `round1/p1.pkg` / `round2/p1.pkg` |
| 2 | Owner | Keystone / Android StrongBox | `round1/p2.pkg` / `round2/p2.pkg` |
| 3 | Co-signer | independent HSM | `round1/p3.pkg` / `round2/p3.pkg` |

## Operator procedure

Each operator runs the SDK's FROST DKG against their own device (the secret
material never leaves it) and publishes only the **public** round packages:

1. `dkg_round1(participant_id, 3, 2)` -> publish `round1/pN.pkg` (the round-1 package only).
2. Once every round-1 package is present, `dkg_round2(...)` -> publish `round2/pN.pkg`.
3. `dkg_round3(...)` -> hold the resulting `key_package` locally; publish the `public_key_package`.

The CI runs with `DKG_OPERATOR_DIR=ceremony`, validates each `*.pkg` with
`verify_dkg_round1_package` / `verify_dkg_round2_package`, and records a line
like `operator pickup: X/Y package(s) valid in ceremony`.

When all packages are present the ceremony is complete: the shared
`public_key_package` is the `conxian-release` signer key, and the value-bearing
path can be enabled once the independent audit (#202) passes.

## Rules

- Never commit a `key_package` or any secret material - only public round
  packages and the public key package.
- The rehearsal in `examples/dkg_ceremony.rs` proves the code path on every
  build; this directory is only for the real ceremony.
- Evidence is published to `s3://conxian-wasm-runtime/dkg-ceremony/{sha}/`
  (and `.../latest/`) by the workflow, and as a 90-day build artifact.
