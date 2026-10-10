# Independent Verification Guide — proving the system without trusting Conxian

This guide lets any external party verify the security claims of `conxius-enclave-sdk`
directly from source and published artifacts, rather than taking Conxian's word for it.

The SDK exposes a machine-readable **evidence model** with five ordered axes:

```
api → implementation → integration → independentReview → productionSupport
```

A capability is only `production-supported` when every earlier axis is evidenced for the
**exact tagged candidate**. The authoritative ledger is
[`docs/architecture/capability-evidence.json`](capability-evidence.json), rendered by
[`docs/architecture/CAPABILITY_MATRIX.md`](CAPABILITY_MATRIX.md). The current maturity is
`stable-conditional` — non-signing surfaces are `Stable (conditional)`; value-bearing
signing stays conditional until `independentReview` is evidenced (issue #202).

## 1. Read the support statement first

1. [`SECURITY.md`](../SECURITY.md) — what is and is not supported.
2. [`docs/architecture/CAPABILITY_MATRIX.md`](CAPABILITY_MATRIX.md) — per-capability axis state.
3. [`docs/architecture/capability-evidence.json`](capability-evidence.json) — the raw ledger.
4. [`docs/architecture/GAP_SCORECARD.md`](GAP_SCORECARD.md) — prioritised residual gaps.

Anything marked `conditional` or `not-evidenced` must be treated as **not production-grade**,
regardless of what API surface exists.

## 2. Reproduce the build from the exact tag

```bash
git clone https://github.com/Conxian/conxius-enclave-sdk.git
cd conxius-enclave-sdk
git checkout v2.1.0            # the exact reviewed candidate
cargo package --locked         # must use the pinned Cargo.lock, no drift
sha256sum target/package/*.crate
```

The produced `sha256sum` must equal the published release checksum.

## 3. Verify the build provenance (SLSA)

The release is built on GitHub-hosted runners and attested with
`actions/attest-build-provenance` in `release-strict.yml`:

```bash
gh attestation verify \
  target/package/*.crate \
  --repo Conxian/conxius-enclave-sdk \
  --signer-workflow Conxian/conxius-enclave-sdk/.github/workflows/release-strict.yml \
  --source-ref refs/tags/v2.1.0
```

This binds the artifact digest to the exact workflow and tag, so a tampered crate cannot
carry a valid attestation.

## 4. Verify the SBOM

The release ships both SPDX and CycloneDX inventories (`sbom.yml` / `release-strict.yml`).
Confirm the dependency graph in the SBOM matches the pinned `Cargo.lock` (the release job
gates on `cargo metadata --locked` to reject a stale lockfile).

## 5. Run the conformance and threshold suites

```bash
cargo test --locked --all-features
```

Key suites to inspect:

- `tests/durable_replay_conformance.rs` — durable replay store contract (`G240-RP`).
- `tests/fixtures/` — shared conformance vectors.
- `src/enclave/threshold.rs`, `src/signing/threshold.rs`, `src/protocol/frost.rs`,
  `src/protocol/frost_crypto.rs` — FROST/MuSig2 keygen, round serialization, aggregation.
- `examples/dkg_ceremony.rs` — the 2-of-3 distributed-key-generation rehearsal that
  `dkg-ceremony.yml` runs continuously in CI.

## 6. Verify static gates

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
```

These are the same gates CI enforces (`ci-strict.yml`).

## 7. Verify the enclave attestation path (offline)

Nitro attestation is verified offline against the Nitro root-of-trust: COSE structure, PCR0-2
digests, nonce/challenge binding, recipient-key binding, and release binding. See
`src/enclave/nitro.rs` and the offline-verification evidence in `docs/audits/`.

## 8. The one thing you cannot verify from source

`independentReview` (issue #202) is the only axis that, by definition, cannot be produced by
the repository itself — it requires a third party recording a capability-by-capability
decision for the exact candidate. Until that is published, treat value-bearing signing as
`conditional`. See
[`INDEPENDENT_SECURITY_REVIEW_RFP_2026-10-10.md`](../audits/INDEPENDENT_SECURITY_REVIEW_RFP_2026-10-10.md)
for the commissioning scope.
