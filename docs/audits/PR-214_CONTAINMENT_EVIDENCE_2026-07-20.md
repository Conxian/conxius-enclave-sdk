# PR #214 Containment Evidence Snapshot

> **Snapshot date:** 2026-07-20
>
> **Scope:** Point-in-time evidence for partial containment in [PR #214](https://github.com/Conxian/conxius-enclave-sdk/pull/214). This snapshot is not a production-readiness, release-acceptance, or repository-wide support claim.

## Source and provenance

| Field | Value |
| --- | --- |
| PR | [#214](https://github.com/Conxian/conxius-enclave-sdk/pull/214) |
| Branch | `charlie/195-fail-closed-containment` |
| Containment head | `a877bf2eb1fa9acf06216f794dea4afc7217bb22` |
| Base branch | `main` |
| Base commit | `a4c19ac0469a633bddca76a0f54ad6a867bdc700` |
| Related issue gates | [#191](https://github.com/Conxian/conxius-enclave-sdk/issues/191), [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |

## What was proven

- Versioned attestation reports sign the report type, version, and security-relevant fields.
- Typed policy tokens enforce exact operation-purpose, algorithm, provider, and trust requirements.
- Missing or unverifiable provider evidence cannot become a production acceptance path; the runtime bypass is removed.
- Replay-cache saturation fails closed for new attestations.
- Raw BIP-340 signatures use the required raw encoding.
- Canonical complete-intent hashes bind rail and dispatch/security context before execution.
- Rail execution requires the attested complete intent, and production raw broadcast is rejected before network dispatch.
- Production-mode tests cover provider-unavailable verification, complete-intent binding, legacy request-only hash rejection, and raw-broadcast rejection.

## Native verification recorded on the containment head

- `cargo fmt --all -- --check && cargo clippy --all-features -- -D warnings && cargo test` — passed: 157 unit tests and 4 integration tests.
- `cargo test --all-targets --all-features` — passed: 176 unit tests and 4 integration tests.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- `cargo test --no-default-features` — passed: 157 unit tests and 4 integration tests.
- `cargo doc --no-deps --all-features` — passed with two existing rustdoc bare-URL warnings.
- `cargo metadata --format-version 1 --no-deps` — passed; package metadata reports `2.0.12`.
- `.github/scripts/verify-release-metadata.sh 2.0.12` — passed metadata consistency validation only.
- `cargo package --allow-dirty --no-verify` — passed.

## GitHub checks and WASM boundary

Every check reported for PR #214 was passing at this snapshot, including CI and CI Strict Rust tests, linting, and WASM builds; CodeQL; coverage; dependency review; repository hygiene; secret scanning; SBOM; security; cargo audit/deny; and GitGuardian checks.

The local WASM target probe was blocked by the existing `secp256k1-sys`/clang `memmove` issue. Both GitHub `WASM Build` checks passed on the pinned containment head. This is a CI result, not a claim of local WASM success or complete WASM runtime/platform support.

## What was not proven

- The provider verifier for Android StrongBox, Nitro, Intel DCAP, or AMD SEV is not available in this containment slice.
- Typed operation key, algorithm, and provider binding is incomplete and remains an open [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195) requirement.
- Independent security review and release acceptance remain open under [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202).
- Passing unit, integration, CI, or metadata checks does not establish production support, live-provider compatibility, or release provenance.

## Release and documentation caveats

The latest observed GitHub release is [`v2.0.11`](https://github.com/Conxian/conxius-enclave-sdk/releases/tag/v2.0.11). Repository metadata consistency for `2.0.12` passed its validation script, but no `v2.0.12` tag or GitHub release was established by that result.

Draft [PR #205](https://github.com/Conxian/conxius-enclave-sdk/pull/205) remains preserved and must not be overwritten or wholesale-merged. The capability evidence files `docs/architecture/capability-evidence.json` and `docs/architecture/CAPABILITY_MATRIX.md` are owned by open [PR #210](https://github.com/Conxian/conxius-enclave-sdk/pull/210), so explicit PR #214 containment/test references are intentionally deferred. WASM documentation and boundary work remains under [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200) and [PR #211](https://github.com/Conxian/conxius-enclave-sdk/pull/211).
