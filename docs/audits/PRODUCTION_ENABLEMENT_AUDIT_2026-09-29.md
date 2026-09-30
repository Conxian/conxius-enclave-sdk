# Production Enablement Audit — 2026-09-29 (redo)

> **Verdict: Stable (conditional) for the non-signing capability surface; value-bearing signing remains conditional pending the #240 release-signing contract and an independent cryptographic review.**
>
> This redo supersedes the 2026-07-20 audit (`PRODUCTION_ENABLEMENT_AUDIT_2026-09-29.md`), whose verdict was **Stable (conditional)**. All P0 and required P1 findings recorded there are now resolved in code, in CI, or by newly captured hardware-attestation evidence. The only remaining production gates are the authenticated signer integration and independent review of the value-bearing signing path.

## Audit identity

| Item | Value |
| --- | --- |
| Audited candidate | `v2.0.17` (tag, GitHub release, and `Cargo.toml` `version` all agree) |
| Toolchain floor | `rust-version = "1.98.1"` |
| CI | All checks green on `main` (Rust tests, WASM build/runtime lanes, clippy/rustfmt, cargo-audit, cargo-deny, CodeQL, coverage, SBOM, provenance, secret-scan, hygiene) |
| Child issues | #195, #196, #197, #198, #199, #200, #201 — all CLOSED |
| Final gate | #202 — this redo is the capability-by-capability evidence record |
| Scope | Public repository source, tests, documentation, package metadata, and CI/release definitions |

## Resolution of P0 findings

| ID | 2026-07-20 finding | 2026-09-29 status | Evidence |
| --- | --- | --- | --- |
| P0-01 | Production signing unavailable (no real provider) | **Attestation verification is now real; signer integration remains open.** | The AWS Nitro attestation path was qualified end-to-end: a real Nitro enclave produced a signed attestation document, and the SDK's offline verifier accepted it (COSE signature + AWS Nitro root-CA trust chain + PCR0/1/2 + nonce + recipient-key hash + release binding). The CBOR pre-scan bug that rejected every genuine attestation document was fixed and merged (#392). |
| P0-02 | Typed rail settlement containment complete but production evidence incomplete | **Containment confirmed; distributed replay + signer evidence remain.** | Typed fail-closed boundary unchanged and exercised by tests. Process-local replay remains; distributed authorization and the #240 signer contract are the outstanding items. |
| P0-03 | BIP-322 acceptance-only verification | **Resolved.** | `src/protocol/bip322.rs` now performs real `secp256k1` ECDSA (P2WPKH), Schnorr (P2TR), and Taproot-commitment verification via the `bitcoin`/`secp256k1` crates (`verify_p2wpkh`, `verify_p2tr`, `verify_taproot_commitment`). |
| P0-04 | Non-canonical Ethereum/Taproot hashing | **Resolved.** | `src/protocol/ethereum.rs` uses `alloy::primitives::{eip191_hash_message, keccak256}`; `src/protocol/bitcoin.rs` uses `secp256k1::taproot::{TapLeafHash, TapNodeHash, TapTweakHash}` (BIP-341). |
| P0-05 | High-impact protocol surfaces unverified | **Resolved (fail-closed).** | CCTP now validates EVM addresses, rejects the zero address, and carries Circle's published secp256k1 attestation key; account abstraction fails closed pending a canonical module registry and rejects empty/malformed value-bearing calls. FROST/Fedimint/Ark/BitVM2 remain explicitly quarantined. |

## Resolution of P1 findings

| ID | 2026-07-20 finding | 2026-09-29 status |
| --- | --- | --- |
| P1-01 | Duplicate release publishers/creators | **Resolved** — single `release-strict.yml` publisher/creator (#199). |
| P1-02 | Non-reproducible dependency/toolchain evidence | **Resolved** — `Cargo.lock` tracked, MSRV pinned to `1.98.1`, CI toolchain pinned (#199). |
| P1-03 | Package metadata/version/tag/release drift | **Resolved** — `v2.0.17` tag + GitHub release + `Cargo.toml` all agree (#199). |
| P1-04 | Secret-scan echo-only gate | **Resolved** — checksum-verified full-history Gitleaks on tag paths (#199). |
| P1-05 | WASM/runtime/hardware evidence incomplete | **Resolved** — WASM build + generated runtime lanes in CI; Nitro hardware attestation evidence added (#200, #392). |
| P1-06 | Telemetry/privacy underspecified | **Resolved** — `docs/operations/TELEMETRY_OPERATIONS.md` (#201). |
| P1-07 | Unverified/placeholder asset addresses | **Resolved** — `validate_evm_address` + zero-address rejection across rails (#198). |
| P1-08 | Operational runbooks incomplete | **Resolved** — `docs/operations/PUBLIC_OPERATIONS_RUNBOOK.md`, `RELEASE_RECOVERY_RUNBOOK.md` (#201). |

## Capability-by-capability decision (exact candidate `v2.0.17`)

| Capability | Decision | Evidence chain |
| --- | --- | --- |
| Bitcoin/Taproot + BIP-322 verification | **Stable (conditional)** | requirement → `src/protocol/bitcoin.rs` / `bip322.rs` → unit tests → CI → `v2.0.17` artifact; canonical `secp256k1`/`bitcoin` crates |
| Ethereum derivation/signing | **Stable (conditional)** | `src/protocol/ethereum.rs` uses `alloy` Keccak/EIP-191 → tests → CI |
| Attestation verification (Nitro) | **Stable (conditional)** | real Nitro attestation qualified end-to-end (PR #392) → `src/enclave/nitro.rs` verifier → tests → CI |
| Hardware-backed signing (value-bearing) | **Conditional** | verifier real; signer integration (#240) + independent review still open |
| FROST / Fedimint / Ark / BitVM2 | **Quarantined (excluded)** | explicitly unsupported until protocol-vector + provider evidence |
| CCTP / account abstraction | **Fail-closed (conditional)** | `src/protocol/cctp.rs` / `account_abstraction.rs` reject invalid inputs |
| WASM surface | **Stable (conditional)** | WASM build + runtime lanes + secret-boundary tests in CI |

## Remaining gates (do not block non-signing promotion)

1. **#240 release-signing contract** — integrate the authenticated KMS signer (`alias/conxian-nitro-release`) into the value-bearing path, with distributed replay authorization.
2. **Independent cryptographic review** — a third-party review of the signing/settlement-critical paths before enabling value-bearing production signing.
3. **Distributed replay guard** — replace the process-local replay guard with deployment-safe coordination for production settlement.

## Verification limits

This is a source, test, CI, and documentation audit; it is not a penetration test or a substitute for the independent cryptographic review named above. It does not exercise live mainnet settlement, external custodians, or deployed consumer applications.
