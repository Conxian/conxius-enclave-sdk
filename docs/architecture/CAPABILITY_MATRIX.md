# Capability and Evidence Matrix

> **Canonical status:** Beta / conditional as of 2026-07-20.
>
> This matrix records evidence maturity, not marketing status. API presence does not imply implementation completeness, interoperability, independent review, or production support. See [the production-enablement audit](../audits/PRODUCTION_ENABLEMENT_AUDIT_2026-07-20.md) for findings, gates, and unknowns.

## Evidence levels

| Column | Meaning |
| --- | --- |
| API present | A public type, function, trait, or WASM binding exists. |
| Implementation complete | The declared semantics are implemented without simulated, structural-only, or placeholder behavior. |
| Integration-tested | The capability is tested against real protocol vectors, vendor/platform boundaries, or a live testnet integration as appropriate. Unit tests alone are insufficient. |
| Independently reviewed | An external security, cryptographic, or protocol review is attached to the exact implementation/release under consideration. |
| Production-supported | The capability has passed the release, operational, monitoring, rollback, and support gates for a specific artifact. |

`Yes` means evidence was found for the stated scope. `Partial` means only part of the scope is evidenced. `No` means the repository evidence shows the gate is not met. `Not evidenced` means this repository does not establish the claim.

## Matrix

| Capability | API present | Implementation complete | Integration-tested | Independently reviewed | Production-supported | Evidence and boundary |
| --- | --- | --- | --- | --- | --- | --- |
| Enclave abstraction and signing interface | Yes | Partial — production provider unavailable | Partial — software/test fixtures only | Not evidenced | No | `src/enclave/mod.rs` routes value-bearing protocol signing through a fail-closed verifier; software drivers are gated behind `development-simulators`/test configuration. |
| Hardware-backed attestation | Yes | Partial — provider verifier unavailable | No — simulated fixtures | Not evidenced | No | `DeviceIntegrityReport` verifies canonical bytes, nonce, freshness, signature, roots, levels, purpose, and typed algorithm markers, but vendor roots, deployed hardware, and provider evidence are not present. |
| Rail attestation and trust-tier policy | Yes | Partial — strict boundary, no provider evidence | Partial — negative and deterministic boundary tests | Not evidenced | No | `RailProxy` requires canonical intent binding and complete typed report verification; replay state is consumed only after successful verification and the legacy boolean cannot disable enforcement. |
| Bitcoin ECDSA signing | Yes | No — production boundary rejects unavailable/software providers | Partial — unit paths | Not evidenced | No | `src/protocol/bitcoin.rs` uses the common value-bearing signer boundary; no real hardware/provider release evidence exists. |
| Schnorr/Taproot signing | Yes | No | Partial — unit paths | Not evidenced | No | `src/protocol/bitcoin.rs` contains a custom TapTweak tag; canonical BIP-340/BIP-341 vectors are not evidenced. |
| BIP-322 message verification | Yes | No | No — acceptance-only tests | Not evidenced | No | `src/protocol/bip322.rs` decodes input and returns success without cryptographic signature verification. |
| Ethereum addresses and signed messages | Yes | No | No — implementation mismatch | Not evidenced | No | `src/protocol/ethereum.rs` uses SHA-256 for operations that require canonical Ethereum hashing. |
| FROST threshold signing | Yes | No — structural/hash placeholder | No — structural tests | Not evidenced | No | `src/protocol/frost.rs` derives labels/shares by hashing and returns an `R` placeholder. |
| Fedimint blind/threshold flows | Yes | No — simulated threshold path | No — structural tests | Not evidenced | No | `src/protocol/nexus/fedimint.rs` uses simulated federation keys, structural DLEQ checks, and hash-based aggregation. |
| Ark / BitVM2 orchestration | Yes | No — simulated/partial | No — structural tests | Not evidenced | No | `src/protocol/ark.rs` and `src/protocol/bitvm2.rs` include simulated IDs and an always-true challenge-window branch. |
| CCTP transfer and attestation | Yes | No — placeholder | No | Not evidenced | No | `src/protocol/cctp.rs` returns an empty burn payload and treats any non-empty attestation as valid. |
| ERC-7579/account abstraction | Yes | No — structural only | No | Not evidenced | No | `src/protocol/account_abstraction.rs` creates an example batch mode and validates only non-empty module addresses. |
| Asset registry and chain catalog | Yes | Partial | Partial — registry tests | Not evidenced | No | `src/protocol/asset.rs` exposes many active assets without contract addresses; executable address provenance is incomplete. |
| WASM bindings | Yes | Partial — signing provider unavailable by default | No — build-only evidence | Not evidenced | No | `src/wasm_bindings.rs` rejects the default software-enclave constructor and uses an error-only unavailable provider until a real hardware/runtime integration is supplied. |
| Telemetry and observability | Yes | No — privacy/operations gaps | No | Not evidenced | No | `src/telemetry.rs` sends API key and signature hash in a detached request with undocumented consent/retention/failure policy. |
| Release, SBOM, and provenance | Yes | Partial — workflow definitions | No — durable artifact set not evidenced | Not evidenced | No | `.github/workflows/release*.yml`, `.github/workflows/provenance.yml`, and package metadata exist, but workflows are duplicated and `2.0.12` release evidence is not reconciled with visible `v2.0.11`. |

## Promotion rules

1. A row cannot be marked **production-supported** unless all preceding evidence columns are `Yes` for the same artifact and deployment scope.
2. `Simulation only`, `structural`, `placeholder`, `mock`, and `development-only` behavior must remain explicitly labeled and must not be used as production evidence.
3. A capability may be supported for one artifact/platform and unsupported for another; promotion must name the exact tag, target, runtime, hardware, and integration boundary.
4. Any unknown or missing evidence is a gate failure for value-bearing signing or settlement, not an implicit pass.
