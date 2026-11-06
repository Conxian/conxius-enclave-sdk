# Signing Compatibility Matrix (SDK-010)

> Phase 2, generated 2026-08-07. Last reconciled 2026-11-06.
>
> **This matrix tracks code presence, not production support.** The authoritative
> support decision is [`capability-evidence.json`](architecture/capability-evidence.json),
> rendered by [`CAPABILITY_MATRIX.md`](architecture/CAPABILITY_MATRIX.md). A
> capability is production-supported only when the ordered axes
> `api → implementation → integration → independentReview → productionSupport`
> are all evidenced for the exact tagged candidate.
>
> **Current status (2026-11-06): 0 production-supported capability records.**
> Every signing capability below is `unsupported` or `conditional`, and no
> capability has evidenced `independentReview`. Value-bearing signing must remain
> disabled in production (see [README status](../README.md) and
> [HARDWARE_SIGNING_PROVIDER_MATRIX_2026.md](architecture/HARDWARE_SIGNING_PROVIDER_MATRIX_2026.md)).

## Legend

- **Present** — code and local tests exist for this chain/algorithm pair.
- **Prod** — production support per the capability ledger.
- `(feature)` — the crypto backend is gated behind a non-default Cargo feature.

## Signing Backend × Chain Family

| Chain Family | Algorithm | UCS Trait | Enclave Signing | FROST Threshold | MuSig2 | BIP-322 | Prod |
|---|---|---|---|---|---|---|---|
| **Bitcoin Taproot** | Schnorr (BIP-340) | Present (SDK-001) | Present | Present (`frost-crypto`) | Present | N/A | unsupported |
| **Bitcoin Legacy** | ECDSA secp256k1 | Present (SDK-001) | Present | N/A | N/A | Present (SDK-004) | conditional |
| **Ethereum** | ECDSA secp256k1 | Present (SDK-001) | Present | N/A | N/A | N/A | unsupported |
| **Solana** | Ed25519 | Present (SDK-001) | Present | N/A | N/A | N/A | conditional |
| **Stacks** | ECDSA secp256k1 | Present (SDK-001) | Present | N/A | N/A | N/A | conditional |
| **Babylon** | Schnorr delegation | Present (SDK-001) | Present | N/A | N/A | N/A | unsupported |
| **RGB** | Bitcoin anchor | Present (SDK-001) | Present | N/A | N/A | N/A | unsupported |

None of the above is production-supported. `Enclave Signing` for value-bearing
operations fails closed through `UnavailableEnclave` until a hardware provider is
qualified.

## Signing Modules

| Module | Protocol | Code | Prod |
|---|---|---|---|
| `covenant_signing.rs` | Covenant (OP_CAT) recursive signing | Present | unsupported |
| `dlc_signing.rs` | DLC oracle signing | Present | unsupported |
| `lightning_signing.rs` | Lightning BOLT12 offer signing | Present | unsupported |
| `zkml_signing.rs` | ZKML proof verification signing | Present | unsupported |
| `statechain_signing.rs` | Spark statechain vUTXO signing | Present | unsupported |
| `bitvm2_signing.rs` | BitVM2 challenge/response signing | Present | unsupported |
| `wasm_runtime.rs` | WASM signing surface | Present | unsupported |

"Present" means code and local tests exist. It does not mean the module is wired
into a qualified runtime, independently reviewed, or production-supported.

## Trust Tier Enforcement

| Tier | Required | SDK Enforcement |
|---|---|---|
| **T1 (Sovereign Verified)** | `proof_verified` + hardware attestation | Typed boundary; no production-supported provider, fails closed |
| **T2 (Hybrid Verified)** | `proof_verified` + secondary verifier | Typed boundary; no production-supported provider, fails closed |
| **T3 (Attester Network)** | `attester_verified` | Typed boundary; no production-supported provider, fails closed |
| **T4 (Observer)** | `observer_only` | Not allowed in production |

## Feature Gates

| Feature | Default | Controls |
|---|---|---|
| `frost-crypto` | Off | ZF FROST v3.0.0 real crypto backend (RFC 9591) |
| `cryptoki` | Off | PKCS#11 HSM adapter (fails closed when disabled) |
| `webauthn` | Off | WebAuthn/FIDO2 attestation |
| `groth16` | Off | Groth16/BitVM2 SNARK verification |
| `fedimint-crypto` | Off | Fedimint e-cash blinding / DLEQ |
| `bip110_compliant` | Off | BIP-110 reduced-data validation |

`musig2` (BIP-327) is a default dependency, not feature-gated; its capability
record is still `unsupported` for production.

Without the relevant feature the boundary types validate structurally and return
`ProtocolUnsupported` for all cryptographic execution paths.

## Key

- **Present** — implemented with local tests
- **conditional / unsupported** — production support per the capability ledger
- N/A — not applicable
