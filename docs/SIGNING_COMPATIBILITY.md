# Signing Compatibility Matrix (SDK-010)

> Phase 2, generated 2026-08-07. Tracks which chain/algorithm pairs are
> exposed by which signing backend. These are API/UCS compatibility surfaces,
> not unconditional production/value-bearing support; provider, protocol,
> runtime, review, and release-evidence gates still apply.

## Signing Backend × Chain Family

| Chain Family | Algorithm | UCS Trait | Enclave Signing | FROST Threshold | MuSig2 | BIP-322 |
|---|---|---|---|---|---|---|
| **Bitcoin Taproot** | Schnorr (BIP-340) | ✅ SDK-001 | API surface; gated | ✅ SDK-002 | ✅ SDK-003 | N/A |
| **Bitcoin Legacy** | ECDSA secp256k1 | ✅ SDK-001 | API surface; gated | N/A | N/A | ✅ SDK-004 |
| **Ethereum** | ECDSA secp256k1 | ✅ SDK-001 | API surface; gated | N/A | N/A | N/A |
| **Solana** | Ed25519 | ✅ SDK-001 | API surface; gated | N/A | N/A | N/A |
| **Stacks** | ECDSA secp256k1 | ✅ SDK-001 | API surface; gated | N/A | N/A | N/A |
| **Babylon** | Schnorr delegation | ✅ SDK-001 | Phase 2 UCS surface; gated | N/A | N/A | N/A |
| **RGB** | Bitcoin anchor | ✅ SDK-001 | Phase 2 UCS surface; gated | N/A | N/A | N/A |

## Phase 2+ Signing Modules

| Module | Protocol | Status |
|---|---|---|
| `covenant_signing.rs` | Covenant (OP_CAT) recursive signing | API/UCS surface; gated |
| `dlc_signing.rs` | DLC oracle signing | API/UCS surface; gated |
| `lightning_signing.rs` | Lightning BOLT12 offer signing | API/UCS surface; gated |
| `zkml_signing.rs` | ZKML proof verification signing | API/UCS surface; gated |
| `statechain_signing.rs` | Spark statechain vUTXO signing | API/UCS surface; gated |
| `bitvm2_signing.rs` | BitVM2 challenge/response signing | API/UCS surface; gated |
| `wasm_runtime.rs` | WASM signing surface | API surface; runtime/provider gated |

## Trust Tier Enforcement

| Tier | Required | SDK Support |
|---|---|---|
| **T1 (Sovereign Verified)** | `proof_verified` + hardware attestation | ✅ EnclaveManager |
| **T2 (Hybrid Verified)** | `proof_verified` + secondary verifier | ✅ EnclaveManager |
| **T3 (Attester Network)** | `attester_verified` | ✅ EnclaveManager |
| **T4 (Observer)** | `observer_only` | ❌ Not allowed in production |

## Feature Gates

| Feature | Default | Controls |
|---|---|---|
| `frost-crypto` | Off | ZF FROST v3.0.0 real crypto backend |
| `bip110_compliant` | Off | BIP-110 reduced-data validation |

## Key

- ✅ API surface implemented and scoped tests present
- 🚧 Boundary/quarantine only
- ❌ Not supported
- N/A Not applicable
