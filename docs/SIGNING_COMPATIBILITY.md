# Signing Compatibility Matrix (SDK-010)

> Phase 2, generated 2026-08-07. Tracks which chain/algorithm pairs are
> supported by which signing backend. All 13 signing modules are complete.

## Signing Backend × Chain Family

| Chain Family | Algorithm | UCS Trait | Enclave Signing | FROST Threshold | MuSig2 | BIP-322 |
|---|---|---|---|---|---|---|
| **Bitcoin Taproot** | Schnorr (BIP-340) | ✅ SDK-001 | ✅ value-bearing | ✅ SDK-002 | ✅ SDK-003 | N/A |
| **Bitcoin Legacy** | ECDSA secp256k1 | ✅ SDK-001 | ✅ value-bearing | N/A | N/A | ✅ SDK-004 |
| **Ethereum** | ECDSA secp256k1 | ✅ SDK-001 | ✅ value-bearing | N/A | N/A | N/A |
| **Solana** | Ed25519 | ✅ SDK-001 | ✅ value-bearing | N/A | N/A | N/A |
| **Stacks** | ECDSA secp256k1 | ✅ SDK-001 | ✅ value-bearing | N/A | N/A | N/A |
| **Babylon** | Schnorr delegation | ✅ SDK-001 | ✅ Phase 2 done | N/A | N/A | N/A |
| **RGB** | Bitcoin anchor | ✅ SDK-001 | ✅ Phase 2 done | N/A | N/A | N/A |

## Phase 2+ Signing Modules

| Module | Protocol | Status |
|---|---|---|
| `covenant_signing.rs` | Covenant (OP_CAT) recursive signing | ✅ |
| `dlc_signing.rs` | DLC oracle signing | ✅ |
| `lightning_signing.rs` | Lightning BOLT12 offer signing | ✅ |
| `zkml_signing.rs` | ZKML proof verification signing | ✅ |
| `statechain_signing.rs` | Spark statechain vUTXO signing | ✅ |
| `bitvm2_signing.rs` | BitVM2 challenge/response signing | ✅ |
| `wasm_runtime.rs` | WASM signing surface | ✅ |

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

- ✅ Implemented and tested
- 🚧 Boundary/quarantine only
- ❌ Not supported
- N/A Not applicable
