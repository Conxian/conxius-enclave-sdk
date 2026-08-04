# Signing Compatibility Matrix (SDK-010)

> Phase 1, generated 2026-08-03. Tracks which chain/algorithm pairs are
> supported by which signing backend.

## Signing Backend × Chain Family

| Chain Family | Algorithm | UCS Trait | Enclave Signing | FROST Threshold | MuSig2 | BIP-322 |
|---|---|---|---|---|---|---|
| **Bitcoin Taproot** | Schnorr (BIP-340) | ✅ SDK-001 | ✅ value-bearing | ✅ SDK-002 | ✅ SDK-003 | N/A |
| **Bitcoin Legacy** | ECDSA secp256k1 | ✅ SDK-001 | ✅ value-bearing | N/A | N/A | ✅ SDK-004 |
| **Ethereum** | ECDSA secp256k1 | ✅ SDK-001 | ✅ value-bearing | N/A | N/A | N/A |
| **Solana** | Ed25519 | ✅ SDK-001 | ✅ value-bearing | N/A | N/A | N/A |
| **Stacks** | ECDSA secp256k1 | ✅ SDK-001 | ✅ value-bearing | N/A | N/A | N/A |
| **Babylon** | Schnorr delegation | ✅ SDK-001 | 🚧 quarantine | 🚧 planned | 🚧 planned | N/A |
| **RGB** | Bitcoin anchor | 🚧 planned | 🚧 quarantine | N/A | N/A | N/A |

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
