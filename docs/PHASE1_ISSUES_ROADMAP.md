# PHASE 1: SDK Issue Creation & Discovery

**Status**: 📋 Planning Phase  
**Date**: 2026-07-20  
**Scope**: Hardware enclave SDK alignment with core UCS

## Overview

This document tracks Phase 1 issues for the Enclave SDK. Focuses on **UCS implementation foundation**, **FROST DKG integration**, and **multi-chain signing protocol**.

---

## CONXIUS-ENCLAVE-SDK Issues

### Category: UCS Implementation

#### [SDK-001] Implement UniversalChainSigner Trait from Core
**Type**: Implementation  
**Priority**: 🔴 CRITICAL  
**Depends On**: CORE-001  

**Description**:
Implement the `UniversalChainSigner` trait defined in core library. This is the gateway between enclave signing and multi-chain operations.

**Acceptance Criteria**:
- [ ] Import trait from `lib-conxian-core`
- [ ] Struct: `EnclaveUniversalSigner` implementing the trait
- [ ] Methods for all chain families:
  - Bitcoin (Taproot + Legacy)
  - Stacks (ECDSA secp256k1)
  - Ethereum (ECDSA)
  - Solana (Ed25519)
  - Babylon (BTC delegation)
- [ ] Unit tests for each chain (5+ test cases per chain)
- [ ] Integration tests with `EnclaveManager`

**Files to Create/Modify**:
- `src/signing/ucs.rs` (new)
- `src/lib.rs` (add module)

**Related Code**:
- `src/enclave/mod.rs` (EnclaveManager trait)
- `src/protocol/bitcoin.rs`, `src/protocol/stacks.rs`, etc.

---

#### [SDK-002] FROST DKG Ceremony Integration (Treasury Multisig)
**Type**: Implementation  
**Priority**: 🔴 CRITICAL  
**Depends On**: SDK-001  

**Description**:
Complete FROST Distributed Key Generation ceremony for SAB Treasury 3-of-5 multisig setup. Issue #180 describes requirements.

**Acceptance Criteria**:
- [ ] Struct: `FrostDkgSession` with full lifecycle
- [ ] 4-round ceremony:
  - Round 1: Commitment generation (`generate_commitment()`)
  - Round 2: Share distribution (`distribute_shares()`)
  - Round 3: Share verification (`verify_shares()`)
  - Round 4: Key package generation (`generate_key_package()`)
- [ ] Trait: `ThresholdSigner` for t-of-n signing
- [ ] TEE key storage integration
- [ ] Serialization for cross-ceremony persistence
- [ ] Comprehensive test suite (20+ test cases)
- [ ] Documentation: User guide + API reference

**Files to Create/Modify**:
- `src/protocol/frost.rs` (new)
- `src/signing/threshold.rs` (new)

**Related Issues**:
- #180 (SDK-001 in old tracking)

---

#### [SDK-003] MuSig2 Aggregate Signature Support
**Type**: Implementation  
**Priority**: 🔴 CRITICAL  
**Depends On**: SDK-001, SDK-002  

**Description**:
Extend MuSig2 implementation for multi-signature Bitcoin transactions. Currently functional but needs:
- Proper integration with UCS
- Test coverage for all scenarios
- Documentation

**Acceptance Criteria**:
- [ ] `MuSig2Session` fully integrated with `EnclaveManager`
- [ ] Support for 2-of-2, 2-of-3, 3-of-5 configurations
- [ ] Nonce generation with replay protection
- [ ] Partial signature aggregation
- [ ] Final signature verification
- [ ] 15+ unit tests
- [ ] E2E test with mock Bitcoin transaction

**Files to Modify**:
- `src/protocol/musig2.rs` (enhance)

---

### Category: Multi-Chain Protocol Support

#### [SDK-004] BIP-322 Enclave Integration (Message Signing)
**Type**: Enhancement  
**Priority**: 🟠 HIGH  
**Depends On**: SDK-001  

**Description**:
Integrate BIP-322 universal message signing with enclave attestation. Enable proof-of-ownership for all address types.

**Acceptance Criteria**:
- [ ] `Bip322Enclave` struct with attestation
- [ ] Support all address types:
  - P2PKH (Legacy)
  - P2SH (SegWit wrapped)
  - P2WPKH (Native SegWit)
  - P2WSH (Multi-sig SegWit)
  - P2TR (Taproot)
- [ ] Device attestation included in signature
- [ ] Verification against enclave certificate chain
- [ ] 12+ unit tests

**Files to Modify**:
- `src/protocol/bip322.rs` (enhance with attestation)

---

#### [SDK-005] Babylon BTC Staking Integration
**Type**: Implementation  
**Priority**: 🟠 HIGH  
**Depends On**: SDK-001  

**Description**:
Enable BTC delegation signing for Babylon protocol. Support commitment creation and EOTS (Extractable One-Time Signatures).

**Acceptance Criteria**:
- [ ] Struct: `BabylonDelegation` for staking flow
- [ ] Methods:
  - `create_btc_delegation()` - generates delegation transaction
  - `sign_eots()` - creates EOTS for commitment
  - `verify_delegation()` - validates BTC proof
- [ ] BTC header chain verification hook (from Nexus)
- [ ] 10+ unit tests
- [ ] Integration test with Babylon testnet (optional for Phase 1)

**Files to Create/Modify**:
- `src/protocol/babylon.rs` (new)

---

#### [SDK-006] RGB State Transition Signing
**Type**: Implementation  
**Priority**: 🟠 HIGH  
**Depends On**: SDK-001  

**Description**:
Support RGB protocol state transition signing. Enable asset transfers and contract execution on RGB.

**Acceptance Criteria**:
- [ ] Struct: `RgbTransitionSigner`
- [ ] Methods:
  - `sign_transition()` - creates valid RGB transition
  - `verify_rgb_proof()` - validates against stash
  - `get_rgb_address()` - derive RGB-compatible address
- [ ] Integration with Gateway's RGB adapter (#228)
- [ ] 8+ unit tests
- [ ] Stash resolver integration optional for Phase 1

**Files to Create/Modify**:
- `src/protocol/rgb.rs` (new)

---

### Category: BIP-110 & Protocol Compliance

#### [SDK-007] Enforce BIP-110 in Signing Operations
**Type**: Enhancement  
**Priority**: 🟠 HIGH  
**Depends On**: CORE-004, SDK-001  

**Description**:
Ensure all signing operations respect BIP-110 data limits. Add validation before signing.

**Acceptance Criteria**:
- [ ] Pre-signing checks for:
  - Pushdata ≤ 256 bytes
  - OP_RETURN ≤ 83 bytes
  - ScriptPubKey ≤ 34 bytes
- [ ] Suggestions for optimization
- [ ] Warnings logged with helpful context
- [ ] 10+ test cases for edge cases
- [ ] Documentation: BIP-110 compliance guide

**Files to Modify**:
- `src/protocol/bip110.rs` (enhance)
- All `src/protocol/*.rs` files (add pre-sign checks)

---

#### [SDK-008] Add Taproot Tweak Calculation Utilities
**Type**: Enhancement  
**Priority**: 🟠 HIGH  
**Depends On**: SDK-001, SDK-007  

**Description**:
Complete Taproot tweak utilities for key tweaking and leaf script inclusion.

**Acceptance Criteria**:
- [ ] Functions:
  - `calculate_taproot_output_key()` - internal + external key
  - `tweak_secret_key()` - applies leaf script tweak
  - `validate_tap_leaf()` - ensures valid leaf structure
- [ ] Support for:
  - Pure key path spending
  - Script path spending
  - Complex tapscripts
- [ ] 12+ unit tests
- [ ] Documentation with examples

**Files to Modify/Create**:
- `src/protocol/bitcoin.rs` (enhance TaprootManager)
- `src/signing/taproot_utils.rs` (new)

---

### Category: Testing & Verification

#### [SDK-009] Create Enclave Test Harness
**Type**: Testing  
**Priority**: 🟠 HIGH  
**Depends On**: SDK-001  

**Description**:
Build comprehensive test harness for mocking enclave operations across all protocols.

**Acceptance Criteria**:
- [ ] Mock implementations:
  - `MockEnclaveManager` - simulates hardware
  - `MockAttestationProvider` - creates fake attestations
  - `MockKeyStore` - in-memory key storage
- [ ] Test fixtures for:
  - BTC transactions (all types)
  - Stacks transactions
  - Ethereum transactions
  - Solana transactions
  - FROST ceremonies
  - MuSig2 signing
- [ ] Deterministic nonces for reproducibility
- [ ] CI integration for automated testing

**Files to Create**:
- `tests/harness/mod.rs` (new)
- `tests/harness/mock_enclave.rs` (new)
- `tests/harness/fixtures.rs` (new)

---

#### [SDK-010] Protocol Compatibility Matrix
**Type**: Documentation  
**Priority**: 🟠 HIGH  
**Depends On**: SDK-001 through SDK-008  

**Description**:
Document SDK capability matrix across all protocols, platforms, and enclave types.

**Acceptance Criteria**:
- [ ] Matrix covering:
  - Protocols: Bitcoin, Stacks, Ethereum, Solana, Babylon, Liquid, RGB, DLC
  - Platforms: Android (StrongBox), iOS, Web (WASM), Cloud
  - Enclave types: Hardware TEE, Trusted Execution, Mock
- [ ] Version compatibility
- [ ] Known limitations per combination
- [ ] Upgrade path documentation

**Format**: `docs/COMPATIBILITY_MATRIX.md`

---

### Category: Build & Integration

#### [SDK-011] Dependency Alignment with Core v0.2.12
**Type**: Maintenance  
**Priority**: 🟠 HIGH  
**Depends On**: SDK-001  

**Description**:
Ensure SDK dependencies are synchronized with core library and compatible with gateway/nexus.

**Acceptance Criteria**:
- [ ] Cargo.toml review:
  - bitcoin crate version alignment
  - secp256k1/k256 consistency
  - serde version matching
- [ ] Feature flag compatibility
- [ ] Optional dependencies (core's enclave feature)
- [ ] Documentation: Dependency update process

**Files to Modify**:
- `Cargo.toml`

---

## Summary

### Issues to Create (11 total)

| ID | Title | Priority | Type | Status |
|:---|:------|:--------:|:----:|:-------|
| SDK-001 | Implement UCS Trait | 🔴 | Impl | ⏳ |
| SDK-002 | FROST DKG Integration | 🔴 | Impl | ⏳ |
| SDK-003 | MuSig2 Support | 🔴 | Impl | ⏳ |
| SDK-004 | BIP-322 Attestation | 🟠 | Enh | ⏳ |
| SDK-005 | Babylon Staking | 🟠 | Impl | ⏳ |
| SDK-006 | RGB Transitions | 🟠 | Impl | ⏳ |
| SDK-007 | BIP-110 Enforcement | 🟠 | Enh | ⏳ |
| SDK-008 | Taproot Utils | 🟠 | Enh | ⏳ |
| SDK-009 | Test Harness | 🟠 | Test | ⏳ |
| SDK-010 | Compatibility Matrix | 🟠 | Doc | ⏳ |
| SDK-011 | Dependency Alignment | 🟠 | Maint | ⏳ |

### Dependency Graph

```
CORE-001 (UCS Spec)
    ↓
SDK-001 (Implement UCS)
    ├→ SDK-002 (FROST DKG)
    ├→ SDK-003 (MuSig2)
    ├→ SDK-004 (BIP-322)
    ├→ SDK-005 (Babylon)
    ├→ SDK-006 (RGB)
    └→ SDK-007 (BIP-110)
        └→ SDK-008 (Taproot Utils)
            └→ SDK-009 (Test Harness)
                └→ SDK-010 (Compatibility)
                    └→ SDK-011 (Dependencies)
```

### Next Steps

1. Create all 11 issues in GitHub
2. Link CORE issues as dependencies
3. Schedule architecture review for SDK-001
4. Begin Phase 2 after approval

