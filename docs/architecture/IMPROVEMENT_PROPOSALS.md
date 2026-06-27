# Conclave SDK: Improvement Proposals (v2.0.2)

## 1. BIP-322 Universal Message Signing (Hardened)
**Context**: Structural verification logic implemented in v2.0.2.
**Improvements**:
- Successfully integrated virtual 'to_spend' and 'to_sign' transaction construction.
- Implemented SegWit (v0 and v1) support for proof-of-ownership.
**Next Steps**:
- Implement "Full" BIP-322 verification (script engine integration).
- Add support for P2PKH and P2SH legacy address verification.

## 2. FROST DKG Round 1
**Context**: `FrostManager` (v2.0.1) implements RFC 9591 Round 1.
**Improvements**:
- Implemented commitment and PoK generation for DKG Round 1.
**Next Steps**:
- Implement Round 2 (Secret Share Distribution) and Round 3 (Signature Aggregation).
- Integrate with `SettlementEngine` for persistent session state.

## 3. Fedimint OPR (Hardened)
**Context**: `FedimintAdapter` (v2.0.1) performs local blinding.
**Improvements**:
- Implemented structural OPR (Oblivious Proof of Reserve) verification.
**Next Steps**:
- Integrate `fedimint-client-wasm` for real cryptographic blinding/signing.
- Support multiple concurrent federations for high-availability liquidity.

## 4. Hardware-Bound Attestation (Hardened)
**Context**: `DeviceIntegrityReport` (v2.0.1) enforces root trust.
**Improvements**:
- Added `TRUSTED_ROOTS` registry and verified root-of-trust.
- Enforced `HARDWARE_BACKED` requirements for high trust tiers.
**Next Steps**:
- Implement full X.509 DER parsing for certificate chains.
- Integrate with external Attestation Services (e.g., Android Key Attestation).
