# Conclave SDK: Improvement Proposals (v2.0.4)

## 1. FROST Round 2 (Secret Share Distribution)
**Context**: `FrostManager` (v2.0.4) implements RFC 9591 Round 2.
**Improvements**:
- Implemented encrypted secret share generation for participants.
- Added structural verification for received shares.
**Next Steps**:
- Implement Round 3 (Signature Aggregation).
- Integrate with `SettlementEngine` for persistent session state.

## 2. Hardware Attestation (X.509 Hardened)
**Context**: `DeviceIntegrityReport` (v2.0.4) enforces structural X.509 verification.
**Improvements**:
- Integrated `x509-cert` crate for DER parsing.
- Implemented raw public key extraction from certificates.
**Next Steps**:
- Implement full certificate path validation (signatures).
- Integrate with external Attestation Services (e.g., Android Key Attestation).

## 3. Hardened Fedimint Blinding
**Context**: `FedimintAdapter` (v2.0.4) performs bound blinding.
**Improvements**:
- Replaced string-based stubs with SHA-256 bound blinding factors.
- Expanded note model to include unblinded signatures.
**Next Steps**:
- Integrate `fedimint-client-wasm` for real cryptographic blinding/signing.
- Support multiple concurrent federations.

## 4. FDC3 Treasury Handshake
**Context**: `RailProxy` (v2.0.4) supports FDC3 intent resolution.
**Improvements**:
- Deep integration of `fdc3.instrument` into the intent preparation path.
- Verified with cross-chain integration tests.
**Next Steps**:
- Support more complex FDC3 contexts (e.g. `fdc3.position`).
- Implement FDC3 App Directory discovery for solvers.
