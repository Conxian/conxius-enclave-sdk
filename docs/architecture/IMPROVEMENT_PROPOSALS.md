# Conclave SDK: Improvement Proposals (v2.0.5)

## 1. FROST Round 3 (Signature Aggregation)
**Context**: `FrostManager` (v2.0.5) implements hardened structural implementation of RFC 9591.
**Improvements**:
- Implemented signature share aggregation with bound message/group public key commitment.
- Hardened Round 1/2 key generation with participant-bound commitments.
**Next Steps**:
- Fully integrate `frost-dalek` or `roast` for production-grade finite field arithmetic.
- Integrate with `SettlementEngine` for persistent session state.

## 2. Hardened Fedimint Blinding
**Context**: `FedimintAdapter` (v2.0.5) performs real cryptographic blinding on Secp256k1.
**Improvements**:
- Transitioned to real Chaumian blinding factors (Scalar/PublicKey tweaks).
- Implemented unblinding verification against simulated federation secret keys.
**Next Steps**:
- Integrate `fedimint-client-wasm` for real-world federation interaction.
- Support multiple concurrent federations.

## 3. Ark Protocol Stateless Recovery (Hardened)
**Context**: `ArkManager` (v2.0.5) supports hardened V-UTXO discovery.
**Improvements**:
- Implemented bound discovery hashes for V-UTXO lookup.
- Hardened gap-limit logic for stateless scans.
**Next Steps**:
- Implement real `reqwest` integration for production ASP APIs.
- Support Ark Round 2 (vTXO tree construction).

## 4. Hardware Attestation (X.509 Hardened)
**Context**: `DeviceIntegrityReport` (v2.0.4) enforces structural X.509 verification.
**Improvements**:
- Integrated `x509-cert` crate for DER parsing.
- Implemented raw public key extraction from certificates.
**Next Steps**:
- Implement full certificate path validation (signatures).
- Integrate with external Attestation Services (e.g., Android Key Attestation).

## 5. FDC3 Treasury Handshake
**Context**: `RailProxy` (v2.0.4) supports FDC3 intent resolution.
**Improvements**:
- Deep integration of `fdc3.instrument` into the intent preparation path.
- Verified with cross-chain integration tests.
**Next Steps**:
- Support more complex FDC3 contexts (e.g. `fdc3.position`).
- Implement FDC3 App Directory discovery for solvers.
