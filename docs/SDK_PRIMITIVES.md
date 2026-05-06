# Conclave SDK Primitives

## GTM V1: Hardware-Backed Bitcoin Signing & Policy

The first commercial SDK primitive focuses on binding cryptographic trust anchors to Bitcoin transaction orchestration.

### 1. Capabilities
- **Hardware-Isolated Signing**: Native ECDSA and Schnorr signing within Android StrongBox, Apple Secure Enclave, or Cloud TEE.
- **Policy Enforcement**: Pre-signing validation of transaction intents (e.g., spending limits, recipient allowlists, timelocks).
- **Hardware Attestation**: Cryptographic proof of execution environment integrity (DeviceIntegrityReport).
- **Sovereign Handshake**: A two-phase intent-based protocol (Prepare -> Sign -> Broadcast).

### 2. API Surface
- `generate_key(path)`: Derive a hardware-protected public key.
- `sign_intent(intent)`: Validate and sign a structured transaction intent.
- `verify_attestation(report)`: Verify the integrity of the signing environment.
- `execute_swap(intent, signature, attestation)`: Atomic execution of verified intents.

### 3. Target Integrators
- Institutional Bitcoin Custodians
- Bitcoin-native Fintech Applications
- Sovereign Node Operators
- Multi-party Computation (MPC) Providers (as a hardware-security layer)

### 4. Non-Goals (V1)
- Consumer-facing Wallet UI (SDK only)
- Generic Smart Contract Execution (Bitcoin-stack focus)
- Custodial Asset Management (Strictly non-custodial)
