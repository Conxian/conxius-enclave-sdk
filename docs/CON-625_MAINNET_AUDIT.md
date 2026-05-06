# CON-625: Mainnet Readiness Audit (Fail-Open & Simulated Behavior)

## Overview
Audit of `lib-conclave-sdk` for fail-open logic, placeholder persistence, and simulated behavior that could compromise mainnet safety.

## Findings

### 1. Enclave Simulation
- **Status**: **IDENTIFIED & LABELED**.
- **Details**: `CloudEnclave` and `CoreEnclaveManager` currently default to `AttestationLevel::Software`.
- **Mainnet Safety**: The code correctly prevents high-value operations if `AttestationLevel::Software` is reported and `enforce_attestation` is true in `RailProxy`.
- **Remediation**: Production builds must use hardware-bound drivers that report `AttestationLevel::TEE`, `StrongBox`, or `CloudTEE`.

### 2. Rail Implementation
- **Status**: **PRODUCTION READY**.
- **Details**: `ChangellyRail`, `BisqRail`, etc., have been updated to use real `reqwest` calls to the Gateway API. Mock responses have been removed.
- **Fail-Open Check**: No "fail-open" logic found in the request broadcasting layer. If the Gateway is down, the operation fails.

### 3. Attestation Verification
- **Status**: **HARDENED**.
- **Details**: `DeviceIntegrityReport::verify` now strictly requires `is_hardened` (TEE/StrongBox/CloudTEE) and `has_valid_extension`.
- **Note**: The simulation notice in README correctly warns developers about this.

### 4. Placeholder Persistence
- **Status**: **MINIMAL**.
- **Details**: Some "simulated" strings remain in `extension_data` for the software drivers, but these are unreachable in a true hardware-bound implementation.

## Recommendation
- **Pass Status**: **GO (with conditions)**.
- **Conditions**:
    1. Ensure the `enforce_attestation` flag is NEVER disabled in production environments.
    2. Verify that the production Gateway API endpoint is correctly configured and does not itself contain fail-open logic.
