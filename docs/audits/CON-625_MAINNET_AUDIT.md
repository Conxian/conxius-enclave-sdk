# CON-625: Mainnet Readiness Audit (Fail-Open & Simulated Behavior)

> **Historical record.** The current repository-wide production-enablement status is **Beta / conditional**. See [PRODUCTION_ENABLEMENT_AUDIT_2026-07-20.md](./PRODUCTION_ENABLEMENT_AUDIT_2026-07-20.md) and [CAPABILITY_MATRIX.md](../architecture/CAPABILITY_MATRIX.md). The earlier conditional “GO” below must not be treated as current approval.

## Overview
Audit of `conxius-enclave-sdk` for fail-open logic, placeholder persistence, and simulated behavior that could compromise mainnet safety.

## Findings

### 1. Enclave Simulation
- **Status**: **IDENTIFIED & LABELED**.
- **Details**: `CloudEnclave` and `CoreEnclaveManager` currently default to `AttestationLevel::Software` and are development-oriented software drivers, not production hardware-bound implementations.
- **Mainnet Safety**: This historical conclusion covered the intended software-tier check only; the current production-enablement audit found a P0 gap because rail policy does not call the full report verifier and can be configured to bypass enforcement.
- **Remediation**: Production builds must use hardware-bound drivers that report `AttestationLevel::TEE`, `StrongBox`, or `CloudTEE`.

### 2. Rail Implementation
- **Status**: **Historical implementation review; current support is not established**.
- **Details**: `ChangellyRail`, `BisqRail`, etc., have been updated to use real `reqwest` calls to the Gateway API. Mock responses have been removed.
- **Fail-Open Check**: No "fail-open" logic found in the request broadcasting layer. If the Gateway is down, the operation fails.

### 3. Attestation Verification
- **Status**: **HARDENED (with production-driver dependency)**.
- **Details**: `DeviceIntegrityReport::verify` strictly requires `is_hardened` (TEE/StrongBox/CloudTEE) and `has_valid_extension`.
- **Operational note**: This only provides production-grade assurance when the active driver is truly hardware-bound.

### 4. Placeholder Persistence
- **Status**: **MINIMAL**.
- **Details**: Some explicit simulation strings remain in software-driver `extension_data` to make non-production behavior unmistakable.

## Recommendation
- **Pass Status**: **GO (with conditions)**.
- **Conditions**:
    1. Ensure the `enforce_attestation` flag is NEVER disabled in production environments.
    2. Verify that the production Gateway API endpoint is correctly configured and does not itself contain fail-open logic.
    3. Ensure production environments never ship the software-backed driver as the active trust path for high-value operations.
