# Remediation Report: SDK Core Architecture Alignment

Based on the OpenSpec review of the current codebase against the newly established `sdk-core-architecture` proposal, the following gaps and remediation steps have been identified.

## 1. Business Management
- **Current State**: `AffiliateManager` uses simple strings and a basic signing mechanism.
- **Gap**: Missing lifecycle management, permissioning, and enclave-backed business identities.
- **Remediation**:
    - [ ] Rename `AffiliateManager` to `BusinessManager`.
    - [ ] Implement `BusinessRegistry` to track partner public keys.
    - [ ] Update `AffiliateProof` to `BusinessAttribution` with enhanced metadata.

## 2. Asset Registry
- **Current State**: Assets are represented as raw strings (`"BTC"`, `"ETH"`) in `SwapRequest`.
- **Gap**: No validation of decimals, chain IDs, or asset status. High risk of cross-chain address collisions.
- **Remediation**:
    - [ ] Create `Asset` struct and `AssetRegistry` singleton/provider.
    - [ ] Refactor `SwapRequest` to use `AssetIdentifier` instead of `String`.
    - [ ] Add `validate_asset_pair` to `RailProxy`.

## 3. Modular Architecture
- **Current State**: `CoreEnclaveManager` is hardcoded. `RailProxy` has an enum-based dispatch for rails.
- **Gap**: Adding a new hardware enclave or a new bridge requires core SDK modifications.
- **Remediation**:
    - [ ] Formalize `EnclaveManager` trait.
    - [ ] Extract `Changelly`, `Bisq`, and `Wormhole` into separate modules implementing a `SovereignRail` trait.
    - [ ] Use a registry pattern in `RailProxy` to allow dynamic rail registration.

## 4. Sovereign Handshake
- **Current State**: Basic prepare/sign/broadcast flow exists.
- **Gap**: Lacks explicit verification of business and asset context within the enclave signing boundary.
- **Remediation**:
    - [ ] Update `SwapIntent` to include structured asset and business metadata.
    - [ ] Enhance `verify_hardware_integrity` to check business-specific constraints.
