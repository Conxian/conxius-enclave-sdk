# Remediation Report: SDK Core Architecture Alignment

Based on the OpenSpec review of the current codebase against the newly established `sdk-core-architecture` proposal, the following gaps and remediation steps have been identified.

## 1. Business Management
- **Current State**: `BusinessManager` handles partner onboarding, permissioning, and cryptographic attribution.
- **Gap**: None. Successfully refactored from `AffiliateManager`.
- **Remediation**:
    - [x] Rename `AffiliateManager` to `BusinessManager`.
    - [x] Implement `BusinessRegistry` to track partner public keys.
    - [x] Update `AffiliateProof` to `BusinessAttribution` with enhanced metadata.

## 2. Asset Registry
- **Current State**: Structured `AssetRegistry` handles cross-chain assets with decimal precision and validation.
- **Gap**: None.
- **Remediation**:
    - [x] Create `Asset` struct and `AssetRegistry` singleton/provider.
    - [x] Refactor `SwapRequest` to use `AssetIdentifier` instead of `String`.
    - [x] Add `validate_asset_pair` to `RailProxy`.

## 3. Modular Architecture
- **Current State**: Modular `EnclaveManager` and `SovereignRail` traits implemented. `RailProxy` uses a registry pattern.
- **Gap**: None.
- **Remediation**:
    - [x] Formalize `EnclaveManager` trait.
    - [x] Extract `Changelly`, `Bisq`, and `Wormhole` into separate modules implementing a `SovereignRail` trait.
    - [x] Use a registry pattern in `RailProxy` to allow dynamic rail registration.

## 4. Sovereign Handshake
- **Current State**: Handshake updated to include structured asset and business metadata verification.
- **Gap**: None.
- **Remediation**:
    - [x] Update `SwapIntent` to include structured asset and business metadata.
    - [x] Enhance `verify_hardware_integrity` to check business-specific constraints.
