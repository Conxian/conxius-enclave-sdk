## Context
Currently, the lib-conclave-sdk is a monolith with hardcoded logic for Changelly, Bisq, and Wormhole. Affiliates are just strings, and assets are unstructured.

## Goals / Non-Goals
- **Goals**: Create a modular architecture that separates Enclave hardware logic from Protocol swap logic. Define structured registries for Businesses and Assets.
- **Non-Goals**: Migrate all existing protocol logic to the new system in this PR (only refactor the core structures).

## Decisions
1. **Business as Cryptographic Identity**: Instead of simple strings, businesses will be identified by public keys, and all affiliate proofs will be signed messages to prevent fraud.
2. **Registry over Strings**: Assets will be objects with chain context and decimal precision, preventing cross-chain address errors.
3. **Rust Traits for Extensibility**: We will use traits like `SovereignRail` and `EnclaveManager` to enable third-party plugins.

## Risks / Trade-offs
- [Risk] -> Increased complexity for new developers.
- [Mitigation] -> Provide "Simple" defaults and comprehensive documentation.

## Migration Plan
1. Create new traits and data structures.
2. Refactor existing `AffiliateManager` and `RailProxy` to use these new structures.
3. Deprecate old string-based APIs.
