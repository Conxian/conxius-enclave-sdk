# Changelog

## [2.0.7] - 2026-07-05

### Added
- Support for joining Fedimint federations via invite codes in `FedimintAdapter`.
- Implementation of binary vTXO tree construction in `ArkManager` for multi-party exits.
- v2.0.7 alignment in `GAP_SCORECARD.md`.

### Changed
- Hardened Secp256k1 cryptographic operations in Fedimint nexus adapter.

## [2.0.6] - 2026-05-24

### Added
- Multi-federation support in `FedimintAdapter` with federation registration logic.
- Structural verification for OP_CAT (`BIP-347`) recursive invariants in `CovenantManager`.
- Hardened stateless recovery scan in `ArkManager` with safety boundaries and gap limit validation.
- WASM bindings for the new hardened features.

### Changed
- Refactored `FedimintAdapter` to use `Default` trait and registry-based architecture.

### Fixed
- Improved error paths and validation in Ark V-UTXO discovery.

## [2.0.5] - 2026-05-18

### Added
- Hardened FROST Round 3 signature share aggregation.
- Real Secp256k1-based Chaumian blinding in `FedimintAdapter`.
