//! Enclave-secure multi-chain signing infrastructure.
//!
//! Phase 1 modules:
//! - [`ucs`] — Universal Chain Signer trait (SDK-001) ✅
//! - [`threshold`] — FROST DKG threshold signing (SDK-002) ✅
//! - [`musig2_signing`] — MuSig2 multisig integration (SDK-003) ✅
//! - [`bip322_signing`] — BIP-322 message attestation (SDK-004) ✅
//! - [`bip110_signing`] — BIP-110 enforcement in signing (SDK-007) ✅
//! - [`taproot`] — Taproot utility functions (SDK-008) ✅

pub mod bip110_signing;
pub mod bip322_signing;
pub mod musig2_signing;
pub mod taproot;
pub mod threshold;
pub mod ucs;
