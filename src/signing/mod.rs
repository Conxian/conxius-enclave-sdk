//! Enclave-secure multi-chain signing infrastructure.
//!
//! Phase 1 modules:
//! - [`ucs`] — Universal Chain Signer trait (SDK-001) ✅
//! - [`threshold`] — FROST DKG threshold signing (SDK-002) ✅
//! - [`musig2_signing`] — MuSig2 multisig integration (SDK-003) ✅
//! - [`bip322_signing`] — BIP-322 message attestation (SDK-004) ✅
//! - [`bip110_signing`] — BIP-110 enforcement in signing (SDK-007) ✅
//! - [`taproot`] — Taproot utility functions (SDK-008) ✅
//!
//! Phase 2 modules:
//! - [`wasm_runtime`] — WASM signing surface for web consumers ✅
//! - [`statechain_signing`] — Spark statechain vUTXO signing ✅
//! - [`bitvm2_signing`] — BitVM2 challenge/response signing ✅
//! - [`dlc_signing`] — DLC oracle attestation + CET signing ✅
//! - [`lightning_signing`] — BOLT12, BIP-353, LNURL-auth ✅
//! - [`covenant_signing`] — OP_CAT covenants, CTV, vaults ✅
//! - [`zkml_signing`] — ZKML proof commitment + model registration ✅

pub mod bip110_signing;
pub mod bip322_signing;
pub mod bitvm2_signing;
pub mod covenant_signing;
pub mod dlc_signing;
pub mod lightning_signing;
pub mod musig2_signing;
pub mod statechain_signing;
pub mod taproot;
pub mod threshold;
pub mod ucs;
pub mod wasm_runtime;
pub mod zkml_signing;
