//! Enclave-secure multi-chain signing infrastructure.
//!
//! Phase 1 modules:
//! - [`ucs`] — Universal Chain Signer trait and `EnclaveUniversalSigner` (SDK-001)
//! - [`threshold`] — FROST DKG threshold signing (SDK-002, planned)

pub mod ucs;

// SDK-002: uncomment when implemented
// pub mod threshold;
