//! Hardware attestation verifier backends (Phase 3).
//!
//! Production verifiers that plug into the proof and trust infrastructure:
//! - [`nitro_verifier`] — AWS Nitro TEE (P0: primary deployment target)
//! - [`dstack_verifier`] — Phala dstack research adapter (unavailable; diagnostic parsing only)
//! - [`pkcs11_verifier`] — PKCS#11 HSM/TPM (P1: on-premise hardware)
//! - [`webauthn_verifier`] — WebAuthn/FIDO2 endpoints (P2: mobile/desktop)
//! - [`oidc_verifier`] — OIDC token verification (P1: enterprise auth)

pub mod dstack_verifier;
#[cfg(not(target_arch = "wasm32"))]
pub mod nitro_trust;
#[cfg(not(target_arch = "wasm32"))]
pub mod nitro_verifier;
pub mod oidc_verifier;
pub mod pkcs11_verifier;
pub mod webauthn_verifier;

pub use dstack_verifier::{
    DstackAppPolicy, DstackAttestationDocument, DstackReleaseBinding, PhalaDstackVerifier,
    DSTACK_BINDING_DOMAIN, PHALA_DSTACK_VERIFIER_ID,
};
