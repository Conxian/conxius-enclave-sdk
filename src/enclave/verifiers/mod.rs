//! Hardware attestation verifier backends (Phase 3).
//!
//! Production verifiers that plug into the proof and trust infrastructure:
//! - [`nitro_verifier`] — AWS Nitro TEE (P0: primary deployment target)
//! - [`pkcs11_verifier`] — PKCS#11 HSM/TPM (P1: on-premise hardware)
//! - [`webauthn_verifier`] — WebAuthn/FIDO2 endpoints (P2: mobile/desktop)
//! - [`oidc_verifier`] — OIDC token verification (P1: enterprise auth)

pub mod nitro_trust;
pub mod nitro_verifier;
pub mod oidc_verifier;
pub mod pkcs11_verifier;
pub mod webauthn_verifier;
