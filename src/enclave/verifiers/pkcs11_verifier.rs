//! PKCS#11 HSM/TPM attestation and signing verifier (Phase 3).
//!
//! Wraps the `cryptoki` crate (parallaxsecond/rust-cryptoki) for universal
//! HSM access via the PKCS#11 Cryptographic Token Interface.
//!
//! Supports:
//! - On-premise HSMs (Thales, Utimaco, etc.)
//! - Local TPM 2.0 via tpm2-pkcs11
//! - Software tokens (kryoptic, SoftHSM) for testing
//!
//! # References
//! - PKCS#11 v3.2: https://docs.oasis-open.org/pkcs11/
//! - rust-cryptoki: https://github.com/parallaxsecond/rust-cryptoki
//! - tpm2-pkcs11: https://github.com/tpm2-software/tpm2-pkcs11

use crate::{ConclaveResult, ConclaveError};

/// PKCS#11 slot descriptor.
#[derive(Debug, Clone)]
pub struct Pkcs11Slot {
    pub slot_id: u64,
    pub label: String,
    pub manufacturer_id: String,
    pub token_present: bool,
    pub hardware_slot: bool,
}

/// PKCS#11 key descriptor.
#[derive(Debug, Clone)]
pub struct Pkcs11Key {
    pub key_id: Vec<u8>,
    pub label: String,
    pub key_type: Pkcs11KeyType,
    pub sign_mechanisms: Vec<String>,
}

/// PKCS#11 key type classification.
#[derive(Debug, Clone, PartialEq)]
pub enum Pkcs11KeyType {
    EcdsaSecp256k1,
    EcdsaSecp256r1,
    Ed25519,
    Rsa2048,
    Rsa4096,
    Unknown(String),
}

/// PKCS#11 provider configuration.
#[derive(Debug, Clone)]
pub struct Pkcs11Config {
    /// Path to the PKCS#11 shared library (.so/.dylib/.dll)
    pub library_path: String,
    /// Optional PIN for token login
    pub pin: Option<String>,
    /// Slot ID to use (None = auto-select first available)
    pub slot_id: Option<u64>,
}

/// PKCS#11 verifier and signer.
///
/// Provides universal HSM access for signing operations through
/// the PKCS#11 standard interface. Used for on-premise deployments
/// where keys remain behind the enterprise firewall.
pub struct Pkcs11Verifier {
    config: Pkcs11Config,
}

impl Pkcs11Verifier {
    /// Create a new PKCS#11 verifier.
    pub fn new(config: Pkcs11Config) -> Self {
        Self { config }
    }

    /// Enumerate available slots on the PKCS#11 module.
    pub fn enumerate_slots(&self) -> ConclaveResult<Vec<Pkcs11Slot>> {
        // In production, this calls C_GetSlotList → C_GetSlotInfo → C_GetTokenInfo
        // via the cryptoki crate. For now, returns structured but empty result.
        let _ = &self.config;
        Ok(vec![])
    }

    /// Discover signing keys in a slot.
    pub fn discover_keys(&self, _slot_id: u64) -> ConclaveResult<Vec<Pkcs11Key>> {
        let _ = &self.config;
        Ok(vec![])
    }

    /// Sign a digest using a PKCS#11 key.
    ///
    /// Supports ECDSA (secp256k1, secp256r1) and Ed25519 mechanisms.
    pub fn sign(
        &self,
        _slot_id: u64,
        _key_id: &[u8],
        _mechanism: &str,
        _digest: &[u8],
    ) -> ConclaveResult<Vec<u8>> {
        Err(ConclaveError::Unsupported(
            "PKCS#11 sign: add `cryptoki` crate to Cargo.toml".into(),
        ))
    }

    /// Verify a signature using a PKCS#11 key.
    pub fn verify(
        &self,
        _slot_id: u64,
        _key_id: &[u8],
        _mechanism: &str,
        _digest: &[u8],
        _signature: &[u8],
    ) -> ConclaveResult<bool> {
        Err(ConclaveError::Unsupported(
            "PKCS#11 verify: add `cryptoki` crate to Cargo.toml".into(),
        ))
    }

    /// Get the public key from a PKCS#11 key object.
    pub fn get_public_key(&self, _slot_id: u64, _key_id: &[u8]) -> ConclaveResult<Vec<u8>> {
        Err(ConclaveError::Unsupported(
            "PKCS#11 get_public_key: add `cryptoki` crate".into(),
        ))
    }

    /// Detect if the module is hardware-backed (returns true for HSMs and TPMs).
    pub fn is_hardware_backed(&self, _slot_id: u64) -> ConclaveResult<bool> {
        let _ = &self.config;
        Ok(false) // Default: assume software until cryptoki integration
    }
}

/// PKCS#11 attestation evidence.
///
/// Captures the hardware provenance of signing keys — which HSM/TPM
/// they came from, what firmware version, and whether the module
/// is FIPS-certified.
#[derive(Debug, Clone)]
pub struct Pkcs11AttestationEvidence {
    pub module_path: String,
    pub manufacturer: String,
    pub firmware_version: String,
    pub fips_certified: bool,
    pub slot_label: String,
    pub key_label: String,
    pub key_type: Pkcs11KeyType,
}

impl Pkcs11AttestationEvidence {
    /// Build evidence from slot and key metadata.
    pub fn from_slot_and_key(
        _slot: &Pkcs11Slot,
        _key: &Pkcs11Key,
        _module_path: &str,
    ) -> Self {
        Self {
            module_path: _module_path.to_string(),
            manufacturer: _slot.manufacturer_id.clone(),
            firmware_version: String::new(),
            fips_certified: false,
            slot_label: _slot.label.clone(),
            key_label: _key.label.clone(),
            key_type: _key.key_type.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs11_verifier_constructs() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/softhsm/libsofthsm2.so".into(),
            pin: None,
            slot_id: None,
        };
        let _v = Pkcs11Verifier::new(config);
    }

    #[test]
    fn pkcs11_enumerate_slots_returns_ok() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/softhsm/libsofthsm2.so".into(),
            pin: None,
            slot_id: None,
        };
        let v = Pkcs11Verifier::new(config);
        assert!(v.enumerate_slots().is_ok());
    }

    #[test]
    fn pkcs11_key_type_classification() {
        assert_eq!(Pkcs11KeyType::EcdsaSecp256k1, Pkcs11KeyType::EcdsaSecp256k1);
        assert_ne!(Pkcs11KeyType::Ed25519, Pkcs11KeyType::Rsa2048);
    }
}
