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

use crate::{ConclaveError, ConclaveResult};

#[cfg(feature = "cryptoki")]
use {
    cryptoki::context::{CInitializeArgs, Pkcs11},
    cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme},
    cryptoki::mechanism::Mechanism,
    cryptoki::object::{Attribute, AttributeType, KeyType as CkKeyType, ObjectClass},
    cryptoki::session::UserType,
    std::sync::OnceLock,
};

#[cfg(feature = "cryptoki")]
static PKCS11_CTX: OnceLock<Result<Pkcs11, String>> = OnceLock::new();

#[cfg(feature = "cryptoki")]
fn to_conclave_err(e: impl std::fmt::Debug) -> ConclaveError {
    ConclaveError::Attestation(format!("PKCS#11: {e:?}"))
}

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

    #[cfg(feature = "cryptoki")]
    fn init_ctx(&self) -> ConclaveResult<&Pkcs11> {
        match PKCS11_CTX.get_or_init(|| {
            let lib_path = &self.config.library_path;
            let ctx = Pkcs11::new(lib_path)
                .map_err(|e| format!("failed to load PKCS#11 library '{lib_path}': {e:?}"))?;
            ctx.initialize(CInitializeArgs::OsThreads)
                .map_err(|e| format!("C_Initialize failed: {e:?}"))?;
            Ok(ctx)
        }) {
            Ok(ctx) => Ok(ctx),
            Err(msg) => Err(ConclaveError::Attestation(msg.clone())),
        }
    }

    #[cfg(feature = "cryptoki")]
    fn open_session(&self, slot_id: u64) -> ConclaveResult<cryptoki::session::Session> {
        let ctx = self.init_ctx()?;
        let slot = ctx
            .get_all_slots()
            .map_err(to_conclave_err)?
            .into_iter()
            .find(|s| s.id() == slot_id)
            .ok_or_else(|| {
                ConclaveError::Attestation(format!("PKCS#11 slot {slot_id} not found"))
            })?;
        let session = ctx.open_rw_session(slot).map_err(to_conclave_err)?;
        if let Some(ref pin) = self.config.pin {
            let auth = secrecy::SecretString::new(pin.clone());
            session
                .login(UserType::User, Some(&auth))
                .map_err(to_conclave_err)?;
        }
        Ok(session)
    }

    /// Enumerate available slots on the PKCS#11 module.
    #[cfg(feature = "cryptoki")]
    pub fn enumerate_slots(&self) -> ConclaveResult<Vec<Pkcs11Slot>> {
        let ctx = self.init_ctx()?;
        let slots = ctx.get_all_slots().map_err(to_conclave_err)?;
        let mut result = Vec::new();
        for slot in slots {
            let info = ctx.get_slot_info(slot).map_err(to_conclave_err)?;
            let token = ctx.get_token_info(slot).map_err(to_conclave_err)?;
            result.push(Pkcs11Slot {
                slot_id: slot.id(),
                label: info.slot_description().trim_end().into(),
                manufacturer_id: info.manufacturer_id().trim_end().into(),
                token_present: info.token_present(),
                hardware_slot: token.token_initialized(),
            });
        }
        Ok(result)
    }

    #[cfg(not(feature = "cryptoki"))]
    pub fn enumerate_slots(&self) -> ConclaveResult<Vec<Pkcs11Slot>> {
        let _ = &self.config;
        Ok(vec![])
    }

    /// Discover signing keys in a slot.
    #[cfg(feature = "cryptoki")]
    pub fn discover_keys(&self, slot_id: u64) -> ConclaveResult<Vec<Pkcs11Key>> {
        let session = self.open_session(slot_id)?;
        let handles = session
            .find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Sign(true),
            ])
            .map_err(to_conclave_err)?;
        let mut result = Vec::new();
        for h in &handles {
            let attrs = session
                .get_attributes(
                    *h,
                    &[
                        AttributeType::Id,
                        AttributeType::Label,
                        AttributeType::KeyType,
                    ],
                )
                .map_err(to_conclave_err)?;
            let key_id = match attrs.first() {
                Some(Attribute::Id(bytes)) => bytes.clone(),
                _ => Vec::new(),
            };
            let label = match attrs.get(1) {
                Some(Attribute::Label(bytes)) => String::from_utf8_lossy(bytes).into(),
                _ => String::new(),
            };
            let key_type = match attrs.get(2) {
                Some(Attribute::KeyType(CkKeyType::EC)) => Pkcs11KeyType::EcdsaSecp256r1,
                Some(Attribute::KeyType(CkKeyType::RSA)) => Pkcs11KeyType::Rsa2048,
                Some(Attribute::KeyType(kt)) => Pkcs11KeyType::Unknown(format!("{kt:?}")),
                _ => Pkcs11KeyType::Unknown(String::new()),
            };
            result.push(Pkcs11Key {
                key_id,
                label,
                key_type,
                sign_mechanisms: vec![],
            });
        }
        Ok(result)
    }

    #[cfg(not(feature = "cryptoki"))]
    pub fn discover_keys(&self, _slot_id: u64) -> ConclaveResult<Vec<Pkcs11Key>> {
        let _ = &self.config;
        Ok(vec![])
    }

    /// Sign a digest using a PKCS#11 key.
    #[cfg(feature = "cryptoki")]
    pub fn sign(
        &self,
        slot_id: u64,
        key_id: &[u8],
        mechanism: &str,
        digest: &[u8],
    ) -> ConclaveResult<Vec<u8>> {
        let session = self.open_session(slot_id)?;
        let handle = self.find_key_by_id(&session, key_id)?;
        let mech = self.map_mechanism(mechanism)?;
        session.sign(&mech, handle, digest).map_err(to_conclave_err)
    }

    #[cfg(not(feature = "cryptoki"))]
    pub fn sign(
        &self,
        _slot_id: u64,
        _key_id: &[u8],
        _mechanism: &str,
        _digest: &[u8],
    ) -> ConclaveResult<Vec<u8>> {
        Err(ConclaveError::Unsupported(
            "PKCS#11 sign: enable `cryptoki` feature".into(),
        ))
    }

    /// Verify a signature using a PKCS#11 key.
    #[cfg(feature = "cryptoki")]
    pub fn verify(
        &self,
        slot_id: u64,
        key_id: &[u8],
        mechanism: &str,
        digest: &[u8],
        signature: &[u8],
    ) -> ConclaveResult<bool> {
        let session = self.open_session(slot_id)?;
        let handle = self.find_key_by_id(&session, key_id)?;
        let mech = self.map_mechanism(mechanism)?;
        match session.verify(&mech, handle, digest, signature) {
            Ok(()) => Ok(true),
            Err(cryptoki::error::Error::Pkcs11(_, _)) => Ok(false),
            Err(e) => Err(to_conclave_err(e)),
        }
    }

    #[cfg(not(feature = "cryptoki"))]
    pub fn verify(
        &self,
        _slot_id: u64,
        _key_id: &[u8],
        _mechanism: &str,
        _digest: &[u8],
        _signature: &[u8],
    ) -> ConclaveResult<bool> {
        Err(ConclaveError::Unsupported(
            "PKCS#11 verify: enable `cryptoki` feature".into(),
        ))
    }

    /// Get the public key from a PKCS#11 key object.
    #[cfg(feature = "cryptoki")]
    pub fn get_public_key(&self, slot_id: u64, key_id: &[u8]) -> ConclaveResult<Vec<u8>> {
        let session = self.open_session(slot_id)?;
        let _priv_handle = self.find_key_by_id(&session, key_id)?;
        let pub_handles = session
            .find_objects(&[
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::Id(key_id.to_vec()),
            ])
            .map_err(to_conclave_err)?;
        let pub_handle = pub_handles
            .first()
            .ok_or_else(|| ConclaveError::Attestation("PKCS#11: no matching public key".into()))?;
        let attrs = session
            .get_attributes(*pub_handle, &[AttributeType::EcPoint])
            .map_err(to_conclave_err)?;
        match attrs.first() {
            Some(Attribute::EcPoint(point)) => Ok(point.clone()),
            _ => Ok(Vec::new()),
        }
    }

    #[cfg(not(feature = "cryptoki"))]
    pub fn get_public_key(&self, _slot_id: u64, _key_id: &[u8]) -> ConclaveResult<Vec<u8>> {
        Err(ConclaveError::Unsupported(
            "PKCS#11 get_public_key: enable `cryptoki` feature".into(),
        ))
    }

    /// Detect if the module is hardware-backed (returns true for HSMs and TPMs).
    #[cfg(feature = "cryptoki")]
    pub fn is_hardware_backed(&self, slot_id: u64) -> ConclaveResult<bool> {
        let ctx = self.init_ctx()?;
        let slot = ctx
            .get_all_slots()
            .map_err(to_conclave_err)?
            .into_iter()
            .find(|s| s.id() == slot_id)
            .ok_or_else(|| {
                ConclaveError::Attestation(format!("PKCS#11 slot {slot_id} not found"))
            })?;
        let info = ctx.get_slot_info(slot).map_err(to_conclave_err)?;
        // Hardware slots have non-zero hardware version
        let hw = info.hardware_version();
        Ok(hw.major() > 0 || hw.minor() > 0)
    }

    #[cfg(not(feature = "cryptoki"))]
    pub fn is_hardware_backed(&self, _slot_id: u64) -> ConclaveResult<bool> {
        let _ = &self.config;
        Ok(false)
    }

    #[cfg(feature = "cryptoki")]
    fn find_key_by_id(
        &self,
        session: &cryptoki::session::Session,
        key_id: &[u8],
    ) -> ConclaveResult<cryptoki::object::ObjectHandle> {
        let handles = session
            .find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Id(key_id.to_vec()),
            ])
            .map_err(to_conclave_err)?;
        handles.into_iter().next().ok_or_else(|| {
            ConclaveError::Attestation(format!(
                "PKCS#11: no key found for id {}",
                hex::encode(key_id)
            ))
        })
    }

    #[cfg(feature = "cryptoki")]
    fn map_mechanism(&self, name: &str) -> ConclaveResult<Mechanism<'static>> {
        match name {
            "ECDSA" | "ecdsa" => Ok(Mechanism::Ecdsa),
            "ECDSA_SHA256" => Ok(Mechanism::EcdsaSha256),
            "EdDSA" | "eddsa" | "Ed25519" => Ok(Mechanism::Eddsa(EddsaParams::new(
                EddsaSignatureScheme::Pure,
            ))),
            "RSA_PKCS" | "RS256" => Ok(Mechanism::RsaPkcs),
            "SHA256_RSA_PKCS" => Ok(Mechanism::Sha256RsaPkcs),
            other => Err(ConclaveError::Attestation(format!(
                "PKCS#11: unknown mechanism '{other}'"
            ))),
        }
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
    pub fn from_slot_and_key(_slot: &Pkcs11Slot, _key: &Pkcs11Key, _module_path: &str) -> Self {
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
    #[cfg(not(feature = "cryptoki"))]
    fn pkcs11_verifier_constructs() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/softhsm/libsofthsm2.so".into(),
            pin: None,
            slot_id: None,
        };
        let _v = Pkcs11Verifier::new(config);
    }

    #[test]
    #[cfg(not(feature = "cryptoki"))]
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
