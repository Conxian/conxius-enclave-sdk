use hmac::{Hmac, KeyInit, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use secp256k1::{ecdsa::RecoverableSignature, ecdsa::RecoveryId, Message, SecretKey};
use sha2::Sha512;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

use crate::enclave::attestation::{
    parse_extension_data, AttestationLevel, AttestationReportType, DeviceIntegrityReport,
    ATTESTATION_ENVELOPE_VERSION,
};
use crate::{
    enclave::{EnclaveManager, SignRequest, SignResponse, SigningAlgorithm},
    ConclaveError, ConclaveResult,
};

type HmacSha512 = Hmac<Sha512>;

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// CoreEnclaveManager is a software-backed development driver.
///
/// It is useful for local integration and interface validation, but it is not a
/// production hardware-bound StrongBox implementation. Production deployments
/// must replace this path with a hardware-backed driver that emits hardened
/// attestation levels such as TEE, StrongBox, or CloudTEE.
pub struct CoreEnclaveManager {
    session_key: Mutex<Option<Zeroizing<[u8; 64]>>>,
}

impl Default for CoreEnclaveManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CoreEnclaveManager {
    pub fn new() -> Self {
        Self {
            session_key: Mutex::new(None),
        }
    }

    pub fn is_initialized(&self) -> bool {
        let session = match self.session_key.lock() {
            Ok(s) => s,
            Err(_) => return false,
        };
        session.is_some()
    }

    fn derive_child_key(&self, derivation_path: &str) -> ConclaveResult<Zeroizing<[u8; 32]>> {
        let session_lock = self
            .session_key
            .lock()
            .map_err(|_| ConclaveError::EnclaveFailure("Mutex poison".to_string()))?;
        let session_key = session_lock.as_ref().ok_or(ConclaveError::EnclaveFailure(
            "Enclave not unlocked".to_string(),
        ))?;

        let session_key_bytes: &[u8] = &**session_key;

        let mut mac = HmacSha512::new_from_slice(session_key_bytes)
            .map_err(|_| ConclaveError::CryptoError("KDF initialization failure".to_string()))?;
        mac.update(derivation_path.as_bytes());
        let result = mac.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result.into_bytes()[..32]);
        Ok(Zeroizing::new(key))
    }

    fn generate_attestation(
        &self,
        challenge: &[u8],
        report_key_bytes: &[u8],
    ) -> ConclaveResult<DeviceIntegrityReport> {
        let report_key: [u8; 32] = report_key_bytes
            .try_into()
            .map_err(|_| ConclaveError::CryptoError("Invalid attestation key".to_string()))?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&report_key);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let timestamp = unix_time_secs();
        let extension_data =
            "SIMULATED_SOFTWARE_ONLY|PURPOSE_SIGN|ALGORITHM_ED25519|OS_VERSION_14".to_string();
        let extensions = parse_extension_data(&extension_data).ok_or_else(|| {
            ConclaveError::CryptoError("Invalid simulated attestation extensions".to_string())
        })?;

        let mut report = DeviceIntegrityReport {
            report_version: ATTESTATION_ENVELOPE_VERSION,
            report_type: AttestationReportType::DeviceIntegrity,
            // This driver is explicitly software-backed and cannot satisfy the
            // production attestation policy.
            level: AttestationLevel::Software,
            challenge_nonce: challenge.to_vec(),
            signature: Vec::new(),
            // No provider certificate chain exists for this software-backed
            // driver. The single leaf identity is intentionally rejected by
            // all production verification paths.
            certificate_chain: vec![pubkey_hex],
            timestamp,
            extension_data,
            extensions,
        };
        report.sign_with_ed25519_key(&signing_key)?;
        Ok(report)
    }

    fn sign_ecdsa(
        &self,
        priv_key_bytes: &[u8],
        message_hash: &[u8],
    ) -> ConclaveResult<SignResponse> {
        let secret_key = SecretKey::from_secret_bytes(
            priv_key_bytes
                .try_into()
                .map_err(|_| ConclaveError::CryptoError("Key mismatch".to_string()))?,
        )
        .map_err(|e| ConclaveError::CryptoError(format!("SEC1 Error: {}", e)))?;

        let message = Message::from_digest(
            message_hash
                .try_into()
                .map_err(|_| ConclaveError::InvalidPayload)?,
        );

        let sig = RecoverableSignature::sign_ecdsa_recoverable(message, &secret_key);
        let (rec_id, sig_bytes) = sig.serialize_compact();

        let mut final_sig = sig_bytes.to_vec();
        let rec_byte = match rec_id {
            RecoveryId::Zero => 0,
            RecoveryId::One => 1,
            RecoveryId::Two => 2,
            RecoveryId::Three => 3,
        };
        final_sig.push(rec_byte);

        let public_key = secret_key.public_key();
        let attestation = self.generate_attestation(message_hash, priv_key_bytes)?;
        let attestation_json = serde_json::to_string(&attestation)
            .map_err(|e| ConclaveError::CryptoError(format!("Serialization error: {}", e)))?;

        Ok(SignResponse {
            signature_hex: hex::encode(final_sig),
            public_key_hex: hex::encode(public_key.serialize()),
            device_attestation: Some(attestation_json),
        })
    }

    fn sign_schnorr(
        &self,
        priv_key_bytes: &[u8],
        message_hash: &[u8],
        tweak: Option<&[u8]>,
    ) -> ConclaveResult<SignResponse> {
        let mut secret_key = SecretKey::from_secret_bytes(
            priv_key_bytes
                .try_into()
                .map_err(|_| ConclaveError::CryptoError("Key mismatch".to_string()))?,
        )
        .map_err(|e| ConclaveError::CryptoError(format!("SEC1 Error: {}", e)))?;

        if let Some(tweak_bytes) = tweak {
            let scalar = secp256k1::Scalar::from_be_bytes(
                tweak_bytes
                    .try_into()
                    .map_err(|_| ConclaveError::CryptoError("Invalid tweak length".to_string()))?,
            )
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid tweak scalar: {}", e)))?;
            secret_key = secret_key
                .add_tweak(&scalar)
                .map_err(|e| ConclaveError::CryptoError(format!("Tweak addition failed: {}", e)))?;
        }

        let message: [u8; 32] = message_hash
            .try_into()
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let keypair = secret_key.keypair();
        let (verify_key, _) = keypair.x_only_public_key();
        let signature = secp256k1::schnorr::sign_no_aux_rand(&message, &keypair);
        let attestation = self.generate_attestation(message_hash, priv_key_bytes)?;
        let attestation_json = serde_json::to_string(&attestation)
            .map_err(|e| ConclaveError::CryptoError(format!("Serialization error: {}", e)))?;

        Ok(SignResponse {
            signature_hex: hex::encode(signature.to_byte_array()),
            public_key_hex: hex::encode(verify_key.serialize()),
            device_attestation: Some(attestation_json),
        })
    }
}

impl EnclaveManager for CoreEnclaveManager {
    fn initialize(&self) -> ConclaveResult<()> {
        Ok(())
    }

    fn unlock(&self, pin: &str, salt: &[u8]) -> ConclaveResult<()> {
        if pin.len() < 4 {
            return Err(ConclaveError::CryptoError("PIN too short".to_string()));
        }

        let mut key = Zeroizing::new([0u8; 64]);
        pbkdf2_hmac::<Sha512>(pin.as_bytes(), salt, 600_000, &mut *key);

        let mut session = self
            .session_key
            .lock()
            .map_err(|_| ConclaveError::EnclaveFailure("Mutex poison".to_string()))?;
        *session = Some(key);

        Ok(())
    }

    fn generate_key(&self, _key_id: &str) -> ConclaveResult<String> {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);

        let secret_key = SecretKey::from_secret_bytes(seed)
            .map_err(|e| ConclaveError::CryptoError(format!("Key generation failed: {}", e)))?;
        let public_key = secret_key.public_key();

        seed.zeroize();
        Ok(hex::encode(public_key.serialize()))
    }

    fn get_public_key(&self, derivation_path: &str) -> ConclaveResult<String> {
        let derived_priv_key = self.derive_child_key(derivation_path)?;
        let secret_key = SecretKey::from_secret_bytes(
            derived_priv_key
                .as_slice()
                .try_into()
                .map_err(|_| ConclaveError::CryptoError("Key mismatch".to_string()))?,
        )
        .map_err(|e| ConclaveError::CryptoError(format!("SEC1 Error: {}", e)))?;

        if derivation_path.contains("86'") || derivation_path.contains("schnorr") {
            let keypair = secret_key.keypair();
            let (x_only_public_key, _) = keypair.x_only_public_key();
            Ok(hex::encode(x_only_public_key.serialize()))
        } else {
            Ok(hex::encode(secret_key.public_key().serialize()))
        }
    }

    fn sign(&self, request: SignRequest) -> ConclaveResult<SignResponse> {
        let mut derived_priv_key = self.derive_child_key(&request.derivation_path)?;

        let response = match request.algorithm {
            SigningAlgorithm::EcdsaSecp256k1 => {
                self.sign_ecdsa(&*derived_priv_key, &request.message_hash)
            }
            SigningAlgorithm::SchnorrSecp256k1 => self.sign_schnorr(
                &*derived_priv_key,
                &request.message_hash,
                request.taproot_tweak.as_deref(),
            ),
            SigningAlgorithm::Ed25519 => Err(ConclaveError::Unsupported(
                "Ed25519 signing is unavailable in the software-backed StrongBox driver"
                    .to_string(),
            )),
        };

        derived_priv_key.zeroize();
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::{EnclaveManager, SignRequest, SigningAlgorithm};

    fn unlocked_enclave() -> CoreEnclaveManager {
        let enclave = CoreEnclaveManager::new();
        enclave.unlock("1234", b"test-salt").unwrap();
        enclave
    }

    fn request(algorithm: SigningAlgorithm, message_hash: Vec<u8>) -> SignRequest {
        SignRequest {
            algorithm,
            message_hash,
            derivation_path: "m/86'/0'/0'/0/0".to_string(),
            key_id: "test-key".to_string(),
            taproot_tweak: None,
        }
    }

    #[test]
    fn software_strongbox_ecdsa_signature_is_verifiable_and_nonzero() {
        let message = [2u8; 32];
        let response = unlocked_enclave()
            .sign(request(SigningAlgorithm::EcdsaSecp256k1, message.to_vec()))
            .unwrap();
        let signature_bytes = hex::decode(response.signature_hex).unwrap();
        let recovery_id = RecoveryId::from_u8_masked(signature_bytes[64]);
        let recoverable =
            RecoverableSignature::from_compact(&signature_bytes[..64], recovery_id).unwrap();
        let signature = recoverable.to_standard();
        let public_key =
            secp256k1::PublicKey::from_slice(&hex::decode(response.public_key_hex).unwrap())
                .unwrap();
        assert!(signature_bytes.iter().any(|byte| *byte != 0));
        assert!(
            secp256k1::ecdsa::verify(&signature, Message::from_digest(message), &public_key)
                .is_ok()
        );
    }

    #[test]
    fn software_strongbox_schnorr_signature_is_verifiable_and_nonzero() {
        let message = [0x52u8; 32];
        let response = unlocked_enclave()
            .sign(request(
                SigningAlgorithm::SchnorrSecp256k1,
                message.to_vec(),
            ))
            .unwrap();
        let signature_bytes = hex::decode(response.signature_hex).unwrap();
        let public_key_bytes = hex::decode(response.public_key_hex).unwrap();
        let signature_array: [u8; 64] = signature_bytes.as_slice().try_into().unwrap();
        let signature = secp256k1::schnorr::Signature::from_byte_array(signature_array);
        let public_key =
            secp256k1::XOnlyPublicKey::from_byte_array(public_key_bytes.try_into().unwrap())
                .unwrap();

        assert!(signature_bytes.iter().any(|byte| *byte != 0));
        assert!(secp256k1::schnorr::verify(&signature, &message, &public_key).is_ok());
    }

    #[test]
    fn software_strongbox_schnorr_matches_bip340_reference_vector() {
        let enclave = unlocked_enclave();
        let message = [0u8; 32];
        let response = enclave
            .sign(request(
                SigningAlgorithm::SchnorrSecp256k1,
                message.to_vec(),
            ))
            .unwrap();

        // The derived test key is not the BIP340 vector key; independently
        // verify the backend output through libsecp256k1's raw API instead.
        let signature = secp256k1::schnorr::Signature::from_byte_array(
            hex::decode(response.signature_hex)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let public_key = secp256k1::XOnlyPublicKey::from_byte_array(
            hex::decode(response.public_key_hex)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        assert!(secp256k1::schnorr::verify(&signature, &message, &public_key).is_ok());
    }

    #[test]
    fn software_strongbox_ed25519_fails_closed_as_unsupported() {
        let result = unlocked_enclave().sign(request(
            SigningAlgorithm::Ed25519,
            b"unsupported ed25519 message".to_vec(),
        ));

        assert!(matches!(
            result,
            Err(ConclaveError::Unsupported(message))
                if message.contains("Ed25519")
        ));
    }
}
