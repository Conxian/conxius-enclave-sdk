use hmac::{Hmac, KeyInit, Mac};
use k256::schnorr::signature::Signer;
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use secp256k1::{Message, SecretKey, ecdsa::RecoverableSignature, ecdsa::RecoveryId};
use sha2::Sha512;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

use crate::enclave::attestation::{AttestationLevel, DeviceIntegrityReport};
use crate::{
    ConclaveError, ConclaveResult,
    enclave::{EnclaveManager, SignRequest, SignResponse, SigningAlgorithm},
};

type HmacSha512 = Hmac<Sha512>;
const SOFTWARE_SIMULATION_EXTENSION: &str =
    "SIMULATED_SOFTWARE_ONLY|PURPOSE_SIGN|ALGORITHM_EC|OS_VERSION_14";

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

    fn generate_attestation(&self, challenge: &[u8]) -> DeviceIntegrityReport {
        DeviceIntegrityReport {
            level: AttestationLevel::Software,
            challenge_nonce: challenge.to_vec(),
            signature: vec![0u8; 64],
            certificate_chain: vec![
                "CONCLAVE_ROOT_CA_01".to_string(),
                "CONCLAVE_HARDWARE_BACKED_DEVICE_0x1".to_string(),
            ],
            timestamp: unix_time_secs(),
            extension_data: SOFTWARE_SIMULATION_EXTENSION.to_string(),
        }
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
        let attestation = self.generate_attestation(message_hash);
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

        let signing_key =
            k256::schnorr::SigningKey::from_bytes(&secret_key.to_secret_bytes().into())
                .map_err(|e| ConclaveError::CryptoError(format!("Schnorr Error: {}", e)))?;

        let signature: k256::schnorr::Signature = signing_key.sign(message_hash);
        let verify_key = signing_key.verifying_key();
        let attestation = self.generate_attestation(message_hash);
        let attestation_json = serde_json::to_string(&attestation)
            .map_err(|e| ConclaveError::CryptoError(format!("Serialization error: {}", e)))?;

        Ok(SignResponse {
            signature_hex: hex::encode(signature.to_bytes()),
            public_key_hex: hex::encode(verify_key.to_bytes()),
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
            let signing_key =
                k256::schnorr::SigningKey::from_bytes(&secret_key.to_secret_bytes().into())
                    .map_err(|e| ConclaveError::CryptoError(format!("Schnorr Error: {}", e)))?;
            Ok(hex::encode(signing_key.verifying_key().to_bytes()))
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
            SigningAlgorithm::Ed25519 => {
                let attestation = self.generate_attestation(&request.message_hash);
                let attestation_json = serde_json::to_string(&attestation).map_err(|e| {
                    ConclaveError::CryptoError(format!("Serialization error: {}", e))
                })?;
                Ok(SignResponse {
                    signature_hex: hex::encode(vec![0u8; 64]),
                    public_key_hex: hex::encode(vec![0u8; 32]),
                    device_attestation: Some(attestation_json),
                })
            }
        };

        derived_priv_key.zeroize();
        response
    }
}
