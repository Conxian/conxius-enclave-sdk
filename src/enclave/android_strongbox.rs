use hmac::{Hmac, Mac};
use k256::schnorr::signature::Signer;
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use secp256k1::{
    Message, PublicKey, Secp256k1, SecretKey, ecdsa::RecoverableSignature, ecdsa::RecoveryId,
};
use sha2::Sha512;
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

use crate::enclave::attestation::{AttestationLevel, DeviceIntegrityReport};
use crate::{
    ConclaveError, ConclaveResult,
    enclave::{SignRequest, SignResponse},
};

type HmacSha512 = Hmac<Sha512>;

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

    pub fn derive_session_key(&self, pin: &str, salt: &[u8]) -> ConclaveResult<()> {
        if pin.len() < 4 {
            return Err(ConclaveError::CryptoError("PIN too short".to_string()));
        }

        let mut key = [0u8; 64];
        pbkdf2_hmac::<Sha512>(pin.as_bytes(), salt, 600_000, &mut key);

        let mut session = self
            .session_key
            .lock()
            .map_err(|_| ConclaveError::EnclaveFailure("Mutex poison".to_string()))?;
        *session = Some(Zeroizing::new(key));

        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        let session = self.session_key.lock().unwrap();
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

        // Access the inner array of Zeroizing
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
            level: AttestationLevel::StrongBox,
            challenge_nonce: challenge.to_vec(),
            signature: vec![0u8; 64],
            certificate_chain: vec![
                "CONCLAVE_ROOT_CA_01".to_string(),
                "CONCLAVE_HARDWARE_BACKED_DEVICE_0x1".to_string(),
            ],
            timestamp: 1710000000,
            extension_data: "PURPOSE_SIGN|ALGORITHM_EC|OS_VERSION_14".to_string(),
        }
    }

    fn sign_ecdsa(
        &self,
        priv_key_bytes: &[u8],
        message_hash: &[u8],
    ) -> ConclaveResult<SignResponse> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_byte_array(
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

        let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(message, &secret_key);
        let (rec_id, sig_bytes) = sig.serialize_compact();

        let mut final_sig = sig_bytes.to_vec();
        let rec_byte = if rec_id == RecoveryId::from_u8_masked(0) {
            0u8
        } else if rec_id == RecoveryId::from_u8_masked(1) {
            1u8
        } else if rec_id == RecoveryId::from_u8_masked(2) {
            2u8
        } else if rec_id == RecoveryId::from_u8_masked(3) {
            3u8
        } else {
            0u8
        };
        final_sig.push(rec_byte);

        let public_key = secret_key.public_key(&secp);
        let attestation = self.generate_attestation(message_hash);

        Ok(SignResponse {
            signature_hex: hex::encode(final_sig),
            public_key_hex: hex::encode(public_key.serialize()),
            device_attestation: Some(serde_json::to_string(&attestation).unwrap_or_default()),
        })
    }

    fn sign_schnorr(
        &self,
        priv_key_bytes: &[u8],
        message_hash: &[u8],
        tweak: Option<&[u8]>,
    ) -> ConclaveResult<SignResponse> {
        let mut secret_key = SecretKey::from_byte_array(
            priv_key_bytes
                .try_into()
                .map_err(|_| ConclaveError::CryptoError("Key mismatch".to_string()))?,
        )
        .map_err(|e| ConclaveError::CryptoError(format!("SEC1 Error: {}", e)))?;

        // Apply Taproot Tweak if provided (BIP341)
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
            k256::schnorr::SigningKey::from_bytes(secret_key.secret_bytes().as_slice())
                .map_err(|e| ConclaveError::CryptoError(format!("Schnorr Error: {}", e)))?;

        let signature: k256::schnorr::Signature = signing_key.sign(message_hash);
        let verify_key = signing_key.verifying_key();
        let attestation = self.generate_attestation(message_hash);

        Ok(SignResponse {
            signature_hex: hex::encode(signature.to_bytes()),
            public_key_hex: hex::encode(verify_key.to_bytes()),
            device_attestation: Some(serde_json::to_string(&attestation).unwrap_or_default()),
        })
    }
}

impl crate::enclave::EnclaveManager for CoreEnclaveManager {
    fn initialize(&self) -> ConclaveResult<()> {
        Ok(())
    }

    fn generate_key(&self, _key_id: &str) -> ConclaveResult<String> {
        // Fix: Zero Secret Egress violation. Raw seeds must not leave the enclave.
        // In a production StrongBox implementation, this would persist the key in
        // hardware and return a handle/alias. For this mock, we return the public key.
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_byte_array(seed)
            .map_err(|e| ConclaveError::CryptoError(format!("Key generation failed: {}", e)))?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        seed.zeroize();
        Ok(hex::encode(public_key.serialize()))
    }

    fn get_public_key(&self, derivation_path: &str) -> ConclaveResult<String> {
        let derived_priv_key = self.derive_child_key(derivation_path)?;
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_byte_array(
            derived_priv_key
                .as_slice()
                .try_into()
                .map_err(|_| ConclaveError::CryptoError("Key mismatch".to_string()))?,
        )
        .map_err(|e| ConclaveError::CryptoError(format!("SEC1 Error: {}", e)))?;

        if derivation_path.contains("86'") || derivation_path.contains("schnorr") {
            let signing_key =
                k256::schnorr::SigningKey::from_bytes(secret_key.secret_bytes().as_slice())
                    .map_err(|e| ConclaveError::CryptoError(format!("Schnorr Error: {}", e)))?;
            Ok(hex::encode(signing_key.verifying_key().to_bytes()))
        } else {
            Ok(hex::encode(secret_key.public_key(&secp).serialize()))
        }
    }

    fn sign(&self, request: SignRequest) -> ConclaveResult<SignResponse> {
        if request.message_hash.len() != 32 {
            return Err(ConclaveError::InvalidPayload);
        }

        let mut derived_priv_key = self.derive_child_key(&request.derivation_path)?;

        let response = if request.derivation_path.contains("86'")
            || request.derivation_path.contains("schnorr")
        {
            self.sign_schnorr(
                &*derived_priv_key,
                &request.message_hash,
                request.taproot_tweak.as_deref(),
            )
        } else {
            self.sign_ecdsa(&*derived_priv_key, &request.message_hash)
        };

        derived_priv_key.zeroize();
        response
    }
}
