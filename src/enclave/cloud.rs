use crate::enclave::attestation::{AttestationLevel, DeviceIntegrityReport};
use crate::{
    ConclaveError, ConclaveResult,
    enclave::{EnclaveManager, SignRequest, SignResponse, SigningAlgorithm},
};
use ed25519_dalek::{Signer, SigningKey};
use rand::Rng;
use secp256k1::{Message, SecretKey};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

const SIMULATED_KMS_KEYGEN_MAX_ATTEMPTS: usize = 1024;

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct CloudEnclave {
    pub kms_endpoint: String,
    local_dev_key_bytes: Option<Zeroizing<[u8; 32]>>,
    simulated_kms_key_bytes: Zeroizing<[u8; 32]>,
}

impl CloudEnclave {
    pub fn new(kms_endpoint: String) -> ConclaveResult<Self> {
        let simulated_kms_key_bytes = Self::generate_simulated_kms_key_bytes()?;
        Ok(Self {
            kms_endpoint,
            local_dev_key_bytes: None,
            simulated_kms_key_bytes,
        })
    }

    pub fn with_dev_key(mut self, key_bytes: [u8; 32]) -> ConclaveResult<Self> {
        let dev_key_bytes = Zeroizing::new(key_bytes);
        self.local_dev_key_bytes = Some(dev_key_bytes);
        Ok(self)
    }

    fn generate_simulated_kms_key_bytes() -> ConclaveResult<Zeroizing<[u8; 32]>> {
        let mut rng = rand::rng();
        let mut key_bytes = Zeroizing::new([0u8; 32]);

        for _ in 0..SIMULATED_KMS_KEYGEN_MAX_ATTEMPTS {
            rng.fill_bytes(&mut *key_bytes);
            if Self::is_valid_secret_key_bytes(&key_bytes) {
                return Ok(key_bytes);
            }
        }

        Err(ConclaveError::CryptoError(
            "Failed to generate simulated KMS secret key".to_string(),
        ))
    }

    fn is_valid_secret_key_bytes(key_bytes: &[u8; 32]) -> bool {
        let ok = unsafe {
            secp256k1::ffi::secp256k1_ec_seckey_verify(
                secp256k1::ffi::secp256k1_context_no_precomp,
                key_bytes.as_ptr(),
            )
        };
        ok == 1
    }

    fn get_active_key_bytes(&self) -> &[u8; 32] {
        match self.local_dev_key_bytes.as_ref() {
            Some(key_bytes) => key_bytes,
            None => &self.simulated_kms_key_bytes,
        }
    }

    fn get_active_secp_key(&self) -> ConclaveResult<SecretKey> {
        SecretKey::from_secret_bytes(*self.get_active_key_bytes())
            .map_err(|e| ConclaveError::CryptoError(format!("SEC1 Error: {e}")))
    }

    fn generate_attestation_report(&self, challenge: &[u8]) -> DeviceIntegrityReport {
        let key_bytes = self.get_active_key_bytes();
        let signing_key = SigningKey::from_bytes(key_bytes);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

        let timestamp = unix_time_secs();
        let extension_data =
            "PURPOSE_SIGN|ALGORITHM_ED25519|PLATFORM_CLOUD|TEE_TYPE_AZURE_SNP".to_string();

        // Hardened: Sign the report fields
        let mut data_to_verify = Vec::new();
        data_to_verify.extend_from_slice(challenge);
        data_to_verify.extend_from_slice(extension_data.as_bytes());
        data_to_verify.extend_from_slice(&timestamp.to_le_bytes());

        let signature = signing_key.sign(&data_to_verify).to_bytes().to_vec();

        DeviceIntegrityReport {
            level: AttestationLevel::CloudTEE, // Hardened level
            challenge_nonce: challenge.to_vec(),
            signature,
            certificate_chain: vec![
                pubkey_hex,
                "CONCLAVE_CLOUD_ROOT_CA".to_string(),
                format!("CLOUD_KMS_INSTANCE_{}", self.kms_endpoint),
            ],
            timestamp,
            extension_data,
        }
    }
}

impl EnclaveManager for CloudEnclave {
    fn initialize(&self) -> ConclaveResult<()> {
        if self.kms_endpoint.is_empty() {
            return Err(ConclaveError::EnclaveFailure(
                "KMS endpoint not configured".to_string(),
            ));
        }
        Ok(())
    }

    fn generate_key(&self, key_id: &str) -> ConclaveResult<String> {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let key_handle = format!("cloud_key_{}_{}", key_id, hex::encode(&seed[..4]));
        seed.zeroize();
        Ok(key_handle)
    }

    fn get_public_key(&self, _derivation_path: &str) -> ConclaveResult<String> {
        let secret_key = self.get_active_secp_key()?;
        let public_key = secret_key.public_key();
        Ok(hex::encode(public_key.serialize()))
    }

    fn sign(&self, request: SignRequest) -> ConclaveResult<SignResponse> {
        let public_key_hex: String;
        let signature_hex: String;

        match request.algorithm {
            SigningAlgorithm::EcdsaSecp256k1 => {
                let secret_key = self.get_active_secp_key()?;
                let public_key = secret_key.public_key();
                public_key_hex = hex::encode(public_key.serialize());
                let message_bytes: [u8; 32] = request
                    .message_hash
                    .clone()
                    .try_into()
                    .map_err(|_| ConclaveError::InvalidPayload)?;
                let message = Message::from_digest(message_bytes);
                let sig = secp256k1::ecdsa::sign(message, &secret_key);
                signature_hex = hex::encode(sig.serialize_compact());
            }
            SigningAlgorithm::SchnorrSecp256k1 => {
                let secret_key = self.get_active_secp_key()?;
                let public_key = secret_key.public_key();
                public_key_hex = hex::encode(public_key.serialize());
                // Simulated Schnorr for CloudEnclave
                signature_hex = hex::encode(vec![0u8; 64]);
            }
            SigningAlgorithm::Ed25519 => {
                let key_bytes = self.get_active_key_bytes();
                let signing_key = SigningKey::from_bytes(key_bytes);
                public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
                let sig = signing_key.sign(&request.message_hash);
                signature_hex = hex::encode(sig.to_bytes());
            }
        };

        let attestation = self.generate_attestation_report(&request.message_hash);
        let attestation_json = serde_json::to_string(&attestation)
            .map_err(|e| ConclaveError::CryptoError(format!("Serialization error: {}", e)))?;

        Ok(SignResponse {
            signature_hex,
            public_key_hex,
            device_attestation: Some(attestation_json),
        })
    }
}
