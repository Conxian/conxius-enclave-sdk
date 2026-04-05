use crate::enclave::attestation::{AttestationLevel, DeviceIntegrityReport};
use crate::{
    ConclaveError, ConclaveResult,
    enclave::{EnclaveManager, SignRequest, SignResponse},
};
use rand::Rng;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use std::time::{SystemTime, UNIX_EPOCH};

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A mock CloudEnclave implementation for testing and cloud-based non-custodial signing.
/// In a real implementation, this would communicate with a secure KMS or HSM over TLS.
pub struct CloudEnclave {
    pub kms_endpoint: String,
}

impl CloudEnclave {
    pub fn new(kms_endpoint: String) -> Self {
        Self { kms_endpoint }
    }

    fn get_mock_secret_key(&self) -> SecretKey {
        // Fixed dummy key for deterministic mock testing
        SecretKey::from_byte_array([0xcd; 32]).unwrap()
    }

    fn generate_mock_attestation(&self, challenge: &[u8]) -> DeviceIntegrityReport {
        DeviceIntegrityReport {
            level: AttestationLevel::CloudTEE,
            challenge_nonce: challenge.to_vec(),
            signature: vec![0u8; 64],
            certificate_chain: vec![
                "CONCLAVE_CLOUD_ROOT_CA".to_string(),
                format!("CLOUD_KMS_INSTANCE_{}", self.kms_endpoint),
            ],
            timestamp: unix_time_secs(),
            extension_data: "PURPOSE_SIGN|ALGORITHM_EC|PLATFORM_CLOUD|TEE_TYPE_AZURE_SNP"
                .to_string(),
        }
    }
}

impl EnclaveManager for CloudEnclave {
    fn initialize(&self) -> ConclaveResult<()> {
        // In reality, check connection to KMS/HSM
        Ok(())
    }

    fn generate_key(&self, key_id: &str) -> ConclaveResult<String> {
        // Mocking key generation
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        Ok(format!("cloud_key_{}_{}", key_id, hex::encode(&seed[..4])))
    }

    fn get_public_key(&self, _derivation_path: &str) -> ConclaveResult<String> {
        let secp = Secp256k1::new();
        let secret_key = self.get_mock_secret_key();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        Ok(hex::encode(public_key.serialize()))
    }

    fn sign(&self, request: SignRequest) -> ConclaveResult<SignResponse> {
        if request.message_hash.len() != 32 {
            return Err(ConclaveError::InvalidPayload);
        }

        let secp = Secp256k1::new();
        let secret_key = self.get_mock_secret_key();
        let message_bytes: [u8; 32] = request.message_hash.clone().try_into().unwrap();
        let message = Message::from_digest(message_bytes);

        let sig = secp.sign_ecdsa(message, &secret_key);
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let attestation = self.generate_mock_attestation(&request.message_hash);

        Ok(SignResponse {
            signature_hex: hex::encode(sig.serialize_compact()),
            public_key_hex: hex::encode(public_key.serialize()),
            device_attestation: Some(serde_json::to_string(&attestation).unwrap_or_default()),
        })
    }
}
