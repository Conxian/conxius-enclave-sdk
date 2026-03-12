use crate::{ConclaveResult, ConclaveError, enclave::{EnclaveManager, SignRequest, SignResponse}};
use crate::enclave::attestation::{DeviceIntegrityReport, AttestationLevel};
use secp256k1::{Secp256k1, Message, SecretKey};
use rand::Rng;

/// A mock CloudEnclave implementation for testing and cloud-based non-custodial signing.
/// In a real implementation, this would communicate with a secure KMS or HSM over TLS.
pub struct CloudEnclave {
    pub kms_endpoint: String,
}

impl CloudEnclave {
    pub fn new(kms_endpoint: String) -> Self {
        Self { kms_endpoint }
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
            timestamp: 1710000000,
            extension_data: "PURPOSE_SIGN|ALGORITHM_EC|PLATFORM_CLOUD|TEE_TYPE_AZURE_SNP".to_string(),
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
        // Mock public key
        Ok("0250863ad64a87ad9a007159741e26b1f02337efa5f1d44d79e4c0303a74624a3f".to_string())
    }

    fn sign(&self, request: SignRequest) -> ConclaveResult<SignResponse> {
        if request.message_hash.len() != 32 {
            return Err(ConclaveError::InvalidPayload);
        }

        // Mock signing using a fixed dummy key for the cloud mock
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_byte_array([0xcd; 32]).unwrap();
        let message = Message::from_digest(request.message_hash.clone().try_into().unwrap());

        let sig = secp.sign_ecdsa(message, &secret_key);
        let public_key = secret_key.public_key(&secp);

        let attestation = self.generate_mock_attestation(&request.message_hash);

        Ok(SignResponse {
            signature_hex: hex::encode(sig.serialize_compact()),
            public_key_hex: hex::encode(public_key.serialize()),
            device_attestation: Some(serde_json::to_string(&attestation).unwrap_or_default()),
        })
    }
}
