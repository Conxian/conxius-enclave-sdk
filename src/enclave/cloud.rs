use crate::enclave::attestation::{AttestationLevel, DeviceIntegrityReport};
use crate::{
    ConclaveError, ConclaveResult,
    enclave::{EnclaveManager, SignRequest, SignResponse},
};
use rand::Rng;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// CloudEnclave provides an abstraction for cloud-based HSM/KMS environments.
///
/// In production, this client communicates with a secure KMS (e.g., Azure Key Vault, AWS KMS)
/// using hardware-backed keys and Cloud TEE (e.g., Azure SNP) for attestation.
pub struct CloudEnclave {
    pub kms_endpoint: String,
    /// Optional local development key material, stored as zeroizing bytes.
    /// If None, the enclave uses an ephemeral in-memory key and simulates remote KMS operations.
    local_dev_key_bytes: Option<Zeroizing<[u8; 32]>>,
    ephemeral_key_bytes: Zeroizing<[u8; 32]>,
}

impl CloudEnclave {
    pub fn new(kms_endpoint: String) -> Self {
        let ephemeral_key_bytes = Self::generate_valid_secret_key_bytes();
        Self {
            kms_endpoint,
            local_dev_key_bytes: None,
            ephemeral_key_bytes,
        }
    }

    /// Sets a local development key for deterministic testing.
    /// WARNING: For development use only.
    pub fn with_dev_key(mut self, key_bytes: [u8; 32]) -> ConclaveResult<Self> {
        let key_bytes = Zeroizing::new(key_bytes);
        SecretKey::from_byte_array(*key_bytes)
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid dev key: {}", e)))?;

        self.local_dev_key_bytes = Some(key_bytes);
        Ok(self)
    }

    fn generate_valid_secret_key_bytes() -> Zeroizing<[u8; 32]> {
        loop {
            let mut candidate = Zeroizing::new([0u8; 32]);
            rand::rng().fill_bytes(&mut candidate[..]);
            if SecretKey::from_byte_array(*candidate).is_ok() {
                return candidate;
            }
        }
    }

    fn get_active_key(&self) -> ConclaveResult<SecretKey> {
        let source_bytes = match self.local_dev_key_bytes.as_ref() {
            Some(key_bytes) => &key_bytes[..],
            None => &self.ephemeral_key_bytes[..],
        };

        let mut key_bytes = Zeroizing::new([0u8; 32]);
        key_bytes[..].copy_from_slice(source_bytes);

        SecretKey::from_byte_array(*key_bytes)
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid active key: {}", e)))
    }

    fn generate_attestation_report(&self, challenge: &[u8]) -> DeviceIntegrityReport {
        DeviceIntegrityReport {
            level: AttestationLevel::CloudTEE,
            challenge_nonce: challenge.to_vec(),
            signature: vec![0u8; 64], // Simulated signature
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
        // Verification of KMS connectivity and TEE environment
        if self.kms_endpoint.is_empty() {
            return Err(ConclaveError::EnclaveFailure(
                "KMS endpoint not configured".to_string(),
            ));
        }
        Ok(())
    }

    fn generate_key(&self, key_id: &str) -> ConclaveResult<String> {
        // In production, this sends a 'Create Key' intent to the KMS.
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let key_handle = format!("cloud_key_{}_{}", key_id, hex::encode(&seed[..4]));
        seed.zeroize();
        Ok(key_handle)
    }

    fn get_public_key(&self, _derivation_path: &str) -> ConclaveResult<String> {
        let secp = Secp256k1::new();
        let secret_key = self.get_active_key()?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        Ok(hex::encode(public_key.serialize()))
    }

    fn sign(&self, request: SignRequest) -> ConclaveResult<SignResponse> {
        if request.message_hash.len() != 32 {
            return Err(ConclaveError::InvalidPayload);
        }

        let secp = Secp256k1::new();
        let secret_key = self.get_active_key()?;
        let message_bytes: [u8; 32] = request.message_hash.clone().try_into().unwrap();
        let message = Message::from_digest(message_bytes);

        let sig = secp.sign_ecdsa(message, &secret_key);
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let attestation = self.generate_attestation_report(&request.message_hash);

        Ok(SignResponse {
            signature_hex: hex::encode(sig.serialize_compact()),
            public_key_hex: hex::encode(public_key.serialize()),
            device_attestation: Some(serde_json::to_string(&attestation).unwrap_or_default()),
        })
    }
}
