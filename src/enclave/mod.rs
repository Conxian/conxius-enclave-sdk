pub mod android_strongbox;
pub mod attestation;
pub mod cloud;
pub mod replay_guard;

#[cfg(test)]
mod hardware_attestation_tests;

use crate::ConclaveResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SigningAlgorithm {
    EcdsaSecp256k1,
    SchnorrSecp256k1,
    Ed25519,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub algorithm: SigningAlgorithm,
    pub message_hash: Vec<u8>,
    pub derivation_path: String,
    pub key_id: String,
    pub taproot_tweak: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    pub signature_hex: String,
    pub public_key_hex: String,
    pub device_attestation: Option<String>,
}

pub trait EnclaveManager: Send + Sync {
    fn initialize(&self) -> ConclaveResult<()>;
    fn unlock(&self, _secret: &str, _salt: &[u8]) -> ConclaveResult<()> {
        Ok(())
    }
    fn generate_key(&self, key_id: &str) -> ConclaveResult<String>;
    fn get_public_key(&self, derivation_path: &str) -> ConclaveResult<String>;
    fn sign(&self, request: SignRequest) -> ConclaveResult<SignResponse>;
}

#[cfg(test)]
mod enclave_tests {
    use super::*;
    use crate::enclave::cloud::CloudEnclave;

    #[test]
    fn test_cloud_enclave_ed25519_signing() {
        let enclave = CloudEnclave::new("https://kms.test".to_string()).unwrap();
        let message = b"hello world";
        let request = SignRequest {
            algorithm: SigningAlgorithm::Ed25519,
            message_hash: message.to_vec(),
            derivation_path: "m/44'/501'/0'/0'".to_string(),
            key_id: "test-key".to_string(),
            taproot_tweak: None,
        };

        let response = enclave.sign(request).unwrap();
        assert!(!response.signature_hex.is_empty());
        assert_eq!(response.public_key_hex.len(), 64); // 32 bytes hex
        assert!(response.device_attestation.is_some());
    }
}
