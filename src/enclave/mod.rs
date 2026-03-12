pub mod android_strongbox;
pub mod attestation;
pub mod cloud;

use crate::ConclaveResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
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

/// EnclaveManager trait for hardware-backed security modules.
pub trait EnclaveManager: Send + Sync {
    /// Initialize the enclave, ensuring the hardware backend is available.
    fn initialize(&self) -> ConclaveResult<()>;
    
    /// Generate a new keypair within the secure hardware.
    fn generate_key(&self, key_id: &str) -> ConclaveResult<String>;

    /// Retrieve the public key for a specific derivation path.
    fn get_public_key(&self, derivation_path: &str) -> ConclaveResult<String>;
    
    /// Sign a raw payload using the hardware-backed key.
    fn sign(&self, request: SignRequest) -> ConclaveResult<SignResponse>;
}
