use crate::{ConclaveResult, ConclaveError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub message_hash: Vec<u8>,
    pub derivation_path: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    pub signature_hex: String,
    pub public_key_hex: String,
    pub device_attestation: Option<String>,
}

/// Headless Cryptographic State Machine trait.
/// 
/// This must be implemented by the platform-specific hardware layer
/// (e.g., Android StrongBox or Apple Secure Enclave).
pub trait HeadlessEnclave {
    /// Initialize the enclave, ensuring the hardware backend is available.
    fn initialize(&self) -> ConclaveResult<()>;
    
    /// Generate a new keypair within the secure hardware.
    fn generate_key(&self, key_id: &str) -> ConclaveResult<String>;
    
    /// Sign a raw payload using the hardware-backed key.
    fn sign(&self, request: SignRequest) -> ConclaveResult<SignResponse>;
}
