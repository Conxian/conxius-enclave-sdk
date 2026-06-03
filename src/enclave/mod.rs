pub mod android_strongbox;
pub mod attestation;
pub mod cloud;

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
