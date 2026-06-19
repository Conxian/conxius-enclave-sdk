use crate::{
    ConclaveError, ConclaveResult,
    enclave::{EnclaveManager, SignRequest, SigningAlgorithm},
};
use sha2::Digest;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct EthereumManager {
    enclave: std::sync::Arc<dyn EnclaveManager>,
}

impl EthereumManager {
    pub fn new(enclave: std::sync::Arc<dyn EnclaveManager>) -> Self {
        Self { enclave }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl EthereumManager {
    pub fn get_address(&self, derivation_path: &str) -> ConclaveResult<String> {
        let pubkey_hex = self.enclave.get_public_key(derivation_path)?;
        let pubkey_bytes = hex::decode(pubkey_hex).map_err(|_| ConclaveError::InvalidPayload)?;

        let mut hasher = sha2::Sha256::new();
        hasher.update(&pubkey_bytes[1..]);
        let hash = hasher.finalize();
        Ok(format!("0x{}", hex::encode(&hash[12..])))
    }

    pub fn sign_transaction_hash(
        &self,
        sighash: Vec<u8>,
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        let request = SignRequest {
            algorithm: SigningAlgorithm::EcdsaSecp256k1,
            message_hash: sighash,
            derivation_path: derivation_path.to_string(),
            key_id: key_id.to_string(),
            taproot_tweak: None,
        };

        let response = self.enclave.sign(request)?;
        Ok(response.signature_hex)
    }

    pub fn sign_message(
        &self,
        message: &str,
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut hasher = sha2::Sha256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(message.as_bytes());
        let message_hash = hasher.finalize().to_vec();

        let request = SignRequest {
            algorithm: SigningAlgorithm::EcdsaSecp256k1,
            message_hash,
            derivation_path: derivation_path.to_string(),
            key_id: key_id.to_string(),
            taproot_tweak: None,
        };

        let response = self.enclave.sign(request)?;
        Ok(response.signature_hex)
    }
}
