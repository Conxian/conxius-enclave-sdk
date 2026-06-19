use crate::{
    ConclaveResult,
    enclave::{EnclaveManager, SignRequest, SigningAlgorithm},
};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct SolanaManager {
    enclave: std::sync::Arc<dyn EnclaveManager>,
}

impl SolanaManager {
    pub fn new(enclave: std::sync::Arc<dyn EnclaveManager>) -> Self {
        Self { enclave }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl SolanaManager {
    pub fn get_address(&self, derivation_path: &str) -> ConclaveResult<String> {
        let pubkey_hex = self.enclave.get_public_key(derivation_path)?;
        Ok(pubkey_hex)
    }

    pub fn sign_transaction_hash(
        &self,
        message_hash: Vec<u8>,
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        let request = SignRequest {
            algorithm: SigningAlgorithm::Ed25519,
            message_hash,
            derivation_path: derivation_path.to_string(),
            key_id: key_id.to_string(),
            taproot_tweak: None,
        };

        let response = self.enclave.sign(request)?;
        Ok(response.signature_hex)
    }
}
