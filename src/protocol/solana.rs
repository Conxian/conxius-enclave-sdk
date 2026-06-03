use crate::{
    ConclaveResult,
    enclave::{EnclaveManager, SignRequest, SigningAlgorithm},
};

pub struct SolanaManager<'a> {
    enclave: &'a dyn EnclaveManager,
}

impl<'a> SolanaManager<'a> {
    pub fn new(enclave: &'a dyn EnclaveManager) -> Self {
        Self { enclave }
    }

    pub fn get_address(&self, derivation_path: &str) -> ConclaveResult<String> {
        let pubkey_hex = self.enclave.get_public_key(derivation_path)?;
        Ok(pubkey_hex)
    }

    pub fn sign_transaction_hash(
        &self,
        message_hash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        let request = SignRequest {
            algorithm: SigningAlgorithm::Ed25519,
            message_hash: message_hash.to_vec(),
            derivation_path: derivation_path.to_string(),
            key_id: key_id.to_string(),
            taproot_tweak: None,
        };

        let response = self.enclave.sign(request)?;
        Ok(response.signature_hex)
    }
}
