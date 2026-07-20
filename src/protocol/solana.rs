use crate::{
    enclave::{sign_value_bearing, EnclaveManager, SignRequest, SigningAlgorithm},
    ConclaveResult,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplTransfer {
    pub source_token_account: String,
    pub destination_token_account: String,
    pub amount: u64,
    pub owner: String,
}

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

        let response = sign_value_bearing(self.enclave, request)?;
        Ok(response.signature_hex)
    }

    /// Prepares a simple SPL token transfer instruction data.
    pub fn prepare_spl_transfer(&self, transfer: SplTransfer) -> Vec<u8> {
        // Token Program Transfer instruction: [3, amount]
        let mut data = vec![3]; // Instruction index for Transfer
        data.extend(transfer.amount.to_le_bytes());
        data
    }
}
