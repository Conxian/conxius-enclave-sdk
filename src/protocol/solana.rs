use crate::{
    enclave::{
        sign_value_bearing, EnclaveManager, OperationContext, SignerKeyBinding, SigningAlgorithm,
        TrustRequirement, ValueBearingPurpose, ValueBearingSignRequest, VALUE_BEARING_POLICY_ID,
    },
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
        let public_key = hex::decode(self.enclave.get_public_key(derivation_path)?)
            .map_err(|_| crate::ConclaveError::InvalidPayload)?;
        let request = ValueBearingSignRequest::new(
            OperationContext::new(
                "conxian/solana/transaction",
                ValueBearingPurpose::Transaction,
                message_hash.to_vec(),
            )?,
            SigningAlgorithm::Ed25519,
            TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID)?,
            message_hash,
            SignerKeyBinding::new(key_id, derivation_path, public_key)?,
            None,
        )?;

        let response = sign_value_bearing(self.enclave, request)?;
        Ok(response.sign_response().signature_hex.clone())
    }

    /// Prepares a simple SPL token transfer instruction data.
    pub fn prepare_spl_transfer(&self, transfer: SplTransfer) -> Vec<u8> {
        // Token Program Transfer instruction: [3, amount]
        let mut data = vec![3]; // Instruction index for Transfer
        data.extend(transfer.amount.to_le_bytes());
        data
    }
}
