use crate::{
    enclave::{
        sign_value_bearing, EnclaveManager, OperationContext, SignerKeyBinding, SigningAlgorithm,
        TrustRequirement, ValueBearingPurpose, ValueBearingSignRequest, VALUE_BEARING_POLICY_ID,
    },
    ConclaveError, ConclaveResult,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct StacksTransactionIntent {
    pub payload: Vec<u8>,
    pub message_hash: Vec<u8>,
}

pub struct StacksManager<'a> {
    enclave: &'a dyn EnclaveManager,
}

impl<'a> StacksManager<'a> {
    pub fn new(enclave: &'a dyn EnclaveManager) -> Self {
        Self { enclave }
    }

    pub fn prepare_transaction(&self, payload: &[u8]) -> Result<StacksTransactionIntent, String> {
        if payload.is_empty() {
            return Err("Payload cannot be empty".to_string());
        }

        let mut hasher = Sha256::new();
        hasher.update(payload);
        let hash1 = hasher.finalize();

        let mut hasher2 = Sha256::new();
        hasher2.update(hash1);
        let message_hash = hasher2.finalize().to_vec();

        Ok(StacksTransactionIntent {
            payload: payload.to_vec(),
            message_hash,
        })
    }

    pub fn sign_prepared_transaction(
        &self,
        intent: StacksTransactionIntent,
        key_id: &str,
    ) -> ConclaveResult<String> {
        let derivation_path = "m/44'/5757'/0'/0/0";
        let message_hash: [u8; 32] = intent
            .message_hash
            .try_into()
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let public_key = hex::decode(self.enclave.get_public_key(derivation_path)?)
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let request = ValueBearingSignRequest::new(
            OperationContext::new(
                "conxian/stacks/transaction",
                ValueBearingPurpose::Transaction,
                message_hash.to_vec(),
            )?,
            SigningAlgorithm::EcdsaSecp256k1,
            TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID)?,
            message_hash,
            SignerKeyBinding::new(key_id, derivation_path, public_key)?,
            None,
        )?;

        let response = sign_value_bearing(self.enclave, request)?;
        Ok(response.sign_response().signature_hex.clone())
    }

    pub fn sign_message(&self, message: &str, key_id: &str) -> ConclaveResult<String> {
        if message.is_empty() {
            return Err(ConclaveError::InvalidPayload);
        }

        let prefix = "\x17Stacks Signed Message:\n";
        let mut hasher = Sha256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(format!("{}", message.len()).as_bytes());
        hasher.update(message.as_bytes());
        let message_hash: [u8; 32] = hasher.finalize().into();
        let derivation_path = "m/44'/5757'/0'/0/0";
        let public_key = hex::decode(self.enclave.get_public_key(derivation_path)?)
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let request = ValueBearingSignRequest::new(
            OperationContext::new(
                "conxian/stacks/message",
                ValueBearingPurpose::Authorization,
                message_hash.to_vec(),
            )?,
            SigningAlgorithm::EcdsaSecp256k1,
            TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID)?,
            message_hash,
            SignerKeyBinding::new(key_id, derivation_path, public_key)?,
            None,
        )?;

        let response = sign_value_bearing(self.enclave, request)?;
        Ok(response.sign_response().signature_hex.clone())
    }
}
