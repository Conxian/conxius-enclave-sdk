use crate::{
    enclave::{sign_value_bearing, EnclaveManager, SigningAlgorithm, ValueBearingSignRequest},
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
        let operation_digest: [u8; 32] = intent
            .message_hash
            .try_into()
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let derivation_path = "m/44'/5757'/0'/0/0";
        let expected_public_key_hex = self.enclave.get_public_key(derivation_path)?;
        let request = ValueBearingSignRequest::new(
            operation_digest,
            SigningAlgorithm::EcdsaSecp256k1,
            derivation_path.to_string(),
            key_id.to_string(),
            expected_public_key_hex,
            None,
        );

        let response = sign_value_bearing(self.enclave, request)?;
        Ok(response.signature_hex)
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
        let operation_digest = hasher.finalize().into();
        let derivation_path = "m/44'/5757'/0'/0/0";
        let expected_public_key_hex = self.enclave.get_public_key(derivation_path)?;

        let request = ValueBearingSignRequest::new(
            operation_digest,
            SigningAlgorithm::EcdsaSecp256k1,
            derivation_path.to_string(),
            key_id.to_string(),
            expected_public_key_hex,
            None,
        );

        let response = sign_value_bearing(self.enclave, request)?;
        Ok(response.signature_hex)
    }
}
