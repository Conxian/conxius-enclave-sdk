use crate::{
    ConclaveError, ConclaveResult,
    enclave::{EnclaveManager, SignRequest},
};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct StacksTransactionIntent {
    pub payload: Vec<u8>,
    pub message_hash: Vec<u8>,
}

/// Stacks-specific transaction and message handling.
pub struct StacksManager<'a> {
    enclave: &'a dyn EnclaveManager,
}

impl<'a> StacksManager<'a> {
    pub fn new(enclave: &'a dyn EnclaveManager) -> Self {
        Self { enclave }
    }

    /// PHASE 1: Prepare the Stacks transaction intent.
    pub fn prepare_transaction(&self, payload: &[u8]) -> Result<StacksTransactionIntent, String> {
        if payload.is_empty() {
            return Err("Payload cannot be empty".to_string());
        }

        // Stacks transactions are double-sha256 hashed usually for the signing part
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

    /// PHASE 2: Sign the prepared intent.
    pub fn sign_prepared_transaction(
        &self,
        intent: StacksTransactionIntent,
        key_id: &str,
    ) -> ConclaveResult<String> {
        let request = SignRequest {
            message_hash: intent.message_hash,
            derivation_path: "m/44'/5757'/0'/0/0".to_string(),
            key_id: key_id.to_string(),
            taproot_tweak: None,
        };

        let response = self.enclave.sign(request)?;
        Ok(response.signature_hex)
    }

    /// Formats and signs a Stacks message (SIP-018)
    pub fn sign_message(&self, message: &str, key_id: &str) -> ConclaveResult<String> {
        if message.is_empty() {
            return Err(ConclaveError::InvalidPayload);
        }

        let prefix = "\x17Stacks Signed Message:\n";
        let mut hasher = Sha256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(format!("{}", message.len()).as_bytes());
        hasher.update(message.as_bytes());
        let message_hash = hasher.finalize().to_vec();

        let request = SignRequest {
            message_hash,
            derivation_path: "m/44'/5757'/0'/0/0".to_string(),
            key_id: key_id.to_string(),
            taproot_tweak: None,
        };

        let response = self.enclave.sign(request)?;
        Ok(response.signature_hex)
    }
}
