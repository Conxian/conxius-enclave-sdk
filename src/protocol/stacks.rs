use crate::{ConclaveResult, ConclaveError, enclave::{SignRequest, HeadlessEnclave}};
use sha2::{Sha256, Digest};

/// Stacks-specific transaction and message handling.
pub struct StacksManager<'a> {
    enclave: &'a dyn HeadlessEnclave,
}

impl<'a> StacksManager<'a> {
    pub fn new(enclave: &'a dyn HeadlessEnclave) -> Self {
        Self { enclave }
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
        };

        let response = self.enclave.sign(request)?;
        Ok(response.signature_hex)
    }

    /// Signs a Stacks transaction payload (placeholder for complex SIP-005 logic)
    pub fn sign_transaction_payload(&self, payload: &[u8], key_id: &str) -> ConclaveResult<String> {
        if payload.is_empty() {
            return Err(ConclaveError::InvalidPayload);
        }

        // Stacks transactions are double-sha256 hashed usually for the signing part
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let hash1 = hasher.finalize();

        let mut hasher2 = Sha256::new();
        hasher2.update(hash1);
        let message_hash = hasher2.finalize().to_vec();

        let request = SignRequest {
            message_hash,
            derivation_path: "m/44'/5757'/0'/0/0".to_string(),
            key_id: key_id.to_string(),
        };

        let response = self.enclave.sign(request)?;
        Ok(response.signature_hex)
    }
}
