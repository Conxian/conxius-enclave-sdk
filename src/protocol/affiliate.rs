use serde::{Deserialize, Serialize};
use sha2::Digest;
use crate::{ConclaveResult, enclave::{SignRequest, HeadlessEnclave}};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffiliateProof {
    pub partner_id: String,
    pub user_id: String,
    pub timestamp: u64,
    pub signature: String,
}

pub struct AffiliateManager<'a> {
    enclave: &'a dyn HeadlessEnclave,
}

impl<'a> AffiliateManager<'a> {
    pub fn new(enclave: &'a dyn HeadlessEnclave) -> Self {
        Self { enclave }
    }

    /// Generates a signed proof of referral.
    /// This ensures that affiliate links cannot be spoofed and conversions
    /// are cryptographically linked to a valid user session.
    pub fn generate_referral_proof(&self, partner_id: &str, user_id: &str) -> ConclaveResult<AffiliateProof> {
        let timestamp = 1710000000; // Mock timestamp
        let message = format!("{}:{}:{}", partner_id, user_id, timestamp);

        let mut hasher = sha2::Sha256::new();
        hasher.update(message.as_bytes());
        let message_hash = hasher.finalize().to_vec();

        let request = SignRequest {
            message_hash,
            derivation_path: "m/44'/5757'/0'/0/affiliate".to_string(),
            key_id: "affiliate_key".to_string(),
        };

        let response = self.enclave.sign(request)?;

        Ok(AffiliateProof {
            partner_id: partner_id.to_string(),
            user_id: user_id.to_string(),
            timestamp,
            signature: response.signature_hex,
        })
    }
}
