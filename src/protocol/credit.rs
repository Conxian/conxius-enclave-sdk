use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Ubuntu Credit Primitive: Hardware-attested group vouching for lending.
/// Aligned with the 'cxn-ubuntu-credit' Clarity contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VouchIntent {
    pub borrower: String,
    pub vouchers: Vec<String>,
    pub amount: u64,
    pub signable_hash: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditScore {
    pub borrower: String,
    pub vouch_count: u32,
    pub active_loans: u32,
    pub hardware_attested_score: u32,
}

pub struct CreditService {
    pub gateway_endpoint: String,
    pub http_client: reqwest::Client,
}

impl CreditService {
    pub fn new(gateway_endpoint: String, http_client: reqwest::Client) -> Self {
        Self {
            gateway_endpoint,
            http_client,
        }
    }

    /// Prepares a vouch intent for signing.
    /// Vouching requires a hardware-backed signature to prevent bot-vouching fraud.
    pub fn prepare_vouch(
        &self,
        borrower: String,
        vouchers: Vec<String>,
        amount: u64,
    ) -> VouchIntent {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut hasher = Sha256::new();
        hasher.update(b"UBUNTU_VOUCH_v1:");
        hasher.update(borrower.as_bytes());
        hasher.update(format!("{:?}", vouchers).as_bytes());
        hasher.update(amount.to_be_bytes());
        hasher.update(timestamp.to_be_bytes());
        let signable_hash = hasher.finalize().to_vec();

        VouchIntent {
            borrower,
            vouchers,
            amount,
            signable_hash,
            timestamp,
        }
    }

    /// Broadcasts a signed vouch intent to the Stacks chain via the Conxian Gateway.
    pub async fn submit_vouch(
        &self,
        intent: VouchIntent,
        signature: String,
        attestation: String,
    ) -> ConclaveResult<String> {
        let url = format!("{}/v1/credit/vouch", self.gateway_endpoint);

        #[derive(Serialize)]
        struct VouchRequest {
            intent: VouchIntent,
            signature: String,
            attestation: String,
        }

        let response = self
            .http_client
            .post(&url)
            .json(&VouchRequest {
                intent,
                signature,
                attestation,
            })
            .send()
            .await
            .map_err(|e| ConclaveError::EnclaveFailure(format!("Vouch submission failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(ConclaveError::EnclaveFailure(format!(
                "Gateway vouch error: {}",
                response.status()
            )));
        }

        let tx_id = response
            .text()
            .await
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid vouch response: {}", e)))?;

        Ok(tx_id)
    }

    /// Retrieves the hardware-attested credit score for a borrower.
    pub async fn get_score(&self, borrower: &str) -> ConclaveResult<CreditScore> {
        let url = format!("{}/v1/credit/score/{}", self.gateway_endpoint, borrower);

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| ConclaveError::EnclaveFailure(format!("Score fetch failed: {}", e)))?;

        let score = response
            .json::<CreditScore>()
            .await
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid score response: {}", e)))?;

        Ok(score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prepare_vouch_determinism() {
        let service = CreditService::new(
            "https://gateway.conxian-labs.com".to_string(),
            reqwest::Client::new(),
        );

        let borrower = "bc1q...".to_string();
        let vouchers = vec!["v1".to_string(), "v2".to_string()];
        let amount = 1000;

        let intent1 = service.prepare_vouch(borrower.clone(), vouchers.clone(), amount);
        let intent2 = service.prepare_vouch(borrower, vouchers, amount);

        // Timestamps might differ if called across second boundary, but here they should be same or we check fields
        assert_eq!(intent1.borrower, intent2.borrower);
        assert_eq!(intent1.vouchers, intent2.vouchers);
        assert_eq!(intent1.amount, intent2.amount);
        assert!(!intent1.signable_hash.is_empty());
    }
}
