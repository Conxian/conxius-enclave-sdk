use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};

/// Zero-Knowledge Machine Learning (ZKML) service for institutional compliance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkmlProofRequest {
    pub model_id: String,
    pub input_commitment: String,
    pub compliance_rule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkmlProofResponse {
    pub proof_hex: String,
    pub verified: bool,
    pub output_commitment: String,
}

pub struct ZkmlService {
    pub gateway_url: String,
    pub http_client: reqwest::Client,
}

impl ZkmlService {
    pub fn new(gateway_url: String, http_client: reqwest::Client) -> Self {
        Self {
            gateway_url,
            http_client,
        }
    }

    /// Generates a ZK proof for compliance verification.
    pub async fn generate_compliance_proof(
        &self,
        request: ZkmlProofRequest,
    ) -> ConclaveResult<ZkmlProofResponse> {
        let url = format!("{}/v1/zkml/prove", self.gateway_url);

        let response = self
            .http_client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| ConclaveError::NetworkError(format!("ZKML request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(ConclaveError::EnclaveFailure(format!(
                "Gateway ZKML error: {}",
                response.status()
            )));
        }

        let proof = response
            .json::<ZkmlProofResponse>()
            .await
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid ZKML response: {}", e)))?;

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkml_service_new() {
        let client = reqwest::Client::new();
        let service = ZkmlService::new("https://api.conxian.io".to_string(), client);
        assert_eq!(service.gateway_url, "https://api.conxian.io");
    }

    #[tokio::test]
    async fn test_zkml_request_construction() {
        // Test request serialization
        let req = ZkmlProofRequest {
            model_id: "compliance_v1".to_string(),
            input_commitment: "0xabc".to_string(),
            compliance_rule: "KYC_AML".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("compliance_v1"));
    }
}
