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
        Self { gateway_url, http_client }
    }

    /// Generates a ZK proof for compliance verification.
    pub async fn generate_compliance_proof(&self, request: ZkmlProofRequest) -> ConclaveResult<ZkmlProofResponse> {
        let url = format!("{}/v1/zkml/prove", self.gateway_url);

        let response = self.http_client.post(&url).json(&request).send().await.map_err(|e| {
            ConclaveError::EnclaveFailure(format!("ZKML request failed: {}", e))
        })?;

        if !response.status().is_success() {
            return Err(ConclaveError::EnclaveFailure(format!("Gateway ZKML error: {}", response.status())));
        }

        let proof = response.json::<ZkmlProofResponse>().await.map_err(|e| {
            ConclaveError::CryptoError(format!("Invalid ZKML response: {}", e))
        })?;

        Ok(proof)
    }
}
