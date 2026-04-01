use crate::ConclaveResult;
use crate::state::MerkleMountainRange;
use serde::{Deserialize, Serialize};

/// Service for handling Merkle Mountain Range (MMR) operations.
pub struct MmrService {
    pub base_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MmrProofResponse {
    pub position: u64,
    pub root: String,
    pub proof: Vec<String>,
}

impl MmrService {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }

    /// Generates a local MMR proof.
    pub fn generate_local_proof(&self, data: &[u8], pos: u64) -> ConclaveResult<MmrProofResponse> {
        let mut mmr = MerkleMountainRange::new();
        mmr.append(data);

        let proof = mmr
            .generate_proof(pos)
            .map_err(crate::ConclaveError::CryptoError)?;

        Ok(MmrProofResponse {
            position: proof.pos,
            root: proof.mmr_root,
            proof: proof.proof_path,
        })
    }

    /// Fetches an MMR proof from the remote /v1/mmr-proof endpoint.
    pub async fn fetch_remote_proof(&self, node_id: &str) -> ConclaveResult<MmrProofResponse> {
        let url = format!("{}/v1/mmr-proof/{}", self.base_url, node_id);
        let client = reqwest::Client::new();

        let response = client.get(&url).send().await.map_err(|e| {
            crate::ConclaveError::EnclaveFailure(format!("API Request failed: {}", e))
        })?;

        let proof = response
            .json::<MmrProofResponse>()
            .await
            .map_err(|e| crate::ConclaveError::CryptoError(format!("Invalid response: {}", e)))?;

        Ok(proof)
    }
}
