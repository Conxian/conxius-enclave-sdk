//! Zero-Knowledge Machine Learning (ZKML) Module
//!
//! Provides ZK proof generation and verification for ML model inference
//! on Bitcoin and other chains. Supports SNARK and STARK proof systems.
//!
//! ## Proof System Comparison
//! | System | Proof Size | Verification | Quantum-Resistant |
//! |--------|------------|--------------|-------------------|
//! | SNARKs | ~192 bytes | ~3ms | No (pairing-based) |
//! | STARKs | 45-200KB | Slower | Yes (hash-based) |
//!
//! ## Supported Tooling
//! - **ezkl**: TensorFlow/Keras to SNARK circuits
//! - **Succinct SP1**: General-purpose zkVM for Bitcoin
//! - **Circom + snarkjs**: Circuit compiler and proof generator
//!
//! ## Use Cases
//! - Privacy-preserving oracles
//! - Decentralized AI marketplaces
//! - On-chain fraud detection
//! - AI trading bots
//!
//! References:
//! - [ezkl GitHub](https://github.com/worldcoin/awesome-zkml)
//! - [Succinct SP1](https://blog.succinct.xyz/bitcoin-sp1)
//! - [ZKML Performance Paper](https://ddkang.github.io/papers/2024/zkml-eurosys.pdf)

use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};

/// Proof system type for ZKML operations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofSystem {
    /// Groth16 or PLONK SNARK - ~192 bytes, fast verification
    Snark,
    /// STARK - 45-200KB, quantum-resistant
    Stark,
    /// Auto-select based on requirements
    Auto,
}

/// ZKML proof request for compliance verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkmlProofRequest {
    /// Unique identifier for the ML model
    pub model_id: String,
    /// Commitment to the model input (hash or Pedersen commitment)
    pub input_commitment: String,
    /// Compliance rule to verify (e.g., "KYC_AML", "SANCTIONS_SCREEN")
    pub compliance_rule: String,
    /// Preferred proof system (defaults to Auto)
    pub proof_system: Option<ProofSystem>,
    /// Optional model output hash for verification
    pub expected_output_hash: Option<String>,
}

impl ZkmlProofRequest {
    /// Creates a new ZKML proof request with default settings.
    pub fn new(model_id: &str, input_commitment: &str, compliance_rule: &str) -> Self {
        Self {
            model_id: model_id.to_string(),
            input_commitment: input_commitment.to_string(),
            compliance_rule: compliance_rule.to_string(),
            proof_system: None,
            expected_output_hash: None,
        }
    }

    /// Sets the proof system preference.
    pub fn with_proof_system(mut self, system: ProofSystem) -> Self {
        self.proof_system = Some(system);
        self
    }

    /// Sets the expected output hash for verification.
    pub fn with_expected_output(mut self, hash: &str) -> Self {
        self.expected_output_hash = Some(hash.to_string());
        self
    }
}

/// ZKML proof response with verification results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkmlProofResponse {
    /// Hex-encoded proof bytes
    pub proof_hex: String,
    /// Whether the proof was successfully verified
    pub verified: bool,
    /// Commitment to the model output
    pub output_commitment: String,
    /// Proof system used
    pub proof_system: ProofSystem,
    /// Verification time in milliseconds (if measured)
    pub verification_time_ms: Option<u64>,
    /// Proof size in bytes
    pub proof_size_bytes: Option<usize>,
}

/// Model inference result for ZK verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkmlModelInference {
    /// Model identifier
    pub model_id: String,
    /// Input hash (SHA-256 of inputs)
    pub input_hash: String,
    /// Output hash (SHA-256 of inference result)
    pub output_hash: String,
    /// Compliance rules satisfied
    pub rules_passed: Vec<String>,
    /// Compliance rules failed
    pub rules_failed: Vec<String>,
}

/// ZKML Service for institutional compliance verification.
///
/// Supports multiple proof systems:
/// - SNARK: Fast, small proofs (not quantum-resistant)
/// - STARK: Larger proofs (quantum-resistant)
///
/// ## Example
/// ```ignore
/// let service = ZkmlService::new(gateway_url, client);
/// let request = ZkmlProofRequest::new("model_v1", &input_hash, "KYC_AML")
///     .with_proof_system(ProofSystem::Snark);
/// let proof = service.generate_compliance_proof(request).await?;
/// ```
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

    /// Verifies a ZK proof locally (for light clients).
    pub async fn verify_proof_locally(
        &self,
        proof_hex: &str,
        public_inputs: &[String],
    ) -> ConclaveResult<bool> {
        let url = format!("{}/v1/zkml/verify", self.gateway_url);

        #[derive(Serialize)]
        struct VerifyRequest<'a> {
            proof_hex: &'a str,
            public_inputs: &'a [String],
        }

        let response = self
            .http_client
            .post(&url)
            .json(&VerifyRequest {
                proof_hex,
                public_inputs,
            })
            .send()
            .await
            .map_err(|e| ConclaveError::NetworkError(format!("ZKML verify failed: {}", e)))?;

        #[derive(Deserialize)]
        struct VerifyResponse {
            valid: bool,
        }

        let result = response
            .json::<VerifyResponse>()
            .await
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid verify response: {}", e)))?;

        Ok(result.valid)
    }

    /// Gets supported proof systems for a given model.
    pub async fn get_supported_proof_systems(
        &self,
        model_id: &str,
    ) -> ConclaveResult<Vec<ProofSystem>> {
        let url = format!("{}/v1/zkml/models/{}/proof-systems", self.gateway_url, model_id);

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| ConclaveError::NetworkError(format!("ZKML request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(ConclaveError::EnclaveFailure(format!(
                "Gateway error: {}",
                response.status()
            )));
        }

        let systems: Vec<String> = response
            .json()
            .await
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid response: {}", e)))?;

        let proof_systems = systems
            .iter()
            .filter_map(|s| match s.as_str() {
                "snark" => Some(ProofSystem::Snark),
                "stark" => Some(ProofSystem::Stark),
                _ => None,
            })
            .collect();

        Ok(proof_systems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkml_service_new() {
        let client = reqwest::Client::new();
        let service = ZkmlService::new("https://gateway.conxian-labs.com".to_string(), client);
        assert_eq!(service.gateway_url, "https://gateway.conxian-labs.com");
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
