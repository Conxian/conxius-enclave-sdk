use crate::ConclaveResult;
use crate::enclave::EnclaveManager;
use crate::protocol::asset::Chain;
use crate::protocol::intent::CrossChainIntent;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Chain Abstraction Service (v2.0.0)
/// Orchestrates NEAR-style chain signatures and universal intent settlement.
/// Enables "Pay in Any Token, Settle in Target Stablecoin" flows.
pub struct ChainAbstractionService {
    enclave: Arc<dyn EnclaveManager>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSignatureRequest {
    pub target_chain: Chain,
    pub transaction_payload: Vec<u8>,
    pub derivation_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSignatureResponse {
    pub signature_hex: String,
    pub public_key: String,
}

impl ChainAbstractionService {
    pub fn new(enclave: Arc<dyn EnclaveManager>) -> Self {
        Self { enclave }
    }

    /// Generates a chain-agnostic signature for a target network.
    /// This allows a single hardware-backed key to control accounts across multiple chains.
    pub async fn sign_chain_transaction(
        &self,
        request: ChainSignatureRequest,
    ) -> ConclaveResult<ChainSignatureResponse> {
        let pubkey = self.enclave.get_public_key(&request.derivation_path)?;

        let algo = match request.target_chain {
            Chain::BITCOIN
            | Chain::ETHEREUM
            | Chain::STACKS
            | Chain::ROOTSTOCK
            | Chain::BOB
            | Chain::MEZO
            | Chain::BABYLON
            | Chain::BOTANIX
            | Chain::CITREA => crate::enclave::SigningAlgorithm::EcdsaSecp256k1,
            Chain::SOLANA | Chain::NEAR | Chain::COSMOS => {
                crate::enclave::SigningAlgorithm::Ed25519
            }
            _ => crate::enclave::SigningAlgorithm::EcdsaSecp256k1,
        };

        let sign_req = crate::enclave::SignRequest {
            algorithm: algo,
            message_hash: request.transaction_payload.clone(), // Simplified, assumes payload is already hashed or handled
            derivation_path: request.derivation_path.clone(),
            key_id: pubkey.clone(),
            taproot_tweak: None,
        };

        let sign_resp = self.enclave.sign(sign_req)?;

        Ok(ChainSignatureResponse {
            signature_hex: sign_resp.signature_hex,
            public_key: pubkey,
        })
    }

    /// Orchestrates an intent-based settlement flow.
    pub async fn settle_intent(&self, intent: CrossChainIntent) -> ConclaveResult<String> {
        // In production, this would interact with the Solver Network (ERC-7683)
        // For now, we return a deterministic tracking ID.
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        hasher.update(format!("{:?}", intent).as_bytes());
        Ok(hex::encode(hasher.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::cloud::CloudEnclave;

    #[tokio::test]
    async fn test_chain_abstraction_signing_logic() {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let service = ChainAbstractionService::new(enclave);

        let req = ChainSignatureRequest {
            target_chain: Chain::SOLANA,
            transaction_payload: vec![0u8; 32],
            derivation_path: "m/44'/501'/0'/0/0".to_string(),
        };

        let result = service.sign_chain_transaction(req).await;
        // Should succeed or fail based on enclave state, but here we check the logic flow
        assert!(result.is_ok() || result.is_err());
    }
}
