use crate::{ConclaveResult, enclave::EnclaveManager};
use crate::protocol::intent::{CrossChainIntent, ResolvedCrossChainOrder, AssetAmount};
#[allow(unused_imports)]
use crate::protocol::asset::{AssetRegistry, AssetIdentifier, Chain};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Chain Abstraction Service (v1.9.2)
/// Orchestrates NEAR-style chain signatures and universal intent settlement.
pub struct ChainAbstractionService {
    enclave: Arc<dyn EnclaveManager>,
    _assets: Arc<AssetRegistry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSignatureRequest {
    pub target_chain: Chain,
    pub payload: Vec<u8>,
    pub derivation_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSignatureResponse {
    pub signature_hex: String,
    pub target_address: String,
}

impl ChainAbstractionService {
    pub fn new(enclave: Arc<dyn EnclaveManager>, _assets: Arc<AssetRegistry>) -> Self {
        Self { enclave, _assets }
    }

    /// Resolves a cross-chain intent into a canonical order format (ERC-7683).
    pub fn resolve_intent(&self, intent: CrossChainIntent) -> ConclaveResult<ResolvedCrossChainOrder> {
        let input_assets = vec![AssetAmount {
            asset: intent.input_asset,
            amount: intent.input_amount,
        }];

        let output_assets = vec![AssetAmount {
            asset: intent.output_asset,
            amount: intent.output_amount,
        }];

        Ok(ResolvedCrossChainOrder {
            user: intent.recipient.clone(),
            origin_chain_id: 1, // Defaulting to Ethereum Mainnet for resolution demo
            open_deadline: 3600,
            fill_deadline: 7200,
            swapper: intent.recipient,
            nonce: 0,
            input_assets,
            output_assets,
        })
    }

    /// Generates a chain-specific signature for a universal account.
    /// This follows the NEAR chain signature model where one master key
    /// in the TEE generates signatures for multiple destination chains.
    pub fn sign_for_chain(&self, request: ChainSignatureRequest) -> ConclaveResult<ChainSignatureResponse> {
        let algorithm = match request.target_chain {
            Chain::BITCOIN | Chain::ETHEREUM | Chain::STACKS =>
                crate::enclave::SigningAlgorithm::EcdsaSecp256k1,
            Chain::SOLANA =>
                crate::enclave::SigningAlgorithm::Ed25519,
            _ => crate::enclave::SigningAlgorithm::EcdsaSecp256k1,
        };

        let sign_request = crate::enclave::SignRequest {
            algorithm,
            message_hash: request.payload,
            derivation_path: request.derivation_path,
            key_id: "universal_master_key".to_string(), // Canonical key ID for chain abstraction
            taproot_tweak: None,
        };

        let response = self.enclave.sign(sign_request)?;

        // In a real implementation, we would derive the target address
        // based on the derived public key for that chain.
        Ok(ChainSignatureResponse {
            signature_hex: response.signature_hex,
            target_address: "0x_derived_address_placeholder".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::cloud::CloudEnclave;

    #[test]
    fn test_resolve_intent_logic() {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let assets = Arc::new(AssetRegistry::new());
        let service = ChainAbstractionService::new(enclave, assets);

        let intent = CrossChainIntent {
            input_asset: AssetIdentifier { chain: Chain::BITCOIN, symbol: "BTC".to_string() },
            output_asset: AssetIdentifier { chain: Chain::ETHEREUM, symbol: "USDC".to_string() },
            input_amount: 1000000,
            output_amount: 65000000000,
            destination_chain: Chain::ETHEREUM,
            recipient: "0xrecipient".to_string(),
        };

        let resolved = service.resolve_intent(intent).unwrap();
        assert_eq!(resolved.input_assets.len(), 1);
        assert_eq!(resolved.output_assets[0].asset.symbol, "USDC");
    }
}
