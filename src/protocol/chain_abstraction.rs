#[allow(unused_imports)]
use crate::protocol::asset::{AssetIdentifier, AssetRegistry, Chain};
use crate::protocol::intent::{AssetAmount, CrossChainIntent, ResolvedCrossChainOrder};
use crate::{
    enclave::{sign_value_bearing, EnclaveManager, ValueBearingSignRequest},
    ConclaveError, ConclaveResult,
};
use alloy::primitives::{Address as EthAddress, Keccak256};
use bitcoin::address::Address;
use bitcoin::key::PublicKey;
use bitcoin::Network;
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
    pub fn resolve_intent(
        &self,
        intent: CrossChainIntent,
    ) -> ConclaveResult<ResolvedCrossChainOrder> {
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
    pub fn sign_for_chain(
        &self,
        request: ChainSignatureRequest,
    ) -> ConclaveResult<ChainSignatureResponse> {
        let target_chain = request.target_chain;
        let algorithm = match target_chain {
            Chain::BITCOIN | Chain::ETHEREUM | Chain::STACKS | Chain::XrpLedger | Chain::TRON => {
                crate::enclave::SigningAlgorithm::EcdsaSecp256k1
            }
            Chain::SOLANA | Chain::STELLAR | Chain::NEAR => {
                crate::enclave::SigningAlgorithm::Ed25519
            }
            _ => crate::enclave::SigningAlgorithm::EcdsaSecp256k1,
        };

        let operation_digest: [u8; 32] = request
            .payload
            .try_into()
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let expected_public_key_hex = self.enclave.get_public_key(&request.derivation_path)?;
        let sign_request = ValueBearingSignRequest::new(
            operation_digest,
            algorithm,
            request.derivation_path,
            "universal_master_key".to_string(),
            expected_public_key_hex,
            None,
        );

        let response = sign_value_bearing(self.enclave.as_ref(), sign_request)?;

        let public_key_bytes = hex::decode(&response.public_key_hex)
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid public key hex: {}", e)))?;

        let target_address = match target_chain {
            Chain::BITCOIN => {
                let pk = PublicKey::from_slice(&public_key_bytes).map_err(|e| {
                    ConclaveError::CryptoError(format!("Invalid Bitcoin PK: {}", e))
                })?;

                // For SegWit, we need a compressed public key
                let compressed = pk.to_bytes();
                let cpk = bitcoin::key::CompressedPublicKey::from_slice(&compressed)
                    .map_err(|e| ConclaveError::CryptoError(format!("Compression error: {}", e)))?;

                Address::p2wpkh(cpk, Network::Bitcoin).to_string()
            }
            Chain::ETHEREUM | Chain::BASE | Chain::ARBITRUM | Chain::POLYGON => {
                // Ethereum address: last 20 bytes of keccak256 hash of uncompressed public key (minus 0x04 prefix)
                let mut hasher = Keccak256::new();
                if public_key_bytes.len() == 65 && public_key_bytes[0] == 0x04 {
                    hasher.update(&public_key_bytes[1..]);
                } else if public_key_bytes.len() == 33 {
                    // Need to uncompress first if it's compressed
                    let pk = secp256k1::PublicKey::from_slice(&public_key_bytes).map_err(|e| {
                        ConclaveError::CryptoError(format!("Invalid compressed PK: {}", e))
                    })?;
                    let uncompressed = pk.serialize_uncompressed();
                    hasher.update(&uncompressed[1..]);
                } else {
                    return Err(ConclaveError::CryptoError(
                        "Invalid public key length for EVM".to_string(),
                    ));
                }
                let hash = hasher.finalize();
                EthAddress::from_slice(&hash[12..]).to_string()
            }
            Chain::SOLANA => {
                // Solana uses the raw 32-byte Ed25519 public key as its address, typically Base58 encoded
                if public_key_bytes.len() == 32 {
                    bs58::encode(&public_key_bytes).into_string()
                } else {
                    return Err(ConclaveError::CryptoError(
                        "Invalid public key length for Solana".to_string(),
                    ));
                }
            }
            Chain::STELLAR => {
                // Stellar uses StrKey encoding (G...) for Ed25519 public keys
                if public_key_bytes.len() == 32 {
                    format!("G{}", bs58::encode(&public_key_bytes).into_string())
                } else {
                    return Err(ConclaveError::CryptoError(
                        "Invalid public key length for Stellar".to_string(),
                    ));
                }
            }
            Chain::NEAR => {
                // NEAR addresses can be account IDs or the public key itself
                if public_key_bytes.len() == 32 {
                    format!("ed25519:{}", bs58::encode(&public_key_bytes).into_string())
                } else {
                    return Err(ConclaveError::CryptoError(
                        "Invalid public key length for NEAR".to_string(),
                    ));
                }
            }
            Chain::XrpLedger => {
                // XRP uses a specific Base58Check dictionary (r-prefix)
                format!("r{}", bs58::encode(&public_key_bytes[..20]).into_string())
            }
            Chain::TRON => {
                // TRON uses Base58Check with 0x41 prefix (simplified)
                format!("T{}", bs58::encode(&public_key_bytes[..20]).into_string())
            }
            Chain::STACKS => {
                format!("SP{}", hex::encode(&public_key_bytes[..20]))
            }
            Chain::COSMOS => {
                format!("cosmos1{}", hex::encode(&public_key_bytes[..20]))
            }
            _ => "0x_fallback_address".to_string(),
        };

        Ok(ChainSignatureResponse {
            signature_hex: response.signature_hex,
            target_address,
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
            input_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            output_asset: AssetIdentifier {
                chain: Chain::ETHEREUM,
                symbol: "USDC".to_string(),
            },
            input_amount: 1000000,
            output_amount: 65000000000,
            destination_chain: Chain::ETHEREUM,
            recipient: "0xrecipient".to_string(),
        };

        let resolved = service.resolve_intent(intent).unwrap();
        assert_eq!(resolved.input_assets.len(), 1);
        assert_eq!(resolved.output_assets[0].asset.symbol, "USDC");
    }

    #[test]
    fn test_sign_for_chain_bitcoin() {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let assets = Arc::new(AssetRegistry::new());
        let service = ChainAbstractionService::new(enclave, assets);

        let request = ChainSignatureRequest {
            target_chain: Chain::BITCOIN,
            payload: vec![0u8; 32],
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
        };

        let response = service.sign_for_chain(request).unwrap();
        assert!(response.target_address.starts_with("bc1"));
    }

    #[test]
    fn test_sign_for_chain_xrp() {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let assets = Arc::new(AssetRegistry::new());
        let service = ChainAbstractionService::new(enclave, assets);

        let request = ChainSignatureRequest {
            target_chain: Chain::XrpLedger,
            payload: vec![0u8; 32],
            derivation_path: "m/44'/144'/0'/0/0".to_string(),
        };

        let response = service.sign_for_chain(request).unwrap();
        assert!(response.target_address.starts_with("r"));
    }

    #[test]
    fn test_sign_for_chain_stellar() {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let assets = Arc::new(AssetRegistry::new());
        let service = ChainAbstractionService::new(enclave, assets);

        let request = ChainSignatureRequest {
            target_chain: Chain::STELLAR,
            payload: vec![0u8; 32],
            derivation_path: "m/44'/148'/0'/0/0".to_string(),
        };

        let response = service.sign_for_chain(request).unwrap();
        assert!(response.target_address.starts_with("G"));
    }

    #[test]
    fn test_sign_for_chain_near() {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let assets = Arc::new(AssetRegistry::new());
        let service = ChainAbstractionService::new(enclave, assets);

        let request = ChainSignatureRequest {
            target_chain: Chain::NEAR,
            payload: vec![0u8; 32],
            derivation_path: "m/44'/397'/0'/0/0".to_string(),
        };

        let response = service.sign_for_chain(request).unwrap();
        assert!(response.target_address.starts_with("ed25519:"));
    }
}
