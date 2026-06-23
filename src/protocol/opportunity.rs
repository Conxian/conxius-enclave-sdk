use crate::{ConclaveResult, ConclaveError};
use crate::enclave::EnclaveManager;
use crate::protocol::economy::{DualStackIntent, YieldEngine};
use crate::protocol::rails::{SwapRequest, RailProxy, SovereignHandshake};
use crate::protocol::asset::{AssetIdentifier, AssetRegistry, Chain};
use crate::protocol::business::BusinessRegistry;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OpportunityPayload {
    DualStack {
        amount_sbtc: u64,
        amount_stx: u64,
        lock_period: u32,
    },
    Swap {
        from_chain: String,
        from_symbol: String,
        to_chain: String,
        to_symbol: String,
        amount: u64,
        recipient: String,
        rail_type: String,
    },
}

pub struct OpportunityDispatcher {
    enclave: Arc<dyn EnclaveManager>,
    assets: Arc<AssetRegistry>,
    businesses: Arc<BusinessRegistry>,
    gateway_url: String,
}

impl OpportunityDispatcher {
    pub fn new(
        enclave: Arc<dyn EnclaveManager>,
        assets: Arc<AssetRegistry>,
        businesses: Arc<BusinessRegistry>,
        gateway_url: String,
    ) -> Self {
        Self {
            enclave,
            assets,
            businesses,
            gateway_url,
        }
    }

    pub async fn execute(&self, payload: OpportunityPayload) -> ConclaveResult<String> {
        match payload {
            OpportunityPayload::DualStack {
                amount_sbtc,
                amount_stx,
                lock_period,
            } => {
                let engine = YieldEngine::new(self.enclave.as_ref());
                let (sig, _) = engine.dual_stack(DualStackIntent {
                    amount_sbtc,
                    amount_stx,
                    lock_period,
                })?;
                Ok(sig)
            }
            OpportunityPayload::Swap {
                from_chain,
                from_symbol,
                to_chain,
                to_symbol,
                amount,
                recipient,
                rail_type,
            } => {
                let proxy = RailProxy::new(
                    self.gateway_url.clone(),
                    reqwest::Client::new(),
                    self.assets.clone(),
                    self.businesses.clone(),
                );

                let from_chain_enum = self.parse_chain(&from_chain)?;
                let to_chain_enum = self.parse_chain(&to_chain)?;

                let request = SwapRequest {
                    from_asset: AssetIdentifier {
                        chain: from_chain_enum,
                        symbol: from_symbol,
                    },
                    to_asset: AssetIdentifier {
                        chain: to_chain_enum,
                        symbol: to_symbol,
                    },
                    amount,
                    recipient_address: recipient,
                    attribution: None,
                };

                let intent = proxy.prepare_intent(&rail_type, request)?;

                let pubkey = self.enclave.get_public_key("m/44'/5757'/0'/0/swap")?;
                let sign_req = crate::enclave::SignRequest {
                    algorithm: crate::enclave::SigningAlgorithm::EcdsaSecp256k1,
                    message_hash: intent.signable_hash.clone(),
                    derivation_path: "m/44'/5757'/0'/0/swap".to_string(),
                    key_id: pubkey,
                    taproot_tweak: None,
                };

                let sign_resp = self.enclave.sign(sign_req)?;

                let response = proxy.broadcast_signed_intent(intent, sign_resp.signature_hex, None).await?;
                Ok(response.transaction_id)
            }
        }
    }

    fn parse_chain(&self, chain: &str) -> ConclaveResult<Chain> {
        match chain.to_uppercase().as_str() {
            "BITCOIN" => Ok(Chain::BITCOIN),
            "ETHEREUM" => Ok(Chain::ETHEREUM),
            "STACKS" => Ok(Chain::STACKS),
            "SOLANA" => Ok(Chain::SOLANA),
            "ARBITRUM" => Ok(Chain::ARBITRUM),
            "BASE" => Ok(Chain::BASE),
            "ROOTSTOCK" => Ok(Chain::ROOTSTOCK),
            "BOB" => Ok(Chain::BOB),
            "MEZO" => Ok(Chain::MEZO),
            "BABYLON" => Ok(Chain::BABYLON),
            "BOTANIX" => Ok(Chain::BOTANIX),
            "CITREA" => Ok(Chain::CITREA),
            "COSMOS" => Ok(Chain::COSMOS),
            _ => Err(ConclaveError::InvalidPayload),
        }
    }
}
