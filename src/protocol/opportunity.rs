use crate::enclave::{EnclaveManager, SignRequest, SigningAlgorithm};
use crate::protocol::asset::Chain;
use crate::protocol::economy::{DualStackIntent, YieldEngine};
use crate::protocol::rails::{RailProxy, SovereignHandshake, SwapRequest};
use crate::{ConclaveError, ConclaveResult};
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
        from_chain: Chain,
        from_symbol: String,
        to_chain: Chain,
        to_symbol: String,
        amount: u64,
        recipient: String,
        rail: String,
    },
}

pub struct OpportunityDispatcher<'a> {
    enclave: &'a dyn EnclaveManager,
    rail_proxy: Arc<RailProxy>,
}

impl<'a> OpportunityDispatcher<'a> {
    pub fn new(enclave: &'a dyn EnclaveManager, rail_proxy: Arc<RailProxy>) -> Self {
        Self {
            enclave,
            rail_proxy,
        }
    }

    pub async fn execute(&self, payload: OpportunityPayload) -> ConclaveResult<String> {
        match payload {
            OpportunityPayload::DualStack {
                amount_sbtc,
                amount_stx,
                lock_period,
            } => {
                let engine = YieldEngine::new(self.enclave);
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
                rail,
            } => {
                let asset_registry = &self.rail_proxy.asset_registry;
                let from_asset = asset_registry
                    .list_assets()
                    .into_iter()
                    .find(|(id, _)| id.chain == from_chain && id.symbol == from_symbol)
                    .ok_or(ConclaveError::InvalidPayload)?
                    .0;
                let to_asset = asset_registry
                    .list_assets()
                    .into_iter()
                    .find(|(id, _)| id.chain == to_chain && id.symbol == to_symbol)
                    .ok_or(ConclaveError::InvalidPayload)?
                    .0;

                let request = SwapRequest {
                    from_asset,
                    to_asset,
                    amount,
                    recipient_address: recipient,
                    attribution: None,
                };

                let intent = self.rail_proxy.prepare_intent(&rail, request)?;

                let (algo, derivation_path) = match from_chain {
                    Chain::SOLANA | Chain::NEAR | Chain::STELLAR | Chain::SUI | Chain::APTOS => {
                        (SigningAlgorithm::Ed25519, "m/44'/501'/0'/0/0".to_string())
                    }
                    Chain::ETHEREUM | Chain::BASE | Chain::ARBITRUM | Chain::POLYGON => (
                        SigningAlgorithm::EcdsaSecp256k1,
                        "m/44'/60'/0'/0/0".to_string(),
                    ),
                    Chain::STACKS => (
                        SigningAlgorithm::EcdsaSecp256k1,
                        "m/44'/5757'/0'/0/0".to_string(),
                    ),
                    _ => (
                        SigningAlgorithm::EcdsaSecp256k1,
                        "m/44'/0'/0'/0/0".to_string(),
                    ),
                };

                let sign_resp = self.enclave.sign(SignRequest {
                    algorithm: algo,
                    message_hash: intent.signable_hash.clone(),
                    derivation_path,
                    key_id: "opportunity_key".to_string(),
                    taproot_tweak: None,
                })?;

                let resp = self
                    .rail_proxy
                    .broadcast_signed_intent(
                        intent,
                        sign_resp.signature_hex,
                        sign_resp.device_attestation,
                    )
                    .await?;

                Ok(resp.transaction_id)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::cloud::CloudEnclave;
    use crate::protocol::asset::AssetRegistry;
    use crate::protocol::business::BusinessRegistry;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_opportunity_dispatcher_instantiation() {
        let enclave = CloudEnclave::new("http://localhost".to_string()).unwrap();
        let registry = Arc::new(AssetRegistry::new());
        let business = Arc::new(BusinessRegistry::new());
        let rail_proxy = Arc::new(RailProxy::new(
            "http://localhost".to_string(),
            reqwest::Client::new(),
            registry,
            business,
        ));

        let dispatcher = OpportunityDispatcher::new(&enclave, rail_proxy);
        assert!(dispatcher.rail_proxy.asset_registry.list_assets().len() > 0);
    }
}
