use crate::enclave::{
    sign_value_bearing, EnclaveManager, OperationContext, SignerKeyBinding, SigningAlgorithm,
    TrustRequirement, ValueBearingPurpose, ValueBearingSignRequest, VALUE_BEARING_POLICY_ID,
};
use crate::protocol::asset::{AssetIdentifier, Chain};
use crate::protocol::economy::{DualStackIntent, YieldEngine};
use crate::protocol::intent::SwapRequest;
use crate::protocol::rails::{RailProxy, SovereignHandshake};
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
        rail: Option<String>,
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
                let registry = &self.rail_proxy.registry;
                let from_asset = AssetIdentifier {
                    chain: from_chain,
                    symbol: from_symbol,
                };
                let to_asset = AssetIdentifier {
                    chain: to_chain,
                    symbol: to_symbol,
                };
                registry.validate_asset(&from_asset)?;
                registry.validate_asset(&to_asset)?;

                let request = SwapRequest {
                    from_asset,
                    to_asset,
                    amount,
                    recipient_address: recipient,
                    attribution: None,
                };

                let rail_name = match rail {
                    Some(r) => r,
                    None => self.rail_proxy.discover_best_rail(&request)?,
                };

                let intent = self.rail_proxy.prepare_intent(&rail_name, request, None)?;

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

                let message_digest: [u8; 32] = intent
                    .signable_hash
                    .clone()
                    .try_into()
                    .map_err(|_| ConclaveError::InvalidPayload)?;
                let public_key = hex::decode(self.enclave.get_public_key(&derivation_path)?)
                    .map_err(|_| ConclaveError::InvalidPayload)?;
                let operation_domain = format!("conxian/opportunity/{from_chain:?}");
                let sign_request = ValueBearingSignRequest::new(
                    OperationContext::new(
                        operation_domain,
                        ValueBearingPurpose::Settlement,
                        message_digest.to_vec(),
                    )?,
                    algo,
                    TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID)?,
                    message_digest,
                    SignerKeyBinding::new("opportunity_key", derivation_path, public_key)?,
                    None,
                )?;
                let sign_response = sign_value_bearing(self.enclave, sign_request.clone())?;
                let operation = self.rail_proxy.authorize_verified_operation(
                    intent,
                    &sign_request,
                    sign_response,
                )?;
                let resp = self
                    .rail_proxy
                    .dispatch_verified_operation(operation)
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

    const TEST_EVM_ADDRESS: &str = "0x52908400098527886E0F7030069857D2E4169EE7";

    #[tokio::test]
    async fn test_opportunity_dispatcher_dynamic_rail() {
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

        let payload = OpportunityPayload::Swap {
            from_chain: Chain::BITCOIN,
            from_symbol: "BTC".to_string(),
            to_chain: Chain::ETHEREUM,
            to_symbol: "ETH".to_string(),
            amount: 100,
            recipient: TEST_EVM_ADDRESS.to_string(),
            rail: None,
        };

        let result = dispatcher.execute(payload).await;
        // In CI/local, this fails because localhost:80 is not a real gateway
        assert!(result.is_err());
    }
}
