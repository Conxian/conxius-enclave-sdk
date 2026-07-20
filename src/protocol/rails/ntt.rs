use crate::protocol::rails::TrustTier;
use crate::protocol::rails::VerifiedOperation;
use crate::protocol::rails::{SovereignRail, SwapRequest, SwapResponse};
use crate::{ConclaveError, ConclaveResult};
use async_trait::async_trait;
use serde_json::json;

pub(crate) struct NTTRail {
    pub(crate) gateway_url: String,
    pub(crate) http_client: reqwest::Client,
}

impl super::sealed::SovereignRail for NTTRail {}

#[async_trait(?Send)]
impl SovereignRail for NTTRail {
    fn name(&self) -> &'static str {
        "ntt"
    }
    fn trust_tier(&self) -> TrustTier {
        TrustTier::T3
    }

    fn validate_request(&self, request: &SwapRequest) -> ConclaveResult<Option<String>> {
        // NTT same-asset transfers validation
        if request.from_asset.symbol != request.to_asset.symbol {
            return Err(ConclaveError::RailError(
                "NTT rail only supports same-asset transfers".to_string(),
            ));
        }
        Ok(Some("NTT_WORMHOLE_V1".to_string()))
    }

    async fn execute_swap(&self, operation: VerifiedOperation) -> ConclaveResult<SwapResponse> {
        let (intent, signature) = operation.into_parts();
        let url = format!("{}/v1/rails/ntt/execute", self.gateway_url);
        let payload = json!({
            "intent": intent,
            "signature": signature,
            "framework": "wormhole-ntt"
        });

        let response = self
            .http_client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| ConclaveError::NetworkError(format!("Gateway request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(ConclaveError::NetworkError(format!(
                "Gateway returned error: {}",
                response.status()
            )));
        }

        let swap_resp = response
            .json::<SwapResponse>()
            .await
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid gateway response: {}", e)))?;

        Ok(swap_resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::asset::{AssetIdentifier, Chain};

    const TEST_EVM_ADDRESS: &str = "0x52908400098527886E0F7030069857D2E4169EE7";

    #[tokio::test]
    async fn test_ntt_rail_name() {
        let rail = NTTRail {
            gateway_url: "https://gateway.conxian-labs.com".to_string(),
            http_client: reqwest::Client::new(),
        };

        assert_eq!(rail.name(), "ntt");

        let req = SwapRequest {
            from_asset: AssetIdentifier {
                chain: Chain::ETHEREUM,
                symbol: "ETH".to_string(),
            },
            to_asset: AssetIdentifier {
                chain: Chain::ARBITRUM,
                symbol: "ETH".to_string(),
            },
            amount: 100,
            recipient_address: TEST_EVM_ADDRESS.to_string(),
            attribution: None,
        };

        assert!(rail.validate_request(&req).is_ok());
    }
}
