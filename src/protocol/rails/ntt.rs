use crate::protocol::rails::{SovereignRail, SwapIntent, SwapRequest, SwapResponse};
use crate::{ConclaveError, ConclaveResult};
use async_trait::async_trait;
use serde_json::json;

pub struct NTTRail {
    pub gateway_url: String,
    pub http_client: reqwest::Client,
}

#[async_trait]
impl SovereignRail for NTTRail {
    fn name(&self) -> &'static str {
        "ntt"
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

    async fn execute_swap(
        &self,
        intent: SwapIntent,
        signature: String,
    ) -> ConclaveResult<SwapResponse> {
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

    #[tokio::test]
    async fn test_ntt_rail_name() {
        let rail = NTTRail {
            gateway_url: "https://api.conxian.io".to_string(),
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
            recipient_address: "0x...".to_string(),
            attribution: None,
        };

        assert!(rail.validate_request(&req).is_ok());
    }
}
