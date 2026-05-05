use crate::protocol::asset::Chain;
use crate::protocol::rails::{SovereignRail, SwapIntent, SwapRequest, SwapResponse};
use crate::{ConclaveError, ConclaveResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub struct BoltzRail {
    pub gateway_url: String,
    pub http_client: reqwest::Client,
}

#[derive(Debug, Serialize, Deserialize)]
struct BroadcastSwapRequest {
    pub intent: SwapIntent,
    pub signature: String,
}

#[async_trait]
impl SovereignRail for BoltzRail {
    fn name(&self) -> &'static str {
        "boltz"
    }

    fn validate_request(&self, request: &SwapRequest) -> ConclaveResult<Option<String>> {
        // Boltz atomic swap validation
        if request.from_asset.chain != Chain::LIGHTNING
            && request.to_asset.chain != Chain::LIGHTNING
        {
            return Err(ConclaveError::RailError("Boltz rail requires Lightning as one of the swap legs".to_string()));
        }

        Ok(Some(format!(
            "BOLTZ_{}_TO_{}",
            request.from_asset.chain, request.to_asset.chain
        )))
    }

    async fn execute_swap(
        &self,
        intent: SwapIntent,
        signature: String,
    ) -> ConclaveResult<SwapResponse> {
        let url = format!("{}/v1/swap/execute", self.gateway_url);
        let payload = BroadcastSwapRequest { intent, signature };

        let response = self
            .http_client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| ConclaveError::NetworkError(format!("Gateway request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(ConclaveError::NetworkError(format!("Gateway returned error: {}", response.status())));
        }

        let swap_resp = response
            .json::<SwapResponse>()
            .await
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid gateway response: {}", e)))?;

        Ok(swap_resp)
    }
}
