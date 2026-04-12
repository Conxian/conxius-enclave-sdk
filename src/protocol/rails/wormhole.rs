use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use crate::protocol::rails::{SovereignRail, SwapIntent, SwapRequest, SwapResponse};

pub struct WormholeRail {
    pub gateway_url: String,
    pub http_client: reqwest::Client,
}

#[derive(Debug, Serialize, Deserialize)]
struct BroadcastSwapRequest {
    pub intent: SwapIntent,
    pub signature: String,
}

#[async_trait]
impl SovereignRail for WormholeRail {
    fn name(&self) -> &'static str {
        "wormhole"
    }

    fn validate_request(&self, request: &SwapRequest) -> Result<Option<String>, String> {
        if request.recipient_address.len() < 40 {
            return Err("Invalid EVM/Solana address for Wormhole transceiver".to_string());
        }
        Ok(Some(format!(
            "WORMHOLE_VAA_TARGET_{}",
            request.to_asset.chain
        )))
    }

    async fn execute_swap(
        &self,
        intent: SwapIntent,
        signature: String,
    ) -> Result<SwapResponse, String> {
        let url = format!("{}/v1/swap/execute", self.gateway_url);
        let payload = BroadcastSwapRequest { intent, signature };

        let response = self.http_client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Gateway request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Gateway returned error: {}", response.status()));
        }

        let swap_resp = response
            .json::<SwapResponse>()
            .await
            .map_err(|e| format!("Invalid gateway response: {}", e))?;

        Ok(swap_resp)
    }
}
