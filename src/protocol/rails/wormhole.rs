use crate::protocol::rails::TrustTier;
use crate::protocol::rails::VerifiedOperation;
use crate::protocol::rails::{SovereignRail, SwapIntent, SwapRequest, SwapResponse};
use crate::{ConclaveError, ConclaveResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub(crate) struct WormholeRail {
    pub(crate) gateway_url: String,
    pub(crate) http_client: reqwest::Client,
}

#[derive(Debug, Serialize, Deserialize)]
struct BroadcastSwapRequest {
    intent: SwapIntent,
    signature: String,
}

impl super::sealed::SovereignRail for WormholeRail {}

#[async_trait(?Send)]
impl SovereignRail for WormholeRail {
    fn name(&self) -> &'static str {
        "wormhole"
    }
    fn trust_tier(&self) -> TrustTier {
        TrustTier::T3
    }

    fn validate_request(&self, request: &SwapRequest) -> ConclaveResult<Option<String>> {
        if request.recipient_address.len() < 40 {
            return Err(ConclaveError::RailError(
                "Invalid EVM/Solana address for Wormhole transceiver".to_string(),
            ));
        }
        Ok(Some(format!(
            "WORMHOLE_VAA_TARGET_{}",
            request.to_asset.chain
        )))
    }

    async fn execute_swap(&self, operation: VerifiedOperation) -> ConclaveResult<SwapResponse> {
        let (intent, signature) = operation.into_parts();
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
