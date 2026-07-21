use crate::protocol::rails::TrustTier;
use crate::protocol::rails::VerifiedOperation;
use crate::protocol::rails::{SovereignRail, SwapIntent, SwapRequest, SwapResponse};
use crate::{ConclaveError, ConclaveResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub(crate) struct ChangellyRail {
    pub(crate) gateway_url: String,
    pub(crate) http_client: reqwest::Client,
}

#[derive(Debug, Serialize, Deserialize)]
struct BroadcastSwapRequest {
    intent: SwapIntent,
    authorization: super::VerifiedOperationAuthorization,
}

impl super::sealed::SovereignRail for ChangellyRail {}

#[async_trait(?Send)]
impl SovereignRail for ChangellyRail {
    fn name(&self) -> &'static str {
        "changelly"
    }
    fn trust_tier(&self) -> TrustTier {
        TrustTier::T3
    }

    fn validate_request(&self, request: &SwapRequest) -> ConclaveResult<Option<String>> {
        // Changelly specific validation
        if request.amount < 100 {
            return Err(ConclaveError::RailError(
                "Amount below Changelly minimum".to_string(),
            ));
        }
        Ok(None)
    }

    async fn execute_swap(&self, operation: VerifiedOperation) -> ConclaveResult<SwapResponse> {
        super::reject_builtin_adapter_dispatch()?;
        let (intent, authorization) = operation.into_parts();
        let url = format!("{}/v1/swap/execute", self.gateway_url);
        let payload = BroadcastSwapRequest {
            intent,
            authorization,
        };

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
