use crate::protocol::asset::AssetIdentifier;
use crate::protocol::rails::TrustTier;
use crate::protocol::rails::{SovereignRail, SwapIntent, SwapRequest, SwapResponse};
use crate::{ConclaveError, ConclaveResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Implementation of the x402 (Payment-Required) protocol for industrial intent.
/// This rail handles autonomous payments triggered by HTTP 402 headers or ERP intents.
pub struct X402Rail {
    pub gateway_url: String,
    pub http_client: reqwest::Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402Intent {
    pub invoice_id: String,
    pub amount_due: u64,
    pub asset: AssetIdentifier,
    pub merchant_address: String,
    pub fallback_url: Option<String>,
}

#[async_trait]
impl SovereignRail for X402Rail {
    fn name(&self) -> &'static str {
        "x402_industrial"
    }
    fn trust_tier(&self) -> TrustTier {
        TrustTier::T1
    }

    fn validate_request(&self, request: &SwapRequest) -> ConclaveResult<Option<String>> {
        // x402 requests must have a valid recipient (the merchant/ERP endpoint)
        if request.recipient_address.is_empty() {
            return Err(ConclaveError::InvalidPayload);
        }

        Ok(Some(format!(
            "X402_INTENT_v1:{}",
            request.recipient_address
        )))
    }

    async fn execute_swap(
        &self,
        intent: SwapIntent,
        signature: String,
    ) -> ConclaveResult<SwapResponse> {
        let url = format!("{}/v1/rails/x402/settle", self.gateway_url);

        #[derive(Serialize)]
        struct X402SettleRequest {
            intent: SwapIntent,
            signature: String,
        }

        let response = self
            .http_client
            .post(&url)
            .json(&X402SettleRequest { intent, signature })
            .send()
            .await
            .map_err(|e| ConclaveError::RailError(format!("x402 settlement failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(ConclaveError::RailError(format!(
                "x402 gateway error: {}",
                response.status()
            )));
        }

        let swap_resp = response
            .json::<SwapResponse>()
            .await
            .map_err(|e| ConclaveError::RailError(format!("Invalid x402 response: {}", e)))?;

        Ok(swap_resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::asset::{AssetIdentifier, Chain};

    #[test]
    fn test_x402_rail_validation() {
        let rail = X402Rail {
            gateway_url: "https://gateway.conxian-labs.com".to_string(),
            http_client: reqwest::Client::new(),
        };

        let request = SwapRequest {
            from_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            to_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            amount: 100,
            recipient_address: "merchant_endpoint".to_string(),
            attribution: None,
        };

        let result = rail.validate_request(&request);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().unwrap(), "X402_INTENT_v1:merchant_endpoint");
    }
}
