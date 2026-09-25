use crate::protocol::asset::Chain;
use crate::protocol::rails::TrustTier;
use crate::protocol::rails::VerifiedOperation;
use crate::protocol::rails::{SovereignRail, SwapIntent, SwapRequest, SwapResponse};
use crate::{ConclaveError, ConclaveResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub(crate) struct BoltzRail {
    pub(crate) gateway_url: String,
    pub(crate) http_client: reqwest::Client,
}

#[derive(Debug, Serialize, Deserialize)]
struct BroadcastSwapRequest {
    intent: SwapIntent,
    authorization: super::VerifiedOperationAuthorization,
}

impl super::sealed::SovereignRail for BoltzRail {}

#[async_trait(?Send)]
impl SovereignRail for BoltzRail {
    fn name(&self) -> &'static str {
        "boltz"
    }
    fn trust_tier(&self) -> TrustTier {
        TrustTier::T3
    }

    fn validate_request(&self, request: &SwapRequest) -> ConclaveResult<Option<String>> {
        if request.amount == 0 {
            return Err(ConclaveError::RailError(
                "Boltz rail requires swap amount to be greater than zero".to_string(),
            ));
        }

        if request.recipient_address.trim().is_empty() {
            return Err(ConclaveError::RailError(
                "Recipient address required for Boltz swap".to_string(),
            ));
        }

        // Boltz atomic swap validation
        if request.from_asset.chain != Chain::LIGHTNING
            && request.to_asset.chain != Chain::LIGHTNING
        {
            return Err(ConclaveError::RailError(
                "Boltz rail requires Lightning as one of the swap legs".to_string(),
            ));
        }

        Ok(Some(format!(
            "BOLTZ_{}_TO_{}",
            request.from_asset.chain, request.to_asset.chain
        )))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::asset::AssetIdentifier;

    fn test_boltz_rail() -> BoltzRail {
        BoltzRail {
            gateway_url: "https://gateway.conxian-labs.com".to_string(),
            http_client: reqwest::Client::new(),
        }
    }

    #[test]
    fn test_boltz_validate_request_zero_amount() {
        let rail = test_boltz_rail();
        let request = SwapRequest {
            from_asset: AssetIdentifier {
                chain: Chain::LIGHTNING,
                symbol: "BTC".to_string(),
            },
            to_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            amount: 0,
            recipient_address: "bc1qtest".to_string(),
            attribution: None,
        };

        let err = rail.validate_request(&request).unwrap_err();
        assert!(matches!(err, ConclaveError::RailError(msg) if msg.contains("greater than zero")));
    }

    #[test]
    fn test_boltz_validate_request_empty_recipient() {
        let rail = test_boltz_rail();
        let request = SwapRequest {
            from_asset: AssetIdentifier {
                chain: Chain::LIGHTNING,
                symbol: "BTC".to_string(),
            },
            to_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            amount: 1000,
            recipient_address: "   ".to_string(),
            attribution: None,
        };

        let err = rail.validate_request(&request).unwrap_err();
        assert!(matches!(err, ConclaveError::RailError(msg) if msg.contains("Recipient address required")));
    }

    #[test]
    fn test_boltz_validate_request_valid() {
        let rail = test_boltz_rail();
        let request = SwapRequest {
            from_asset: AssetIdentifier {
                chain: Chain::LIGHTNING,
                symbol: "BTC".to_string(),
            },
            to_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            amount: 1000,
            recipient_address: "bc1qtest".to_string(),
            attribution: None,
        };

        let tag = rail.validate_request(&request).unwrap().unwrap();
        assert_eq!(tag, "BOLTZ_LIGHTNING_TO_BITCOIN");
    }
}
