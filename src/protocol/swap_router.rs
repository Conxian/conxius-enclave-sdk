use crate::protocol::asset::AssetIdentifier;
use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExactOutSwap {
    pub input_asset: AssetIdentifier,
    pub output_asset: AssetIdentifier,
    pub target_output_amount: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapQuoteRequest {
    pub input_asset: AssetIdentifier,
    pub output_asset: AssetIdentifier,
    pub target_amount: u128,
    pub is_exact_out: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapQuoteResponse {
    pub input_amount: u128,
    pub output_amount: u128,
    pub router_path: String,
    pub estimated_gas: u64,
    pub price_impact: f64,
}

pub struct SwapRouter {
    pub gateway_endpoint: String,
    pub http_client: reqwest::Client,
}

impl SwapRouter {
    pub fn new(gateway_endpoint: String, http_client: reqwest::Client) -> Self {
        Self {
            gateway_endpoint,
            http_client,
        }
    }

    /// Orchestrates Exact-Out routing across Jupiter (Solana) and 0x (EVM) via Conxian Gateway.
    pub async fn get_exact_out_quote(&self, swap: ExactOutSwap) -> ConclaveResult<SwapQuoteResponse> {
        let url = format!("{}/v1/quotes/exact-out", self.gateway_endpoint);

        let request = SwapQuoteRequest {
            input_asset: swap.input_asset,
            output_asset: swap.output_asset,
            target_amount: swap.target_output_amount,
            is_exact_out: true,
        };

        let response = self
            .http_client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| ConclaveError::NetworkError(format!("Quote request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(ConclaveError::RailError(format!(
                "Gateway quote error: {}",
                response.status()
            )));
        }

        let quote = response
            .json::<SwapQuoteResponse>()
            .await
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid quote response: {}", e)))?;

        Ok(quote)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::asset::Chain;

    #[test]
    fn test_quote_request_serialization() {
        let req = SwapQuoteRequest {
            input_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            output_asset: AssetIdentifier {
                chain: Chain::ETHEREUM,
                symbol: "USDC".to_string(),
            },
            target_amount: 1000000,
            is_exact_out: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("BITCOIN"));
        assert!(json.contains("USDC"));
    }
}
