use crate::protocol::asset::{AssetIdentifier, Chain};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct ExactOutSwap {
    pub input_asset: AssetIdentifier,
    pub output_asset: AssetIdentifier,
    pub target_output_amount: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GatewayQuoteRequest {
    pub from_chain: Chain,
    pub from_symbol: String,
    pub to_chain: Chain,
    pub to_symbol: String,
    pub exact_out_amount: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GatewayQuoteResponse {
    pub input_amount: u128,
    pub quote_id: String,
}

pub struct SwapRouter {
    pub gateway_url: String,
    pub http_client: reqwest::Client,
}

impl SwapRouter {
    pub fn new(gateway_url: String, http_client: reqwest::Client) -> Self {
        Self {
            gateway_url,
            http_client,
        }
    }

    pub async fn get_exact_out_quote(&self, swap: ExactOutSwap) -> Result<u128, String> {
        let request = GatewayQuoteRequest {
            from_chain: swap.input_asset.chain,
            from_symbol: swap.input_asset.symbol,
            to_chain: swap.output_asset.chain,
            to_symbol: swap.output_asset.symbol,
            exact_out_amount: swap.target_output_amount,
        };

        let url = format!("{}/v1/quotes/exact-out", self.gateway_url);
        let resp = self
            .http_client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("Network error: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Gateway error: HTTP {}", resp.status()));
        }

        let quote: GatewayQuoteResponse = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse quote: {}", e))?;

        Ok(quote.input_amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swap_router_instantiation() {
        let router = SwapRouter::new("http://localhost".to_string(), reqwest::Client::new());
        assert_eq!(router.gateway_url, "http://localhost");
    }
}
