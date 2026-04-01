use crate::protocol::rails::{SovereignRail, SwapIntent, SwapRequest, SwapResponse};
use async_trait::async_trait;

pub struct BisqRail;

#[async_trait]
impl SovereignRail for BisqRail {
    fn name(&self) -> String {
        "Bisq".to_string()
    }
    fn validate_request(&self, request: &SwapRequest) -> Result<Option<String>, String> {
        if request.from_asset.chain == "BTC" && request.amount < 100_000 {
            return Err("Bisq P2P requires a minimum amount of 100,000 sats".to_string());
        }
        Ok(Some("BTC_SPV_VALIDATED".to_string()))
    }
    async fn execute_swap(
        &self,
        intent: SwapIntent,
        _signature: String,
    ) -> Result<SwapResponse, String> {
        Ok(SwapResponse {
            transaction_id: format!("BISQ-P2P-{}", hex::encode(&intent.signable_hash[..8])),
            status: "Searching for counterparty".to_string(),
            estimated_arrival: 3600,
            rail_used: self.name(),
        })
    }
}
