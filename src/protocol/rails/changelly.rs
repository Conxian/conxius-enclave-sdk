use crate::protocol::rails::{SovereignRail, SwapIntent, SwapRequest, SwapResponse};
use async_trait::async_trait;

pub struct ChangellyRail;

#[async_trait]
impl SovereignRail for ChangellyRail {
    fn name(&self) -> String {
        "Changelly".to_string()
    }
    fn validate_request(&self, _request: &SwapRequest) -> Result<Option<String>, String> {
        Ok(None)
    }
    async fn execute_swap(
        &self,
        intent: SwapIntent,
        _signature: String,
    ) -> Result<SwapResponse, String> {
        Ok(SwapResponse {
            transaction_id: format!("CHG-PX-{}", hex::encode(&intent.signable_hash[..8])),
            status: "Awaiting Inbound Deposit".to_string(),
            estimated_arrival: 600,
            rail_used: self.name(),
        })
    }
}
