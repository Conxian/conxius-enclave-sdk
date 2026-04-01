use crate::protocol::rails::{SovereignRail, SwapIntent, SwapRequest, SwapResponse};
use async_trait::async_trait;

pub struct WormholeRail;

#[async_trait]
impl SovereignRail for WormholeRail {
    fn name(&self) -> String {
        "Wormhole".to_string()
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
        _signature: String,
    ) -> Result<SwapResponse, String> {
        Ok(SwapResponse {
            transaction_id: format!("WORM-VAA-{}", hex::encode(&intent.signable_hash[..8])),
            status: "Pending Portal Finalization".to_string(),
            estimated_arrival: 900,
            rail_used: self.name(),
        })
    }
}
