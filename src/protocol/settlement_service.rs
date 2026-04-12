use crate::ConclaveResult;
use crate::protocol::asset::AssetRegistry;
use crate::protocol::settlement::{SettlementManager, SettlementProposal, SettlementTrigger};
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait SettlementService: Send + Sync {
    async fn process_external_trigger(
        &self,
        trigger: SettlementTrigger,
        asset_chain: &str,
        asset_symbol: &str,
        amount: u64,
        recipient: String,
        current_height: u64,
    ) -> ConclaveResult<SettlementProposal>;
}

pub struct ConclaveSettlementService {
    pub manager: SettlementManager,
}

impl ConclaveSettlementService {
    pub fn new(asset_registry: Arc<AssetRegistry>) -> Self {
        Self {
            manager: SettlementManager::new(asset_registry),
        }
    }
}

#[async_trait]
impl SettlementService for ConclaveSettlementService {
    async fn process_external_trigger(
        &self,
        trigger: SettlementTrigger,
        asset_chain: &str,
        asset_symbol: &str,
        amount: u64,
        recipient: String,
        current_height: u64,
    ) -> ConclaveResult<SettlementProposal> {
        // 1. Verify trigger inside TEE boundary
        if !self.manager.verify_trigger(&trigger)? {
            return Err(crate::ConclaveError::InvalidPayload);
        }

        // 2. Map trigger to proposal with 144-block timelock
        let proposal = self.manager.create_proposal(
            &trigger,
            asset_chain,
            asset_symbol,
            amount,
            recipient,
            current_height,
        )?;

        // 3. In a real system, we would broadcast the proposal to the consensus layer here.
        // For the SDK, we return the proposal for client-side use.
        Ok(proposal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::asset::{AssetRegistry, Chain};
    use crate::protocol::settlement::TriggerSource;

    #[tokio::test]
    async fn test_settlement_service_trigger_to_proposal() {
        let registry = Arc::new(AssetRegistry::new());
        let svc = ConclaveSettlementService::new(registry);

        let payload = b"BRICS_PAYMENT_v1".to_vec();
        let trigger = SettlementTrigger::new(TriggerSource::Brics, payload);

        let proposal = svc
            .process_external_trigger(
                trigger,
                "STACKS",
                "STX",
                500000000, // 500 STX
                "SP...".to_string(),
                120000,
            )
            .await
            .unwrap();

        assert_eq!(proposal.asset.chain, Chain::STACKS);
        assert_eq!(proposal.timelock_height, 120000 + 144);
        assert_eq!(proposal.amount, 500000000);
    }
}
