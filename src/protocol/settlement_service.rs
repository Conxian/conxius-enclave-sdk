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
    /// Orchestrates the end-to-end flow of converting an external settlement trigger
    /// (ISO 20022, PAPSS, etc.) into a digital asset proposal with a mandatory 144-block timelock.
    async fn process_external_trigger(
        &self,
        trigger: SettlementTrigger,
        asset_chain: &str,
        asset_symbol: &str,
        amount: u64,
        recipient: String,
        current_height: u64,
    ) -> ConclaveResult<SettlementProposal> {
        // 1. Verify trigger validity and structural integrity inside TEE boundary
        if !self.manager.verify_trigger(&trigger)? {
            return Err(crate::ConclaveError::InvalidPayload);
        }

        // 2. Map trigger to proposal with 144-block timelock enforcement
        let proposal = self.manager.create_proposal(
            &trigger,
            asset_chain,
            asset_symbol,
            amount,
            recipient,
            current_height,
        )?;

        // 3. Automated Policy Enforcement: Ensure timelock is exactly 144 blocks
        if proposal.timelock_height != current_height + 144 {
            return Err(crate::ConclaveError::CryptoError(
                "Mandatory 144-block timelock violation".to_string(),
            ));
        }

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

        let payload = b"<?xml version=\"1.0\"?><Document xmlns=\"urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08\"><FIToFICstmrCdtTrf></FIToFICstmrCdtTrf></Document>".to_vec();
        let trigger = SettlementTrigger::new(TriggerSource::Iso20022, payload);

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
