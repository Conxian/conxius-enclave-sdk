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

    async fn verify_reconciliation(
        &self,
        proposal: &SettlementProposal,
        trigger: &SettlementTrigger,
    ) -> ConclaveResult<bool>;
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

    /// Verifies reconciliation between the on-chain proposal and the external trigger.
    /// This is a critical requirement for Wave 2 (Enterprise Lane) pilots.
    async fn verify_reconciliation(
        &self,
        proposal: &SettlementProposal,
        trigger: &SettlementTrigger,
    ) -> ConclaveResult<bool> {
        // In a production environment, this would query the MMR state to verify
        // the inclusion of the trigger hash and cross-reference it with the proposal ID.

        if proposal.trigger_id != trigger.trigger_id {
            return Ok(false);
        }

        // Structural check for ISO 20022 pacs.008 payloads
        if trigger.source == crate::protocol::settlement::TriggerSource::Iso20022 {
            let payload = String::from_utf8_lossy(&trigger.raw_payload_bytes);
            if !payload.contains("pacs.008.001.08") {
                return Ok(false);
            }
        }

        Ok(true)
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

    #[tokio::test]
    async fn test_verify_reconciliation() {
        let registry = Arc::new(AssetRegistry::new());
        let svc = ConclaveSettlementService::new(registry);

        let payload = b"<?xml version=\"1.0\"?><Document xmlns=\"urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08\"><FIToFICstmrCdtTrf></FIToFICstmrCdtTrf></Document>".to_vec();
        let trigger = SettlementTrigger::new(TriggerSource::Iso20022, payload);

        let proposal = svc
            .process_external_trigger(
                trigger.clone(),
                "BITCOIN",
                "BTC",
                1000000,
                "bc1q...".to_string(),
                840000,
            )
            .await
            .unwrap();

        let reconciled = svc.verify_reconciliation(&proposal, &trigger).await.unwrap();
        assert!(reconciled);

        // Tamper with trigger
        let bad_trigger = SettlementTrigger::new(TriggerSource::Iso20022, b"tampered".to_vec());
        let reconciled = svc.verify_reconciliation(&proposal, &bad_trigger).await.unwrap();
        assert!(!reconciled);
    }
}
