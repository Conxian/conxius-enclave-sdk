use crate::protocol::asset::{AssetIdentifier, Chain};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TriggerSource {
    Iso20022,
    Papss,
    Brics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementTrigger {
    pub trigger_id: String,
    pub source: TriggerSource,
    pub raw_payload_bytes: Vec<u8>,
    pub timestamp: u64,
}

impl SettlementTrigger {
    pub fn new(source: TriggerSource, payload: Vec<u8>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        hasher.update(format!("{:?}", source).as_bytes());
        let trigger_id = hex::encode(hasher.finalize());

        Self {
            trigger_id,
            source,
            raw_payload_bytes: payload,
            timestamp: unix_time_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProposalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Settled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YieldSplit {
    pub transit_bond_pct: u8,         // 5%
    pub escrow_pct: u8,               // 5%
    pub productive_streaming_pct: u8, // 90%
}

impl Default for YieldSplit {
    fn default() -> Self {
        Self {
            transit_bond_pct: 5,
            escrow_pct: 5,
            productive_streaming_pct: 90,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementProposal {
    pub proposal_id: String,
    pub trigger_id: String,
    pub asset: AssetIdentifier,
    pub amount: u64,
    pub recipient_address: String,
    pub start_height: u64,
    pub timelock_height: u64, // start_height + 144
    pub status: ProposalStatus,
    pub yield_split: YieldSplit,
    pub created_at: u64,
}

impl SettlementProposal {
    pub fn new(
        trigger_id: String,
        asset: AssetIdentifier,
        amount: u64,
        recipient: String,
        current_height: u64,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(trigger_id.as_bytes());
        hasher.update(format!("{:?}", asset).as_bytes());
        hasher.update(amount.to_be_bytes());
        hasher.update(recipient.as_bytes());
        let proposal_id = hex::encode(&hasher.finalize()[..16]);

        Self {
            proposal_id,
            trigger_id,
            asset,
            amount,
            recipient_address: recipient,
            start_height: current_height,
            timelock_height: current_height + 144,
            status: ProposalStatus::Pending,
            yield_split: YieldSplit::default(),
            created_at: unix_time_secs(),
        }
    }
}

use crate::ConclaveResult;
use crate::protocol::asset::AssetRegistry;
use std::sync::Arc;

pub struct SettlementManager {
    pub asset_registry: Arc<AssetRegistry>,
}

impl SettlementManager {
    pub fn new(asset_registry: Arc<AssetRegistry>) -> Self {
        Self { asset_registry }
    }

    /// Verifies an external settlement trigger inside the TEE boundary.
    /// In a real implementation, this would involve complex parsing of ISO 20022, PAPSS, or BRICS messages.
    pub fn verify_trigger(&self, trigger: &SettlementTrigger) -> ConclaveResult<bool> {
        // Validation logic for TradFi payloads
        if trigger.raw_payload_bytes.is_empty() {
            return Ok(false);
        }

        // Ensure the payload doesn't exceed safety bounds
        if trigger.raw_payload_bytes.len() > 1024 * 1024 {
            return Ok(false);
        }

        Ok(true)
    }

    /// Maps an external trigger to a digital asset proposal.
    /// This initiates the 144-block time-lock flow.
    pub fn create_proposal(
        &self,
        trigger: &SettlementTrigger,
        asset_chain: &str,
        asset_symbol: &str,
        amount: u64,
        recipient: String,
        current_height: u64,
    ) -> ConclaveResult<SettlementProposal> {
        let chain_enum = match asset_chain.to_uppercase().as_str() {
            "BITCOIN" => Chain::BITCOIN,
            "ETHEREUM" => Chain::ETHEREUM,
            "STACKS" => Chain::STACKS,
            "LIQUID" => Chain::LIQUID,
            "SOLANA" => Chain::SOLANA,
            "ARBITRUM" => Chain::ARBITRUM,
            "BASE" => Chain::BASE,
            "LIGHTNING" => Chain::LIGHTNING,
            _ => Chain::BITCOIN, // Default
        };

        let id = AssetIdentifier { chain: chain_enum, symbol: asset_symbol.to_string() };
        let asset = self
            .asset_registry
            .get_asset(&id)
            .ok_or(crate::ConclaveError::InvalidPayload)?;

        if !asset.active {
            return Err(crate::ConclaveError::InvalidPayload);
        }

        Ok(SettlementProposal::new(
            trigger.trigger_id.clone(),
            id,
            amount,
            recipient,
            current_height,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::asset::AssetRegistry;
    use std::sync::Arc;

    #[test]
    fn test_settlement_flow() {
        let registry = Arc::new(AssetRegistry::new());
        let manager = SettlementManager::new(registry);

        let payload = b"ISO20022_PAYMENT_DATA".to_vec();
        let trigger = SettlementTrigger::new(TriggerSource::Iso20022, payload);

        assert!(manager.verify_trigger(&trigger).unwrap());

        let proposal = manager
            .create_proposal(
                &trigger,
                "BITCOIN",
                "BTC",
                1000000,
                "bc1q...".to_string(),
                840000,
            )
            .unwrap();

        assert_eq!(proposal.trigger_id, trigger.trigger_id);
        assert_eq!(proposal.timelock_height, 840000 + 144);
        assert_eq!(proposal.yield_split.productive_streaming_pct, 90);
        assert_eq!(proposal.status, ProposalStatus::Pending);
    }
}
