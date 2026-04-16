use crate::protocol::asset::{AssetIdentifier, Chain};
use crate::{ConclaveError, ConclaveResult};
use quick_xml::{Reader, events::Event};
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

use crate::protocol::asset::AssetRegistry;
use std::sync::Arc;

pub struct SettlementManager {
    pub asset_registry: Arc<AssetRegistry>,
}

impl SettlementManager {
    pub fn new(asset_registry: Arc<AssetRegistry>) -> Self {
        Self { asset_registry }
    }

    fn validate_iso20022_trigger_payload(payload: &[u8]) -> bool {
        fn local_name(name: &[u8]) -> &[u8] {
            match name.iter().rposition(|b| *b == b':') {
                Some(idx) => &name[idx + 1..],
                None => name,
            }
        }

        let mut reader = Reader::from_reader(payload);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();

        let mut document_namespace_ok = false;
        let mut saw_document_root = false;
        let mut saw_credit_transfer = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(Event::DocType(_)) => return false,
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                    let qname = e.name();
                    let name = local_name(qname.as_ref());

                    if !saw_document_root {
                        saw_document_root = name == b"Document";
                        if saw_document_root {
                            for attr in e.attributes() {
                                let Ok(attr) = attr else {
                                    return false;
                                };

                                let key = attr.key.as_ref();
                                if !key.starts_with(b"xmlns") {
                                    continue;
                                }

                                let Ok(value) = std::str::from_utf8(attr.value.as_ref()) else {
                                    return false;
                                };
                                if value.contains("urn:iso:std:iso:20022") {
                                    document_namespace_ok = true;
                                    break;
                                }
                            }
                        }
                    }

                    if name == b"FIToFICstmrCdtTrf" {
                        saw_credit_transfer = true;
                    }
                }
                Ok(_) => {}
                Err(_) => return false,
            }

            buf.clear();
        }

        saw_document_root && document_namespace_ok && saw_credit_transfer
    }

    /// Verifies an external settlement trigger inside the TEE boundary.
    /// Performs structured validation based on the source (e.g., ISO 20022).
    pub fn verify_trigger(&self, trigger: &SettlementTrigger) -> ConclaveResult<bool> {
        if trigger.raw_payload_bytes.is_empty() {
            return Ok(false);
        }

        // Safety bound for TEE memory constraints
        if trigger.raw_payload_bytes.len() > 1024 * 1024 {
            return Ok(false);
        }

        match trigger.source {
            TriggerSource::Iso20022 => {
                if !Self::validate_iso20022_trigger_payload(&trigger.raw_payload_bytes) {
                    return Ok(false);
                }
            }
            TriggerSource::Papss | TriggerSource::Brics => {
                // Heuristic validation for PAPSS/BRICS JSON-LD or proprietary formats
                if trigger.raw_payload_bytes.len() < 32 {
                    return Ok(false);
                }
            }
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
            _ => return Err(ConclaveError::InvalidPayload),
        };

        let id = AssetIdentifier {
            chain: chain_enum,
            symbol: asset_symbol.to_string(),
        };
        let asset = self
            .asset_registry
            .get_asset(&id)
            .ok_or(ConclaveError::InvalidPayload)?;

        if !asset.active {
            return Err(ConclaveError::InvalidPayload);
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

        let payload = b"<?xml version=\"1.0\"?><Document xmlns=\"urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08\"><FIToFICstmrCdtTrf></FIToFICstmrCdtTrf></Document>".to_vec();
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
