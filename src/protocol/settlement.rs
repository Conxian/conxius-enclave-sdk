use crate::protocol::asset::{AssetIdentifier, AssetRegistry, Chain};
use crate::{ConclaveError, ConclaveResult};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
}

impl SettlementTrigger {
    pub fn new(source: TriggerSource, payload: Vec<u8>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        let trigger_id = hex::encode(hasher.finalize());

        Self {
            trigger_id,
            source,
            raw_payload_bytes: payload,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalStatus {
    Pending,
    Enforced,
    Settled,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YieldSplit {
    pub productive_streaming_pct: u8,
    pub treasury_buffer_pct: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementProposal {
    pub proposal_id: String,
    pub trigger_id: String,
    pub asset: AssetIdentifier,
    pub amount: u64,
    pub recipient: String,
    pub timelock_height: u64,
    pub yield_split: YieldSplit,
    pub status: ProposalStatus,
}

impl SettlementProposal {
    pub fn new(
        trigger_id: String,
        asset: AssetIdentifier,
        amount: u64,
        recipient: String,
        current_height: u64,
    ) -> Self {
        let proposal_id = format!("prop_{}_{}", trigger_id, current_height);
        Self {
            proposal_id,
            trigger_id,
            asset,
            amount,
            recipient,
            timelock_height: current_height + 144,
            yield_split: YieldSplit {
                productive_streaming_pct: 90,
                treasury_buffer_pct: 10,
            },
            status: ProposalStatus::Pending,
        }
    }
}

pub struct SettlementManager {
    asset_registry: Arc<AssetRegistry>,
}

impl SettlementManager {
    pub fn new(asset_registry: Arc<AssetRegistry>) -> Self {
        Self { asset_registry }
    }

    fn validate_iso20022_trigger_payload(payload: &[u8]) -> bool {
        let mut reader = Reader::from_reader(payload);
        let mut buf = Vec::new();

        let mut depth = 0;
        let mut in_document = false;
        let mut document_depth = None;
        let mut document_closed = false;
        let mut saw_document_root = false;
        let mut document_namespace_ok = false;
        let mut saw_credit_transfer = false;
        let mut namespace_stack: Vec<Option<Vec<u8>>> = Vec::new();
        let mut saw_decl = false;
        let mut saw_any_pre_root_content = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(Event::Start(e)) => {
                    let qname = e.name();
                    let name = if let Some(pos) = qname.as_ref().iter().position(|&b| b == b':') {
                        &qname.as_ref()[pos + 1..]
                    } else {
                        qname.as_ref()
                    };

                    if document_closed {
                        return false;
                    }

                    let mut current_ns = namespace_stack.last().cloned().flatten();
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"xmlns" {
                            current_ns = Some(attr.value.to_vec());
                        }
                    }
                    namespace_stack.push(current_ns.clone());

                    let current_depth = depth;
                    depth += 1;

                    if !saw_document_root {
                        if name != b"Document" {
                            return false;
                        }
                        saw_document_root = true;
                        in_document = true;
                        document_depth = Some(current_depth);

                        if current_ns
                            .as_ref()
                            .is_some_and(|ns| ns.starts_with(b"urn:iso:std:iso:20022:tech:xsd:"))
                        {
                            document_namespace_ok = true;
                        }
                    } else if in_document {
                        let element_is_iso = match current_ns {
                            Some(ns) => ns.starts_with(b"urn:iso:std:iso:20022:tech:xsd:"),
                            None => false,
                        };

                        if name == b"FIToFICstmrCdtTrf" {
                            if !element_is_iso {
                                return false;
                            }
                            saw_credit_transfer = true;
                        }
                    }
                }
                Ok(Event::End(e)) => {
                    let qname = e.name();
                    let name = if let Some(pos) = qname.as_ref().iter().position(|&b| b == b':') {
                        &qname.as_ref()[pos + 1..]
                    } else {
                        qname.as_ref()
                    };

                    if depth == 0 {
                        return false;
                    }

                    let end_depth = depth - 1;

                    if namespace_stack.pop().is_none() {
                        return false;
                    }

                    if name == b"Document" && document_depth == Some(end_depth) {
                        in_document = false;
                        document_depth = None;
                        document_closed = true;
                    }

                    depth = end_depth;
                }
                Ok(event) => match event {
                    Event::Text(t) => {
                        let bytes = t.as_ref();
                        if !saw_document_root
                            && !bytes.is_empty()
                            && !bytes.iter().all(|b| b.is_ascii_whitespace())
                        {
                            saw_any_pre_root_content = true;
                        }
                        if !bytes.is_empty()
                            && !bytes.iter().all(|b| b.is_ascii_whitespace())
                            && (!saw_document_root || document_closed)
                        {
                            return false;
                        }
                    }
                    Event::Decl(_) => {
                        if saw_decl || saw_any_pre_root_content || saw_document_root {
                            return false;
                        }
                        saw_decl = true;
                    }
                    _ => {
                        if !saw_document_root || document_closed {
                            return false;
                        }
                    }
                },
                Err(_) => return false,
            }
            buf.clear();
        }

        depth == 0
            && namespace_stack.is_empty()
            && document_closed
            && !in_document
            && saw_document_root
            && document_namespace_ok
            && saw_credit_transfer
    }

    pub fn verify_trigger(&self, trigger: &SettlementTrigger) -> ConclaveResult<bool> {
        if trigger.raw_payload_bytes.is_empty() {
            return Ok(false);
        }

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
                if trigger.raw_payload_bytes.len() < 32 {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

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
            "ROOTSTOCK" => Chain::ROOTSTOCK,
            "BOB" => Chain::BOB,
            "POLYGON" => Chain::POLYGON,
            "BSC" => Chain::BSC,
            "MEZO" => Chain::MEZO,
            "BABYLON" => Chain::BABYLON,
            "BOTANIX" => Chain::BOTANIX,
            "CITREA" => Chain::CITREA,
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

#[cfg(test)]
mod settlement_expanded_tests {
    use super::*;
    use crate::protocol::asset::AssetRegistry;
    use std::sync::Arc;

    #[test]
    fn test_create_proposal_expanded_chains() {
        let registry = Arc::new(AssetRegistry::new());
        let manager = SettlementManager::new(registry);
        let payload = b"<?xml version=\"1.0\"?><Document xmlns=\"urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08\"><FIToFICstmrCdtTrf></FIToFICstmrCdtTrf></Document>".to_vec();
        let trigger = SettlementTrigger::new(TriggerSource::Iso20022, payload);

        let chains = vec!["MEZO", "BABYLON", "BOTANIX", "CITREA"];
        for chain in chains {
            let proposal = manager
                .create_proposal(&trigger, chain, "BTC", 1000, "recipient".to_string(), 100)
                .unwrap();
            assert_eq!(proposal.asset.chain.as_str(), chain);
        }
    }
}
