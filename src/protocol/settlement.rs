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

        #[derive(Clone)]
        struct NamespaceScope {
            default_is_iso: bool,
            prefix_overrides: Vec<(Vec<u8>, bool)>,
        }

        fn lookup_prefix_is_iso(
            prefix: &[u8],
            current: &NamespaceScope,
            stack: &[NamespaceScope],
        ) -> bool {
            for (p, is_iso) in current.prefix_overrides.iter().rev() {
                if p.as_slice() == prefix {
                    return *is_iso;
                }
            }

            for scope in stack.iter().rev() {
                for (p, is_iso) in scope.prefix_overrides.iter().rev() {
                    if p.as_slice() == prefix {
                        return *is_iso;
                    }
                }
            }

            false
        }

        let mut reader = Reader::from_reader(payload);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();

        let mut depth: usize = 0;
        let mut in_document = false;
        let mut document_depth: Option<usize> = None;
        let mut document_closed = false;
        let mut namespace_stack: Vec<NamespaceScope> = Vec::new();

        let mut document_namespace_ok = false;
        let mut saw_document_root = false;
        let mut saw_credit_transfer = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(Event::DocType(_)) => return false,
                Ok(Event::Start(e)) => {
                    if document_closed {
                        return false;
                    }

                    let qname = e.name();
                    let name = local_name(qname.as_ref());

                    if saw_document_root && name == b"Document" {
                        return false;
                    }

                    let qname_bytes = qname.as_ref();

                    let element_scope = if !saw_document_root {
                        if depth != 0 || name != b"Document" {
                            return false;
                        }

                        saw_document_root = true;
                        in_document = true;
                        document_depth = Some(depth);

                        let document_prefix_bytes = qname_bytes
                            .iter()
                            .position(|b| *b == b':')
                            .map(|idx| &qname_bytes[..idx]);

                        let mut scope = NamespaceScope {
                            default_is_iso: false,
                            prefix_overrides: Vec::new(),
                        };

                        for attr in e.attributes() {
                            let Ok(attr) = attr else {
                                return false;
                            };

                            let key = attr.key.as_ref();
                            if key != b"xmlns" && !key.starts_with(b"xmlns:") {
                                continue;
                            }

                            let Ok(value) = std::str::from_utf8(attr.value.as_ref()) else {
                                return false;
                            };
                            let is_iso = value.starts_with("urn:iso:std:iso:20022");

                            if key == b"xmlns" {
                                scope.default_is_iso = is_iso;
                            } else if let Some(suffix) = key.strip_prefix(b"xmlns:") {
                                scope.prefix_overrides.push((suffix.to_vec(), is_iso));
                            }
                        }

                        document_namespace_ok = match document_prefix_bytes {
                            None => scope.default_is_iso,
                            Some(prefix) => scope
                                .prefix_overrides
                                .iter()
                                .rev()
                                .find(|(p, _)| p.as_slice() == prefix)
                                .map(|(_, is_iso)| *is_iso)
                                .unwrap_or(false),
                        };

                        if !document_namespace_ok {
                            return false;
                        }
                        scope
                    } else {
                        if !in_document {
                            return false;
                        }

                        let parent_default_is_iso = match namespace_stack.last() {
                            Some(scope) => scope.default_is_iso,
                            None => return false,
                        };

                        let mut scope = NamespaceScope {
                            default_is_iso: parent_default_is_iso,
                            prefix_overrides: Vec::new(),
                        };
                        for attr in e.attributes() {
                            let Ok(attr) = attr else {
                                return false;
                            };

                            let key = attr.key.as_ref();
                            if key == b"xmlns" {
                                let Ok(value) = std::str::from_utf8(attr.value.as_ref()) else {
                                    return false;
                                };
                                scope.default_is_iso = value.starts_with("urn:iso:std:iso:20022");
                                continue;
                            }

                            if let Some(suffix) = key.strip_prefix(b"xmlns:") {
                                let Ok(value) = std::str::from_utf8(attr.value.as_ref()) else {
                                    return false;
                                };
                                scope.prefix_overrides.push((
                                    suffix.to_vec(),
                                    value.starts_with("urn:iso:std:iso:20022"),
                                ));
                            }
                        }
                        scope
                    };

                    if in_document && name == b"FIToFICstmrCdtTrf" {
                        let element_prefix = qname_bytes
                            .iter()
                            .position(|b| *b == b':')
                            .map(|idx| &qname_bytes[..idx]);

                        let element_is_iso = match element_prefix {
                            None => element_scope.default_is_iso,
                            Some(prefix) => {
                                lookup_prefix_is_iso(prefix, &element_scope, &namespace_stack)
                            }
                        };

                        if element_is_iso {
                            saw_credit_transfer = true;
                        }
                    }

                    namespace_stack.push(element_scope);
                    depth += 1;
                }
                Ok(Event::Empty(e)) => {
                    if document_closed {
                        return false;
                    }

                    let qname = e.name();
                    let name = local_name(qname.as_ref());

                    if !saw_document_root {
                        return false;
                    }

                    if !in_document {
                        return false;
                    }

                    if name == b"Document" {
                        return false;
                    }

                    let parent_default_is_iso = match namespace_stack.last() {
                        Some(scope) => scope.default_is_iso,
                        None => return false,
                    };

                    let mut scope = NamespaceScope {
                        default_is_iso: parent_default_is_iso,
                        prefix_overrides: Vec::new(),
                    };

                    let qname_bytes = qname.as_ref();
                    for attr in e.attributes() {
                        let Ok(attr) = attr else {
                            return false;
                        };

                        let key = attr.key.as_ref();
                        if key == b"xmlns" {
                            let Ok(value) = std::str::from_utf8(attr.value.as_ref()) else {
                                return false;
                            };
                            scope.default_is_iso = value.starts_with("urn:iso:std:iso:20022");
                            continue;
                        }

                        if let Some(suffix) = key.strip_prefix(b"xmlns:") {
                            let Ok(value) = std::str::from_utf8(attr.value.as_ref()) else {
                                return false;
                            };
                            scope.prefix_overrides.push((
                                suffix.to_vec(),
                                value.starts_with("urn:iso:std:iso:20022"),
                            ));
                        }
                    }

                    if name == b"FIToFICstmrCdtTrf" {
                        let element_prefix = qname_bytes
                            .iter()
                            .position(|b| *b == b':')
                            .map(|idx| &qname_bytes[..idx]);

                        let element_is_iso = match element_prefix {
                            None => scope.default_is_iso,
                            Some(prefix) => lookup_prefix_is_iso(prefix, &scope, &namespace_stack),
                        };

                        if element_is_iso {
                            saw_credit_transfer = true;
                        }
                    }
                }
                Ok(Event::End(e)) => {
                    let qname = e.name();
                    let name = local_name(qname.as_ref());

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
                        if !bytes.is_empty()
                            && !bytes.iter().all(|b| b.is_ascii_whitespace())
                            && (!saw_document_root || document_closed)
                        {
                            return false;
                        }
                    }
                    _ => {
                        if document_closed {
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
