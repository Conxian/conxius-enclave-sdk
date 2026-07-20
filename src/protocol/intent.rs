use crate::protocol::asset::{AssetIdentifier, Chain};
use crate::protocol::business::BusinessAttribution;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separator for the versioned, complete swap-intent commitment.
pub const SWAP_INTENT_HASH_DOMAIN: &[u8] = b"CONXIUS-SWAP-INTENT";

/// Version of the canonical swap-intent encoding.
pub const SWAP_INTENT_HASH_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GaslessCrossChainOrder {
    pub origin_settler: String,
    pub user: String,
    pub nonce: u64,
    pub origin_chain_id: u32,
    pub open_deadline: u32,
    pub fill_deadline: u32,
    pub order_data_type: [u8; 32],
    pub order_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedCrossChainOrder {
    pub user: String,
    pub origin_chain_id: u32,
    pub open_deadline: u32,
    pub fill_deadline: u32,
    pub swapper: String,
    pub nonce: u64,
    pub input_assets: Vec<AssetAmount>,
    pub output_assets: Vec<AssetAmount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetAmount {
    pub asset: AssetIdentifier,
    pub amount: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainIntent {
    pub input_asset: AssetIdentifier,
    pub output_asset: AssetIdentifier,
    pub input_amount: u128,
    pub output_amount: u128,
    pub destination_chain: Chain,
    pub recipient: String,
}

impl CrossChainIntent {
    pub fn to_order_data(&self) -> Vec<u8> {
        // Serialization logic for ERC-7683 orderData
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// A request to perform a cross-chain swap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapRequest {
    pub from_asset: AssetIdentifier,
    pub to_asset: AssetIdentifier,
    pub amount: u64,
    pub recipient_address: String,
    pub attribution: Option<BusinessAttribution>,
}

impl SwapRequest {
    /// Returns the pre-versioned request-only JSON hash.
    ///
    /// Deprecated: request-only hashes omit the selected rail and dispatch
    /// context. They are retained only so callers can identify and migrate
    /// legacy data; all secure intent verification rejects them.
    pub fn get_hash_bytes(&self) -> Vec<u8> {
        let json = serde_json::to_string(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        hasher.finalize().to_vec()
    }

    fn append_canonical_bytes(&self, output: &mut Vec<u8>) {
        append_field(
            output,
            b"from_chain",
            self.from_asset.chain.as_str().as_bytes(),
        );
        append_field(output, b"from_symbol", self.from_asset.symbol.as_bytes());
        append_field(output, b"to_chain", self.to_asset.chain.as_str().as_bytes());
        append_field(output, b"to_symbol", self.to_asset.symbol.as_bytes());
        append_field(output, b"amount", &self.amount.to_be_bytes());
        append_field(
            output,
            b"recipient_address",
            self.recipient_address.as_bytes(),
        );

        match &self.attribution {
            None => append_field(output, b"attribution", &[0]),
            Some(attribution) => {
                append_field(output, b"attribution", &[1]);
                append_field(
                    output,
                    b"attribution_business_id",
                    attribution.business_id.as_bytes(),
                );
                append_field(
                    output,
                    b"attribution_user_id",
                    attribution.user_id.as_bytes(),
                );
                append_field(
                    output,
                    b"attribution_timestamp",
                    &attribution.timestamp.to_be_bytes(),
                );
                append_field(
                    output,
                    b"attribution_expiration",
                    &attribution.expiration.to_be_bytes(),
                );
                append_field(output, b"attribution_nonce", &attribution.nonce);
                append_field(
                    output,
                    b"attribution_signature",
                    attribution.signature.as_bytes(),
                );

                let mut metadata: Vec<_> = attribution.metadata.iter().collect();
                metadata.sort_by(|(left_key, left_value), (right_key, right_value)| {
                    left_key
                        .cmp(right_key)
                        .then_with(|| left_value.cmp(right_value))
                });
                append_field_count(output, b"attribution_metadata", metadata.len());
                for (key, value) in metadata {
                    let mut entry = Vec::new();
                    append_field(&mut entry, b"key", key.as_bytes());
                    append_field(&mut entry, b"value", value.as_bytes());
                    append_field(output, b"attribution_metadata_entry", &entry);
                }
            }
        }
    }
}

/// The result of a signable intent preparation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapIntent {
    pub request: SwapRequest,
    pub signable_hash: Vec<u8>,
    pub rail_type: String,
    pub chain_context: Option<String>,
    pub fdc3_context: Option<Fdc3Context>,
}

impl SwapIntent {
    /// Returns the deterministic, domain-separated bytes signed for this
    /// intent. The encoding includes every request field, the selected rail,
    /// and both optional dispatch contexts. Map entries are sorted before
    /// length framing; JSON or `HashMap` iteration order is never trusted.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        append_len_prefixed(&mut output, SWAP_INTENT_HASH_DOMAIN);
        output.push(SWAP_INTENT_HASH_VERSION);

        let mut request = Vec::new();
        self.request.append_canonical_bytes(&mut request);
        append_field(&mut output, b"request", &request);
        append_field(&mut output, b"rail_type", self.rail_type.as_bytes());
        append_optional_string(&mut output, b"chain_context", self.chain_context.as_deref());

        match &self.fdc3_context {
            None => append_field(&mut output, b"fdc3_context", &[0]),
            Some(context) => {
                append_field(&mut output, b"fdc3_context", &[1]);
                append_field(
                    &mut output,
                    b"fdc3_context_type",
                    context.context_type.as_bytes(),
                );
                append_optional_string(&mut output, b"fdc3_name", context.name.as_deref());

                let mut identifiers: Vec<_> = context.id.iter().collect();
                identifiers.sort_by(|(left_key, left_value), (right_key, right_value)| {
                    left_key
                        .cmp(right_key)
                        .then_with(|| left_value.cmp(right_value))
                });
                append_field_count(&mut output, b"fdc3_id", identifiers.len());
                for (key, value) in identifiers {
                    let mut entry = Vec::new();
                    append_field(&mut entry, b"key", key.as_bytes());
                    append_field(&mut entry, b"value", value.as_bytes());
                    append_field(&mut output, b"fdc3_id_entry", &entry);
                }
            }
        }

        output
    }

    /// Returns the SHA-256 commitment over the complete security context.
    pub fn canonical_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes());
        hasher.finalize().to_vec()
    }
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn append_field(output: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    append_len_prefixed(output, name);
    append_len_prefixed(output, value);
}

fn append_field_count(output: &mut Vec<u8>, name: &[u8], count: usize) {
    append_field(output, name, &(count as u64).to_be_bytes());
}

fn append_optional_string(output: &mut Vec<u8>, name: &[u8], value: Option<&str>) {
    match value {
        None => append_field(output, name, &[0]),
        Some(value) => {
            let mut encoded = Vec::new();
            encoded.push(1);
            append_len_prefixed(&mut encoded, value.as_bytes());
            append_field(output, name, &encoded);
        }
    }
}

/// The response from a swap execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapResponse {
    pub proof_envelope: Option<String>,
    pub transaction_id: String,
    pub status: String,
    pub estimated_arrival: u32,
    pub rail_used: String,
}

/// FDC3-compatible context exchange model (v1.9.2)
/// Enables corporate treasury handshake and interoperability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fdc3Context {
    #[serde(rename = "type")]
    pub context_type: String,
    pub name: Option<String>,
    pub id: std::collections::HashMap<String, String>,
}

impl Fdc3Context {
    pub fn instrument(symbol: &str, chain: &str) -> Self {
        let mut id = std::collections::HashMap::new();
        id.insert("ticker".to_string(), symbol.to_string());
        id.insert("chain".to_string(), chain.to_string());

        Self {
            context_type: "fdc3.instrument".to_string(),
            name: Some(format!("{} on {}", symbol, chain)),
            id,
        }
    }

    pub fn settlement(amount: u128, asset: &str, recipient: &str) -> Self {
        let mut id = std::collections::HashMap::new();
        id.insert("amount".to_string(), amount.to_string());
        id.insert("asset".to_string(), asset.to_string());
        id.insert("recipient".to_string(), recipient.to_string());

        Self {
            context_type: "conxian.settlement".to_string(),
            name: Some("Settlement Intent".to_string()),
            id,
        }
    }
}

/// FDC3 Intent Resolution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fdc3IntentResult {
    pub intent: String,
    pub context: Fdc3Context,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn base_request(metadata: HashMap<String, String>) -> SwapRequest {
        SwapRequest {
            from_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            to_asset: AssetIdentifier {
                chain: Chain::ETHEREUM,
                symbol: "ETH".to_string(),
            },
            amount: 100,
            recipient_address: "recipient".to_string(),
            attribution: Some(BusinessAttribution {
                business_id: "business".to_string(),
                user_id: "user".to_string(),
                timestamp: 10,
                expiration: 20,
                nonce: [7u8; 16],
                signature: "attribution-signature".to_string(),
                metadata,
            }),
        }
    }

    fn base_intent() -> SwapIntent {
        let mut metadata = HashMap::new();
        metadata.insert("zeta".to_string(), "last".to_string());
        metadata.insert("alpha".to_string(), "first".to_string());

        let mut id = HashMap::new();
        id.insert("chain".to_string(), "BITCOIN".to_string());
        id.insert("ticker".to_string(), "BTC".to_string());

        SwapIntent {
            request: base_request(metadata),
            signable_hash: Vec::new(),
            rail_type: "x402".to_string(),
            chain_context: Some("bitcoin-mainnet".to_string()),
            fdc3_context: Some(Fdc3Context {
                context_type: "fdc3.instrument".to_string(),
                name: Some("BTC on Bitcoin".to_string()),
                id,
            }),
        }
    }

    #[test]
    fn test_fdc3_context_creation() {
        let instrument = Fdc3Context::instrument("BTC", "BITCOIN");
        assert_eq!(instrument.context_type, "fdc3.instrument");
        assert_eq!(instrument.id.get("ticker").unwrap(), "BTC");

        let settlement = Fdc3Context::settlement(1000, "USDT", "0x123");
        assert_eq!(settlement.context_type, "conxian.settlement");
        assert_eq!(settlement.id.get("amount").unwrap(), "1000");
    }

    #[test]
    fn canonical_hash_is_independent_of_map_insertion_order() {
        let mut first_metadata = HashMap::new();
        first_metadata.insert("alpha".to_string(), "first".to_string());
        first_metadata.insert("zeta".to_string(), "last".to_string());

        let mut second_metadata = HashMap::new();
        second_metadata.insert("zeta".to_string(), "last".to_string());
        second_metadata.insert("alpha".to_string(), "first".to_string());

        let mut first = base_intent();
        first.request = base_request(first_metadata);

        let mut second = base_intent();
        second.request = base_request(second_metadata);
        if let Some(context) = second.fdc3_context.as_mut() {
            let mut reversed_id = HashMap::new();
            reversed_id.insert("ticker".to_string(), "BTC".to_string());
            reversed_id.insert("chain".to_string(), "BITCOIN".to_string());
            context.id = reversed_id;
        }

        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
        assert_eq!(first.canonical_hash(), second.canonical_hash());
    }

    #[test]
    fn canonical_hash_changes_for_rail_and_dispatch_context_mutations() {
        let base = base_intent();
        let base_hash = base.canonical_hash();

        let mut rail_changed = base.clone();
        rail_changed.rail_type = "wormhole".to_string();
        assert_ne!(base_hash, rail_changed.canonical_hash());

        let mut chain_context_changed = base.clone();
        chain_context_changed.chain_context = Some("bitcoin-testnet".to_string());
        assert_ne!(base_hash, chain_context_changed.canonical_hash());

        let mut fdc3_changed = base;
        fdc3_changed.fdc3_context = Some(Fdc3Context::instrument("ETH", "ETHEREUM"));
        assert_ne!(base_hash, fdc3_changed.canonical_hash());
    }

    #[test]
    fn legacy_request_only_hash_is_not_the_complete_intent_hash() {
        let intent = base_intent();

        assert_ne!(
            intent.request.get_hash_bytes(),
            intent.canonical_hash(),
            "request-only hashes must not authenticate a complete SwapIntent"
        );
    }
}
