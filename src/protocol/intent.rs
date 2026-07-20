use crate::protocol::asset::{AssetIdentifier, Chain};
use crate::protocol::business::BusinessAttribution;
use serde::{Deserialize, Serialize};
use sha2::Digest;

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
    pub fn get_hash_bytes(&self) -> Vec<u8> {
        let json = serde_json::to_string(self).unwrap_or_default();
        let mut hasher = sha2::Sha256::new();
        hasher.update(json.as_bytes());
        hasher.finalize().to_vec()
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

    #[test]
    fn test_fdc3_context_creation() {
        let instrument = Fdc3Context::instrument("BTC", "BITCOIN");
        assert_eq!(instrument.context_type, "fdc3.instrument");
        assert_eq!(instrument.id.get("ticker").unwrap(), "BTC");

        let settlement =
            Fdc3Context::settlement(1000, "USDT", "0x52908400098527886E0F7030069857D2E4169EE7");
        assert_eq!(settlement.context_type, "conxian.settlement");
        assert_eq!(settlement.id.get("amount").unwrap(), "1000");
    }
}
