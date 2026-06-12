use crate::protocol::asset::{AssetIdentifier, Chain};
use serde::{Deserialize, Serialize};

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
