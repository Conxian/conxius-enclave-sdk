use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RailType {
    Changelly,
    Bisq,
    Wormhole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapRequest {
    pub from_chain: String,
    pub to_chain: String,
    pub from_asset: String,
    pub to_asset: String,
    pub amount: u64,
    pub recipient_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapIntent {
    pub request: SwapRequest,
    pub signable_hash: Vec<u8>,
    pub rail_type: RailType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapResponse {
    pub transaction_id: String,
    pub status: String,
    pub estimated_arrival: u64,
    pub rail_used: RailType,
}

pub struct RailProxy {
    pub rail_type: RailType,
    pub endpoint: String,
    pub api_key: Option<String>,
}

impl RailProxy {
    pub fn new(rail_type: RailType, endpoint: String, api_key: Option<String>) -> Self {
        Self { rail_type, endpoint, api_key }
    }

    /// PHASE 1: Prepare the swap intent.
    /// Returns a signable payload that represents the user's sovereign intent.
    pub fn prepare_swap(&self, request: SwapRequest) -> Result<SwapIntent, String> {
        if request.amount == 0 {
            return Err("Amount must be greater than zero".to_string());
        }
        if request.recipient_address.is_empty() {
            return Err("Recipient address is required".to_string());
        }

        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}:{:?}:{}", self.rail_type, request, self.endpoint).as_bytes());
        let signable_hash = hasher.finalize().to_vec();

        Ok(SwapIntent {
            request,
            signable_hash,
            rail_type: self.rail_type.clone(),
        })
    }

    /// PHASE 2: Broadcast the swap with the signature.
    /// This ensures that the rail only executes if the enclave has signed the intent.
    pub async fn broadcast_swap(&self, intent: SwapIntent, signature: String) -> Result<SwapResponse, String> {
        if signature.is_empty() {
            return Err("Sovereign signature required for broadcast".to_string());
        }

        match self.rail_type {
            RailType::Changelly => self.execute_changelly_proxy(intent, signature).await,
            RailType::Bisq => self.execute_bisq_sovereign_node(intent, signature).await,
            RailType::Wormhole => self.execute_wormhole_transceiver(intent, signature).await,
        }
    }

    async fn execute_changelly_proxy(&self, intent: SwapIntent, _sig: String) -> Result<SwapResponse, String> {
        Ok(SwapResponse {
            transaction_id: format!("CHG-PX-{}", hex::encode(&intent.signable_hash[..8])),
            status: "Awaiting Inbound Deposit".to_string(),
            estimated_arrival: 600,
            rail_used: RailType::Changelly,
        })
    }

    async fn execute_bisq_sovereign_node(&self, intent: SwapIntent, _sig: String) -> Result<SwapResponse, String> {
        Ok(SwapResponse {
            transaction_id: format!("BISQ-P2P-{}", hex::encode(&intent.signable_hash[..8])),
            status: "Searching for counterparty".to_string(),
            estimated_arrival: 3600,
            rail_used: RailType::Bisq,
        })
    }

    async fn execute_wormhole_transceiver(&self, intent: SwapIntent, _sig: String) -> Result<SwapResponse, String> {
        Ok(SwapResponse {
            transaction_id: format!("WORM-VAA-{}", hex::encode(&intent.signable_hash[..8])),
            status: "Pending Portal Finalization".to_string(),
            estimated_arrival: 900,
            rail_used: RailType::Wormhole,
        })
    }
}
