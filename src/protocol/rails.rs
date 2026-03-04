use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use async_trait::async_trait;

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
    pub chain_context: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapResponse {
    pub transaction_id: String,
    pub status: String,
    pub estimated_arrival: u64,
    pub rail_used: RailType,
}

/// The Sovereign Handshake: A non-custodial protocol where the Gateway
/// pushes requests to the mobile Enclave for signing before execution.
#[async_trait]
pub trait SovereignHandshake {
    /// Prepare a signable intent from a request.
    fn prepare_intent(&self, request: SwapRequest) -> Result<SwapIntent, String>;

    /// Broadcast a signed intent to the rail.
    async fn broadcast_signed_intent(&self, intent: SwapIntent, signature: String) -> Result<SwapResponse, String>;
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

    fn validate_chain_logic(&self, request: &SwapRequest) -> Result<Option<String>, String> {
        if request.from_chain == "BTC" {
            // Native Bitcoin logic: Verify valid address format (simplified)
            if !request.recipient_address.starts_with("bc1") && !request.recipient_address.starts_with("3") && !request.recipient_address.starts_with("1") {
                return Err("Invalid Bitcoin recipient address".to_string());
            }
            return Ok(Some("BTC_SPV_VALIDATED".to_string()));
        }
        Ok(None)
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

#[async_trait]
impl SovereignHandshake for RailProxy {
    fn prepare_intent(&self, request: SwapRequest) -> Result<SwapIntent, String> {
        if request.amount == 0 {
            return Err("Amount must be greater than zero".to_string());
        }
        if request.recipient_address.is_empty() {
            return Err("Recipient address is required".to_string());
        }

        let chain_context = self.validate_chain_logic(&request)?;

        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}:{:?}:{:?}:{}", self.rail_type, request, chain_context, self.endpoint).as_bytes());
        let signable_hash = hasher.finalize().to_vec();

        Ok(SwapIntent {
            request,
            signable_hash,
            rail_type: self.rail_type.clone(),
            chain_context,
        })
    }

    async fn broadcast_signed_intent(&self, intent: SwapIntent, signature: String) -> Result<SwapResponse, String> {
        if signature.is_empty() {
            return Err("Sovereign signature required for broadcast".to_string());
        }

        match self.rail_type {
            RailType::Changelly => self.execute_changelly_proxy(intent, signature).await,
            RailType::Bisq => self.execute_bisq_sovereign_node(intent, signature).await,
            RailType::Wormhole => self.execute_wormhole_transceiver(intent, signature).await,
        }
    }
}
