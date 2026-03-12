use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use async_trait::async_trait;
use crate::enclave::attestation::DeviceIntegrityReport;
use crate::protocol::asset::{AssetIdentifier, AssetRegistry};
use crate::protocol::business::{BusinessAttribution, BusinessRegistry};
use std::sync::Arc;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapRequest {
    pub from_asset: AssetIdentifier,
    pub to_asset: AssetIdentifier,
    pub amount: u64,
    pub recipient_address: String,
    pub attribution: Option<BusinessAttribution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapIntent {
    pub request: SwapRequest,
    pub signable_hash: Vec<u8>,
    pub rail_type: String,
    pub chain_context: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapResponse {
    pub transaction_id: String,
    pub status: String,
    pub estimated_arrival: u64,
    pub rail_used: String,
}

#[async_trait]
pub trait SovereignRail: Send + Sync {
    fn name(&self) -> String;
    fn validate_request(&self, request: &SwapRequest) -> Result<Option<String>, String>;
    async fn execute_swap(&self, intent: SwapIntent, signature: String) -> Result<SwapResponse, String>;
}

/// The Sovereign Handshake: A non-custodial protocol where the Gateway
/// pushes requests to the mobile Enclave for signing before execution.
#[async_trait]
pub trait SovereignHandshake {
    /// Prepare a signable intent from a request.
    fn prepare_intent(&self, rail_name: &str, request: SwapRequest) -> Result<SwapIntent, String>;

    /// Broadcast a signed intent to the rail, optionally verifying hardware attestation.
    async fn broadcast_signed_intent(
        &self,
        intent: SwapIntent,
        signature: String,
        attestation: Option<String>
    ) -> Result<SwapResponse, String>;
}

pub struct RailProxy {
    pub rails: HashMap<String, Box<dyn SovereignRail>>,
    pub endpoint: String,
    pub api_key: Option<String>,
    pub enforce_attestation: bool,
    pub asset_registry: Arc<AssetRegistry>,
    pub business_registry: Arc<BusinessRegistry>,
}

impl RailProxy {
    pub fn new(
        endpoint: String,
        api_key: Option<String>,
        asset_registry: Arc<AssetRegistry>,
        business_registry: Arc<BusinessRegistry>
    ) -> Self {
        Self {
            rails: HashMap::new(),
            endpoint,
            api_key,
            enforce_attestation: true,
            asset_registry,
            business_registry,
        }
    }

    pub fn register_rail(&mut self, rail: Box<dyn SovereignRail>) {
        self.rails.insert(rail.name(), rail);
    }

    fn verify_hardware_integrity(&self, intent: &SwapIntent, attestation_json: &Option<String>) -> Result<(), String> {
        if !self.enforce_attestation {
            return Ok(());
        }

        let json = attestation_json.as_ref().ok_or("Hardware attestation report missing for high-value rail operation")?;
        let report: DeviceIntegrityReport = serde_json::from_str(json)
            .map_err(|e| format!("Invalid attestation format: {}", e))?;

        if !report.verify(&intent.signable_hash) {
            return Err("Hardware attestation verification failed: Device integrity compromised or nonce mismatch".to_string());
        }

        // Verify business attribution if present
        if let Some(attribution) = &intent.request.attribution {
             let profile = self.business_registry.get_business(&attribution.business_id)
                 .ok_or_else(|| format!("Unknown business partner: {}", attribution.business_id))?;

             if !profile.active {
                 return Err(format!("Business partner {} is currently inactive", attribution.business_id));
             }

             if attribution.expiration < 1710000000 {
                 return Err("Business attribution expired".to_string());
             }

             // In a real implementation, we would also verify the cryptographic signature
             // of the attribution using the profile's public key.
             if attribution.signature.is_empty() {
                 return Err("Cryptographic business attribution signature missing".to_string());
             }
        }

        Ok(())
    }
}

#[async_trait]
impl SovereignHandshake for RailProxy {
    fn prepare_intent(&self, rail_name: &str, request: SwapRequest) -> Result<SwapIntent, String> {
        let rail = self.rails.get(rail_name).ok_or_else(|| format!("Rail {} not found", rail_name))?;

        if request.amount == 0 {
            return Err("Amount must be greater than zero".to_string());
        }

        if !self.asset_registry.validate_pair(&request.from_asset, &request.to_asset) {
            return Err("Invalid or unsupported asset pair".to_string());
        }

        let chain_context = rail.validate_request(&request)?;

        let mut hasher = Sha256::new();
        hasher.update(format!("{}:{:?}:{:?}:{}", rail_name, request, chain_context, self.endpoint).as_bytes());
        let signable_hash = hasher.finalize().to_vec();

        Ok(SwapIntent {
            request,
            signable_hash,
            rail_type: rail_name.to_string(),
            chain_context,
        })
    }

    async fn broadcast_signed_intent(
        &self,
        intent: SwapIntent,
        signature: String,
        attestation: Option<String>
    ) -> Result<SwapResponse, String> {
        let rail = self.rails.get(&intent.rail_type).ok_or_else(|| format!("Rail {} not found", intent.rail_type))?;

        if signature.is_empty() {
            return Err("Sovereign signature required for broadcast".to_string());
        }

        self.verify_hardware_integrity(&intent, &attestation)?;

        rail.execute_swap(intent, signature).await
    }
}

// Default Implementations for existing rails
pub struct ChangellyRail;
#[async_trait]
impl SovereignRail for ChangellyRail {
    fn name(&self) -> String { "Changelly".to_string() }
    fn validate_request(&self, _request: &SwapRequest) -> Result<Option<String>, String> { Ok(None) }
    async fn execute_swap(&self, intent: SwapIntent, _signature: String) -> Result<SwapResponse, String> {
        Ok(SwapResponse {
            transaction_id: format!("CHG-PX-{}", hex::encode(&intent.signable_hash[..8])),
            status: "Awaiting Inbound Deposit".to_string(),
            estimated_arrival: 600,
            rail_used: self.name(),
        })
    }
}

pub struct BisqRail;
#[async_trait]
impl SovereignRail for BisqRail {
    fn name(&self) -> String { "Bisq".to_string() }
    fn validate_request(&self, request: &SwapRequest) -> Result<Option<String>, String> {
        if request.from_asset.chain == "BTC" && request.amount < 100_000 {
            return Err("Bisq P2P requires a minimum amount of 100,000 sats".to_string());
        }
        Ok(Some("BTC_SPV_VALIDATED".to_string()))
    }
    async fn execute_swap(&self, intent: SwapIntent, _signature: String) -> Result<SwapResponse, String> {
        Ok(SwapResponse {
            transaction_id: format!("BISQ-P2P-{}", hex::encode(&intent.signable_hash[..8])),
            status: "Searching for counterparty".to_string(),
            estimated_arrival: 3600,
            rail_used: self.name(),
        })
    }
}

pub struct WormholeRail;
#[async_trait]
impl SovereignRail for WormholeRail {
    fn name(&self) -> String { "Wormhole".to_string() }
    fn validate_request(&self, request: &SwapRequest) -> Result<Option<String>, String> {
        if request.recipient_address.len() < 40 {
            return Err("Invalid EVM/Solana address for Wormhole transceiver".to_string());
        }
        Ok(Some(format!("WORMHOLE_VAA_TARGET_{}", request.to_asset.chain)))
    }
    async fn execute_swap(&self, intent: SwapIntent, _signature: String) -> Result<SwapResponse, String> {
        Ok(SwapResponse {
            transaction_id: format!("WORM-VAA-{}", hex::encode(&intent.signable_hash[..8])),
            status: "Pending Portal Finalization".to_string(),
            estimated_arrival: 900,
            rail_used: self.name(),
        })
    }
}

/// A custom rail extension example for partner-specific liquidity.
pub struct CustomRail;
#[async_trait]
impl SovereignRail for CustomRail {
    fn name(&self) -> String { "CustomPartner".to_string() }
    fn validate_request(&self, request: &SwapRequest) -> Result<Option<String>, String> {
        if request.from_asset.chain != "BTC" {
             return Err("CustomPartner only accepts BTC as inbound".to_string());
        }
        Ok(Some("PARTNER_CUSTOM_v1".to_string()))
    }
    async fn execute_swap(&self, intent: SwapIntent, _signature: String) -> Result<SwapResponse, String> {
        Ok(SwapResponse {
            transaction_id: format!("PARTNER-{}", hex::encode(&intent.signable_hash[..8])),
            status: "Partner processing".to_string(),
            estimated_arrival: 1200,
            rail_used: self.name(),
        })
    }
}
