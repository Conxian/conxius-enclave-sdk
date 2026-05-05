pub mod bisq;
pub mod boltz;
pub mod changelly;
pub mod ntt;
pub mod wormhole;

use crate::enclave::attestation::DeviceIntegrityReport;
use crate::protocol::asset::{AssetIdentifier, AssetRegistry, Chain};
use crate::protocol::business::{BusinessAttribution, BusinessRegistry};
use crate::telemetry::TelemetryClient;
use crate::{ConclaveError, ConclaveResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub use self::bisq::BisqRail;
pub use self::boltz::BoltzRail;
pub use self::changelly::ChangellyRail;
pub use self::ntt::NTTRail;
pub use self::wormhole::WormholeRail;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapRequest {
    pub from_asset: AssetIdentifier,
    pub to_asset: AssetIdentifier,
    pub amount: u64,
    pub recipient_address: String,
    pub attribution: Option<BusinessAttribution>,
}

impl SwapRequest {
    /// Generates a deterministic byte representation of the request for hashing.
    pub fn get_hash_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.from_asset.chain.as_str().as_bytes());
        data.extend_from_slice(self.from_asset.symbol.as_bytes());
        data.extend_from_slice(self.to_asset.chain.as_str().as_bytes());
        data.extend_from_slice(self.to_asset.symbol.as_bytes());
        data.extend_from_slice(&self.amount.to_be_bytes());
        data.extend_from_slice(self.recipient_address.as_bytes());

        if let Some(attribution) = &self.attribution {
            data.extend_from_slice(&attribution.get_hash());
        }

        data
    }
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
    fn name(&self) -> &'static str;
    fn validate_request(&self, request: &SwapRequest) -> ConclaveResult<Option<String>>;
    async fn execute_swap(
        &self,
        intent: SwapIntent,
        signature: String,
    ) -> ConclaveResult<SwapResponse>;
}

/// The Sovereign Handshake: A non-custodial protocol where the Gateway
/// pushes requests to the mobile Enclave for signing before execution.
#[async_trait]
pub trait SovereignHandshake {
    /// Prepare a signable intent from a request.
    fn prepare_intent(&self, rail_name: &str, request: SwapRequest) -> ConclaveResult<SwapIntent>;

    /// Broadcast a signed intent to the rail, optionally verifying hardware attestation.
    async fn broadcast_signed_intent(
        &self,
        intent: SwapIntent,
        signature: String,
        attestation: Option<String>,
    ) -> ConclaveResult<SwapResponse>;
}

pub struct RailProxy {
    pub rails: HashMap<String, Box<dyn SovereignRail>>,
    pub endpoint: String,
    pub http_client: reqwest::Client,
    pub api_key: Option<String>,
    pub enforce_attestation: bool,
    pub asset_registry: Arc<AssetRegistry>,
    pub business_registry: Arc<BusinessRegistry>,
    pub telemetry: Option<Arc<TelemetryClient>>,
}

impl RailProxy {
    pub fn new(
        endpoint: String,
        http_client: reqwest::Client,
        asset_registry: Arc<AssetRegistry>,
        business_registry: Arc<BusinessRegistry>,
    ) -> Self {
        let mut rails: HashMap<String, Box<dyn SovereignRail>> = HashMap::with_capacity(5);

        // Register core rails with gateway endpoint and shared client
        rails.insert(
            "changelly".to_string(),
            Box::new(ChangellyRail {
                gateway_url: endpoint.clone(),
                http_client: http_client.clone(),
            }),
        );
        rails.insert(
            "bisq".to_string(),
            Box::new(BisqRail {
                gateway_url: endpoint.clone(),
                http_client: http_client.clone(),
            }),
        );
        rails.insert(
            "wormhole".to_string(),
            Box::new(WormholeRail {
                gateway_url: endpoint.clone(),
                http_client: http_client.clone(),
            }),
        );
        rails.insert(
            "boltz".to_string(),
            Box::new(BoltzRail {
                gateway_url: endpoint.clone(),
                http_client: http_client.clone(),
            }),
        );
        rails.insert(
            "ntt".to_string(),
            Box::new(NTTRail {
                gateway_url: endpoint.clone(),
                http_client: http_client.clone(),
            }),
        );

        Self {
            rails,
            endpoint,
            http_client,
            api_key: None,
            enforce_attestation: true,
            asset_registry,
            business_registry,
            telemetry: None,
        }
    }

    pub fn with_telemetry(mut self, telemetry: Arc<TelemetryClient>) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }

    pub fn register_rail(&mut self, rail: Box<dyn SovereignRail>) {
        self.rails.insert(rail.name().to_string(), rail);
    }

    fn verify_hardware_integrity(
        &self,
        intent: &SwapIntent,
        attestation_json: &Option<String>,
    ) -> ConclaveResult<()> {
        if !self.enforce_attestation {
            return Ok(());
        }

        let json = attestation_json
            .as_ref()
            .ok_or_else(|| ConclaveError::EnclaveFailure("Hardware attestation report missing for high-value rail operation".to_string()))?;
        let report: DeviceIntegrityReport =
            serde_json::from_str(json).map_err(|_| ConclaveError::InvalidPayload)?;

        if !report.verify(&intent.signable_hash) {
            return Err(ConclaveError::EnclaveFailure("Hardware attestation verification failed: Device integrity compromised, nonce mismatch, or attempting to use a Software/Simulated enclave for a high-value operation".to_string()));
        }

        // Verify business attribution if present
        if let Some(attribution) = &intent.request.attribution {
            let profile = self
                .business_registry
                .get_business(&attribution.business_id)
                .ok_or_else(|| ConclaveError::InvalidPayload)?;

            if !profile.active {
                return Err(ConclaveError::InvalidPayload);
            }

            if attribution.expiration < unix_time_secs() {
                return Err(ConclaveError::InvalidPayload);
            }

            // Cryptographic verification of attribution signature
            attribution
                .verify(&profile.public_key)
                .map_err(|e| ConclaveError::CryptoError(format!("Business attribution verification failed: {}", e)))?;
        }

        Ok(())
    }
}

#[async_trait]
impl SovereignHandshake for RailProxy {
    fn prepare_intent(&self, rail_name: &str, request: SwapRequest) -> ConclaveResult<SwapIntent> {
        let rail = self
            .rails
            .get(rail_name)
            .ok_or_else(|| ConclaveError::InvalidPayload)?;

        if request.amount == 0 {
            return Err(ConclaveError::InvalidPayload);
        }

        if !self
            .asset_registry
            .validate_pair(&request.from_asset, &request.to_asset)
        {
            return Err(ConclaveError::InvalidPayload);
        }

        let chain_context = rail.validate_request(&request).map_err(|e| ConclaveError::RailError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(rail_name.as_bytes());
        hasher.update(b":");
        hasher.update(request.get_hash_bytes());
        hasher.update(b":");
        if let Some(ctx) = &chain_context {
            hasher.update(ctx.as_bytes());
        }
        hasher.update(b":");
        hasher.update(self.endpoint.as_bytes());

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
        attestation: Option<String>,
    ) -> ConclaveResult<SwapResponse> {
        let rail = self
            .rails
            .get(&intent.rail_type)
            .ok_or_else(|| ConclaveError::InvalidPayload)?;

        if signature.is_empty() {
            return Err(ConclaveError::CryptoError("Sovereign signature required for broadcast".to_string()));
        }

        self.verify_hardware_integrity(&intent, &attestation)?;

        if let Some(telemetry) = &self.telemetry {
            let mut hasher = Sha256::new();
            hasher.update(signature.as_bytes());
            telemetry.track_signature(hex::encode(hasher.finalize()));
        }

        rail.execute_swap(intent, signature).await
    }
}

/// A custom rail extension example for partner-specific liquidity.
pub struct CustomRail;
#[async_trait]
impl SovereignRail for CustomRail {
    fn name(&self) -> &'static str {
        "custom_partner"
    }
    fn validate_request(&self, request: &SwapRequest) -> ConclaveResult<Option<String>> {
        if request.from_asset.chain != Chain::BITCOIN {
            return Err(ConclaveError::InvalidPayload);
        }
        Ok(Some("PARTNER_CUSTOM_v1".to_string()))
    }
    async fn execute_swap(
        &self,
        intent: SwapIntent,
        _signature: String,
    ) -> ConclaveResult<SwapResponse> {
        Ok(SwapResponse {
            transaction_id: format!("PARTNER-{}", hex::encode(&intent.signable_hash[..8])),
            status: "Partner processing".to_string(),
            estimated_arrival: 1200,
            rail_used: self.name().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::asset::{AssetIdentifier, Chain};
    use crate::protocol::business::BusinessAttribution;
    use std::collections::HashMap;

    #[test]
    fn test_swap_request_hash_determinism() {
        let from_asset = AssetIdentifier {
            chain: Chain::BITCOIN,
            symbol: "BTC".to_string(),
        };
        let to_asset = AssetIdentifier {
            chain: Chain::ETHEREUM,
            symbol: "ETH".to_string(),
        };

        let mut metadata1 = HashMap::new();
        metadata1.insert("a".to_string(), "1".to_string());
        metadata1.insert("b".to_string(), "2".to_string());
        metadata1.insert("c".to_string(), "3".to_string());

        let mut metadata2 = HashMap::new();
        metadata2.insert("c".to_string(), "3".to_string());
        metadata2.insert("b".to_string(), "2".to_string());
        metadata2.insert("a".to_string(), "1".to_string());

        let req1 = SwapRequest {
            from_asset: from_asset.clone(),
            to_asset: to_asset.clone(),
            amount: 1000,
            recipient_address: "0x123".to_string(),
            attribution: Some(BusinessAttribution {
                business_id: "p1".to_string(),
                user_id: "u1".to_string(),
                timestamp: 100,
                expiration: 200,
                nonce: [0u8; 16],
                signature: String::new(),
                metadata: metadata1,
            }),
        };

        let req2 = SwapRequest {
            from_asset: from_asset.clone(),
            to_asset: to_asset.clone(),
            amount: 1000,
            recipient_address: "0x123".to_string(),
            attribution: Some(BusinessAttribution {
                business_id: "p1".to_string(),
                user_id: "u1".to_string(),
                timestamp: 100,
                expiration: 200,
                nonce: [0u8; 16],
                signature: String::new(),
                metadata: metadata2,
            }),
        };

        assert_eq!(req1.get_hash_bytes(), req2.get_hash_bytes());
    }
}

#[cfg(test)]
mod rail_proxy_tests {
    use super::*;
    use crate::protocol::asset::AssetRegistry;
    use crate::protocol::business::BusinessRegistry;
    use crate::telemetry::TelemetryClient;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_rail_proxy_with_telemetry() {
        let registry = Arc::new(AssetRegistry::new());
        let business = Arc::new(BusinessRegistry::new());
        let telemetry = Arc::new(TelemetryClient::new("http://localhost".to_string(), "test_key".to_string()));

        let mut proxy = RailProxy::new(
            "https://api.conxian.io".to_string(),
            reqwest::Client::new(),
            registry,
            business,
        );
        proxy = proxy.with_telemetry(telemetry);

        assert!(proxy.telemetry.is_some());
    }
}
