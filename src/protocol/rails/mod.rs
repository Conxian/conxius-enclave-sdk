pub mod bisq;
pub mod boltz;
pub mod changelly;
pub mod ntt;
pub mod wormhole;
pub mod x402;

use crate::enclave::attestation::DeviceIntegrityReport;
use crate::enclave::replay_guard::ReplayGuard;
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

const ATTESTATION_REPLAY_TTL_SECS: u64 = 300;
const ATTESTATION_REPLAY_MAX_ENTRIES: usize = 4096;

fn attestation_bypass_allowed() -> bool {
    cfg!(any(test, feature = "dev-attestation-bypass"))
}

pub use self::bisq::BisqRail;
pub use self::boltz::BoltzRail;
pub use self::changelly::ChangellyRail;
pub use self::ntt::NTTRail;
pub use self::wormhole::WormholeRail;
pub use self::x402::X402Rail;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustTier {
    /// T1: Sovereign Verified (proof_verified)
    T1,
    /// T2: Hybrid Verified (proof_verified plus independent secondary verifier)
    T2,
    /// T3: Attester Network (attester_verified)
    T3,
    /// T4: Observer/Weak (observer_only)
    T4,
}

impl TrustTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustTier::T1 => "T1",
            TrustTier::T2 => "T2",
            TrustTier::T3 => "T3",
            TrustTier::T4 => "T4",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofEnvelope {
    pub system: String,
    pub system_version: String,
    pub trust_tier: TrustTier,
    pub verification_class: String,
    pub source_chain_id: String,
    pub destination_chain_id: String,
    pub finality_class: String,
    pub observed_at: u64,
    pub expires_at: u64,
    pub proof_ref: String,
    pub evidence_hash: String,
    pub verifier_set_id: String,
    pub verifier_threshold: u32,
    pub verification_status: String,
    pub config_hash: String,
    pub degrade_status: String,
    pub verification_reason: Option<String>,
}
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
    pub proof_envelope: Option<ProofEnvelope>,
}

#[async_trait]
pub trait SovereignRail: Send + Sync {
    fn name(&self) -> &'static str;
    fn trust_tier(&self) -> TrustTier;
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
    pub min_trust_tier: TrustTier,
    pub api_key: Option<String>,
    pub enforce_attestation: bool,
    pub asset_registry: Arc<AssetRegistry>,
    pub business_registry: Arc<BusinessRegistry>,
    pub telemetry: Option<Arc<TelemetryClient>>,
    replay_guard: ReplayGuard,
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
        rails.insert(
            "x402".to_string(),
            Box::new(X402Rail {
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
            min_trust_tier: TrustTier::T3, // Default to T3 for safety
            asset_registry,
            business_registry,
            telemetry: None,
            replay_guard: ReplayGuard::new(
                ATTESTATION_REPLAY_TTL_SECS,
                ATTESTATION_REPLAY_MAX_ENTRIES,
            ),
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

    pub fn with_min_trust_tier(mut self, tier: TrustTier) -> Self {
        self.min_trust_tier = tier;
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
        self.verify_hardware_integrity_with_policy(
            intent,
            attestation_json,
            attestation_bypass_allowed(),
        )
    }

    fn verify_hardware_integrity_with_policy(
        &self,
        intent: &SwapIntent,
        attestation_json: &Option<String>,
        bypass_allowed: bool,
    ) -> ConclaveResult<()> {
        if !self.enforce_attestation {
            if bypass_allowed {
                return Ok(());
            }

            return Err(ConclaveError::EnclaveFailure(
                "Attestation bypass requested, but this build does not allow bypass. Re-enable attestation or build with `dev-attestation-bypass` for dev/test-only use."
                    .to_string(),
            ));
        }

        let json = attestation_json.as_ref().ok_or_else(|| {
            ConclaveError::EnclaveFailure(
                "Hardware attestation report missing for high-value rail operation".to_string(),
            )
        })?;
        let report: DeviceIntegrityReport =
            serde_json::from_str(json).map_err(|_| ConclaveError::InvalidPayload)?;

        if !report.verify(&intent.signable_hash) {
            return Err(ConclaveError::EnclaveFailure("Hardware attestation verification failed: Device integrity compromised, nonce mismatch, stale timestamp, or attempting to use a Software/Simulated enclave for a high-value operation".to_string()));
        }

        let replay_key = format!(
            "{}:{}",
            report.get_device_fingerprint(),
            hex::encode(&intent.signable_hash)
        );
        if !self
            .replay_guard
            .check_and_record(&replay_key, unix_time_secs())
        {
            return Err(ConclaveError::EnclaveFailure(
                "Hardware attestation replay detected".to_string(),
            ));
        }

        // Verify business attribution if present
        if let Some(attribution) = &intent.request.attribution {
            let profile = self
                .business_registry
                .get_business(&attribution.business_id)
                .ok_or(ConclaveError::InvalidPayload)?;

            if !profile.active {
                return Err(ConclaveError::InvalidPayload);
            }

            if attribution.expiration < unix_time_secs() {
                return Err(ConclaveError::InvalidPayload);
            }

            // Cryptographic verification of attribution signature
            attribution.verify(&profile.public_key).map_err(|e| {
                ConclaveError::CryptoError(format!(
                    "Business attribution verification failed: {}",
                    e
                ))
            })?;
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
            .ok_or(ConclaveError::InvalidPayload)?;

        if rail.trust_tier() > self.min_trust_tier {
            return Err(ConclaveError::RailError(format!(
                "Rail {} has trust tier {:?}, but minimum required is {:?}",
                rail_name,
                rail.trust_tier(),
                self.min_trust_tier
            )));
        }

        if request.amount == 0 {
            return Err(ConclaveError::InvalidPayload);
        }

        if !self
            .asset_registry
            .validate_pair(&request.from_asset, &request.to_asset)
        {
            return Err(ConclaveError::InvalidPayload);
        }

        let chain_context = rail
            .validate_request(&request)
            .map_err(|e| ConclaveError::RailError(e.to_string()))?;

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
            .ok_or(ConclaveError::InvalidPayload)?;

        if signature.is_empty() {
            return Err(ConclaveError::CryptoError(
                "Sovereign signature required for broadcast".to_string(),
            ));
        }

        self.verify_hardware_integrity(&intent, &attestation)?;

        if let Some(telemetry) = &self.telemetry {
            let mut hasher = Sha256::new();
            hasher.update(signature.as_bytes());
            telemetry.track_signature(hex::encode(hasher.finalize()));
        }

        let mut response = rail.execute_swap(intent, signature).await?;

        // If the rail didn't provide a proof envelope, populate a default one
        // based on the rail's declared trust tier.
        if response.proof_envelope.is_none() {
            response.proof_envelope = Some(ProofEnvelope {
                system: rail.name().to_string(),
                system_version: "0.1.0".to_string(),
                trust_tier: rail.trust_tier(),
                verification_class: "default_observed".to_string(),
                source_chain_id: "unknown".to_string(),
                destination_chain_id: "unknown".to_string(),
                finality_class: "probabilistic".to_string(),
                observed_at: unix_time_secs(),
                expires_at: unix_time_secs() + 3600,
                proof_ref: response.transaction_id.clone(),
                evidence_hash: String::new(),
                verifier_set_id: "default".to_string(),
                verifier_threshold: 1,
                verification_status: "verified".to_string(),
                config_hash: String::new(),
                degrade_status: "none".to_string(),
                verification_reason: None,
            });
        }

        Ok(response)
    }
}

/// A custom rail extension example for partner-specific liquidity.
pub struct CustomRail;
#[async_trait]
impl SovereignRail for CustomRail {
    fn name(&self) -> &'static str {
        "custom_partner"
    }
    fn trust_tier(&self) -> TrustTier {
        TrustTier::T4
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
            proof_envelope: None,
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
    use crate::enclave::attestation::{AttestationLevel, DeviceIntegrityReport};
    use crate::protocol::asset::{AssetIdentifier, AssetRegistry, Chain};
    use crate::protocol::business::BusinessRegistry;
    use crate::telemetry::TelemetryClient;
    use std::sync::Arc;

    fn test_proxy() -> RailProxy {
        RailProxy::new(
            "https://gateway.conxian-labs.com".to_string(),
            reqwest::Client::new(),
            Arc::new(AssetRegistry::new()),
            Arc::new(BusinessRegistry::new()),
        )
    }

    fn test_intent(signable_hash: Vec<u8>) -> SwapIntent {
        SwapIntent {
            request: SwapRequest {
                from_asset: AssetIdentifier {
                    chain: Chain::BITCOIN,
                    symbol: "BTC".to_string(),
                },
                to_asset: AssetIdentifier {
                    chain: Chain::ETHEREUM,
                    symbol: "ETH".to_string(),
                },
                amount: 42,
                recipient_address: "0xabc".to_string(),
                attribution: None,
            },
            signable_hash,
            rail_type: "x402".to_string(),
            chain_context: None,
        }
    }

    fn test_attestation_json(nonce: Vec<u8>) -> String {
        serde_json::to_string(&DeviceIntegrityReport {
            level: AttestationLevel::TEE,
            challenge_nonce: nonce,
            signature: vec![7; 64],
            certificate_chain: vec![
                "CONCLAVE_ROOT_CA_01".to_string(),
                "CONCLAVE_HARDWARE_BACKED_DEVICE_0x1".to_string(),
            ],
            timestamp: unix_time_secs(),
            extension_data: "PURPOSE_SIGN|ALGORITHM_EC|OS_VERSION_14".to_string(),
        })
        .expect("attestation should serialize")
    }

    #[tokio::test]
    async fn test_rail_proxy_with_telemetry() {
        let registry = Arc::new(AssetRegistry::new());
        let business = Arc::new(BusinessRegistry::new());
        let telemetry = Arc::new(TelemetryClient::new(
            "http://localhost".to_string(),
            "test_key".to_string(),
        ));

        let mut proxy = RailProxy::new(
            "https://gateway.conxian-labs.com".to_string(),
            reqwest::Client::new(),
            registry,
            business,
        );
        proxy = proxy.with_telemetry(telemetry);

        assert!(proxy.telemetry.is_some());
    }

    #[test]
    fn test_verify_hardware_integrity_rejects_replay() {
        let proxy = test_proxy();
        let intent = test_intent(vec![3; 32]);
        let attestation = Some(test_attestation_json(intent.signable_hash.clone()));

        assert!(
            proxy
                .verify_hardware_integrity(&intent, &attestation)
                .is_ok()
        );

        let replay_result = proxy.verify_hardware_integrity(&intent, &attestation);
        assert!(matches!(
            replay_result,
            Err(ConclaveError::EnclaveFailure(message)) if message.contains("replay")
        ));
    }

    #[test]
    fn test_attestation_bypass_allowed_in_test_build() {
        let mut proxy = test_proxy();
        proxy.enforce_attestation = false;
        let intent = test_intent(vec![9; 32]);
        let no_attestation = None;

        assert!(
            proxy
                .verify_hardware_integrity(&intent, &no_attestation)
                .is_ok()
        );
    }

    #[test]
    fn test_attestation_bypass_fails_closed_when_policy_disallows_it() {
        let mut proxy = test_proxy();
        proxy.enforce_attestation = false;
        let intent = test_intent(vec![11; 32]);
        let no_attestation = None;

        let result = proxy.verify_hardware_integrity_with_policy(&intent, &no_attestation, false);

        assert!(matches!(
            result,
            Err(ConclaveError::EnclaveFailure(message)) if message.contains("does not allow bypass")
        ));
    }

    #[test]
    fn test_trust_tier_enforcement() {
        let mut proxy = test_proxy();
        let request = SwapRequest {
            from_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            to_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            amount: 100,
            recipient_address: "addr".to_string(),
            attribution: None,
        };

        // x402 is T1, proxy default is T3. Should pass.
        proxy.min_trust_tier = TrustTier::T3;
        assert!(proxy.prepare_intent("x402", request.clone()).is_ok());

        // Set requirement to T1. x402 (T1) should pass.
        proxy.min_trust_tier = TrustTier::T1;
        assert!(proxy.prepare_intent("x402", request.clone()).is_ok());

        // Set requirement to T1. wormhole (T3) should fail.
        let result = proxy.prepare_intent("wormhole", request.clone());
        assert!(result.is_err());
        if let Err(ConclaveError::RailError(msg)) = result {
            assert!(msg.contains("trust tier T3"));
            assert!(msg.contains("minimum required is T1"));
        } else {
            panic!("Expected RailError");
        }
    }

    #[tokio::test]
    async fn test_proof_envelope_injection() {
        let proxy = test_proxy();
        let _intent = test_intent(vec![13; 32]);
        // Note: this test requires mocking the network or using a mock rail
        // Since CustomRail returns None for proof_envelope, we can test injection there

        // CustomRail is T4, proxy default is T3. We need to allow T4.
        let mut proxy = proxy.with_min_trust_tier(TrustTier::T4);
        proxy.enforce_attestation = false;

        let mut rail_proxy = test_proxy();
        rail_proxy.enforce_attestation = false;
        rail_proxy.min_trust_tier = TrustTier::T4;
        rail_proxy.register_rail(Box::new(CustomRail));

        let mut intent = test_intent(vec![13; 32]);
        intent.rail_type = "custom_partner".to_string();

        let response = rail_proxy
            .broadcast_signed_intent(intent, "sig".to_string(), None)
            .await
            .unwrap();
        assert!(response.proof_envelope.is_some());
        let envelope = response.proof_envelope.unwrap();
        assert_eq!(envelope.trust_tier, TrustTier::T4);
        assert_eq!(envelope.system, "custom_partner");
    }
}
