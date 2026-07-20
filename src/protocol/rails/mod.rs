pub mod bisq;
pub mod boltz;
pub mod changelly;
pub mod ntt;
pub mod wormhole;
pub mod x402;

use crate::enclave::attestation::{AttestationPolicy, DeviceIntegrityReport};
use crate::enclave::replay_guard::{ReplayGuard, ReplayGuardError};
use crate::protocol::asset::AssetRegistry;
use crate::protocol::business::BusinessRegistry;
use crate::protocol::intent::{SwapIntent, SwapRequest, SwapResponse};
use crate::protocol::solver::{SolverBid, SolverManager};
use crate::telemetry::TelemetryClient;
use crate::{ConclaveError, ConclaveResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Represents the level of trust and security of a settlement rail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustTier {
    /// T1: Native & Hardware-Secure (e.g., L-BTC, sBTC with TEE/StrongBox)
    T1,
    /// T2: Managed & Attested (e.g., Industrial Gateway with device verification)
    T2,
    /// T3: Hybrid & Federated (e.g., Community Mint, Multi-sig Bridge)
    T3,
    /// T4: External & Permissionless (e.g., Wormhole, Uniswap, Changelly)
    T4,
}

/// Abstract representation of a settlement rail (e.g. x402, Wormhole, NTT).
#[async_trait(?Send)]
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
#[async_trait(?Send)]
pub trait SovereignHandshake {
    /// Prepare a signable intent from a request.
    fn prepare_intent(
        &self,
        rail_name: &str,
        request: SwapRequest,
        fdc3_context: Option<crate::protocol::intent::Fdc3Context>,
    ) -> ConclaveResult<SwapIntent>;

    /// Executes the swap by broadcasting the signed intent to the Gateway.
    async fn broadcast_signed_intent(
        &self,
        intent: SwapIntent,
        signature: String,
        attestation: Option<String>,
    ) -> ConclaveResult<SwapResponse>;
}

pub struct RailProxy {
    pub gateway_url: String,
    pub client: reqwest::Client,
    pub registry: Arc<AssetRegistry>,
    pub business: Arc<BusinessRegistry>,
    pub rails: HashMap<String, Box<dyn SovereignRail>>,
    min_trust_tier: TrustTier,
    attestation_policy: AttestationPolicy,
    replay_guard: Arc<ReplayGuard>,
    pub telemetry: Option<Arc<TelemetryClient>>,
}

impl RailProxy {
    pub fn new(
        gateway_url: String,
        client: reqwest::Client,
        registry: Arc<AssetRegistry>,
        business: Arc<BusinessRegistry>,
    ) -> Self {
        let mut rails: HashMap<String, Box<dyn SovereignRail>> = HashMap::new();
        // Register default industrial rails
        rails.insert(
            "x402".to_string(),
            Box::new(self::x402::X402Rail {
                gateway_url: gateway_url.clone(),
                http_client: client.clone(),
            }),
        );
        rails.insert(
            "ntt".to_string(),
            Box::new(self::ntt::NTTRail {
                gateway_url: gateway_url.clone(),
                http_client: client.clone(),
            }),
        );
        rails.insert(
            "wormhole".to_string(),
            Box::new(self::wormhole::WormholeRail {
                gateway_url: gateway_url.clone(),
                http_client: client.clone(),
            }),
        );

        Self {
            gateway_url,
            client,
            registry,
            business,
            rails,
            min_trust_tier: TrustTier::T4,
            attestation_policy: AttestationPolicy::production(),
            replay_guard: Arc::new(ReplayGuard::new(1000, 300)),
            telemetry: None,
        }
    }

    pub fn with_telemetry(mut self, telemetry: Arc<TelemetryClient>) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    pub fn with_min_trust_tier(mut self, min_trust_tier: TrustTier) -> Self {
        self.min_trust_tier = min_trust_tier;
        self
    }

    pub fn min_trust_tier(&self) -> TrustTier {
        self.min_trust_tier
    }

    /// Replaces the attestation policy without ever disabling attestation.
    pub fn with_attestation_policy(mut self, attestation_policy: AttestationPolicy) -> Self {
        self.attestation_policy = attestation_policy;
        self
    }

    pub fn attestation_policy(&self) -> &AttestationPolicy {
        &self.attestation_policy
    }

    /// Configures replay storage while preserving fail-closed saturation semantics.
    pub fn with_replay_guard(mut self, replay_guard: Arc<ReplayGuard>) -> Self {
        self.replay_guard = replay_guard;
        self
    }

    pub fn register_rail(&mut self, rail: Box<dyn SovereignRail>) {
        self.rails.insert(rail.name().to_string(), rail);
    }

    pub fn discover_best_rail(&self, request: &SwapRequest) -> ConclaveResult<String> {
        let mut candidates = Vec::new();

        for rail in self.rails.values() {
            if let Ok(Some(_)) = rail.validate_request(request) {
                if rail.trust_tier() <= self.min_trust_tier {
                    candidates.push(rail);
                }
            }
        }

        // Rank candidates using SolverManager primitives (ERC-7683 alignment)
        let bids = candidates
            .iter()
            .map(|r| SolverBid {
                solver_id: r.name().to_string(),
                rail_name: r.name().to_string(),
                output_amount: request.amount, // Base amount
                fee_sats: 100,
                estimated_latency_secs: match r.trust_tier() {
                    TrustTier::T1 => 10,
                    TrustTier::T2 => 60,
                    TrustTier::T3 => 300,
                    _ => 1200,
                },
            })
            .collect::<Vec<_>>();

        let ranked = SolverManager::rank_bids(bids)?;

        ranked
            .first()
            .map(|b| b.rail_name.clone())
            .ok_or(ConclaveError::RailError(
                "No suitable rail found meeting Trust Tier criteria".to_string(),
            ))
    }

    fn verify_hardware_integrity(
        &self,
        intent: &SwapIntent,
        attestation_json: &Option<String>,
    ) -> ConclaveResult<()> {
        self.verify_hardware_integrity_with_attestation_policy(
            intent,
            attestation_json,
            &self.attestation_policy,
        )
    }

    /// Verifies attestation against an explicit policy. Attestation is always
    /// required; there is no runtime bypass for value-bearing broadcasts.
    pub fn verify_hardware_integrity_with_attestation_policy(
        &self,
        intent: &SwapIntent,
        attestation_json: &Option<String>,
        policy: &AttestationPolicy,
    ) -> ConclaveResult<()> {
        let json = attestation_json
            .as_ref()
            .ok_or(ConclaveError::EnclaveFailure(
                "Hardware attestation required for this trust tier but none provided".to_string(),
            ))?;

        let report: DeviceIntegrityReport = serde_json::from_str(json).map_err(|e| {
            ConclaveError::EnclaveFailure(format!("Invalid attestation JSON: {}", e))
        })?;

        // Bind the evidence to this exact intent before running the complete
        // cryptographic, root, level, and freshness verification path.
        if report.challenge_nonce != intent.signable_hash {
            return Err(ConclaveError::EnclaveFailure(
                "Attestation challenge does not match intent hash".to_string(),
            ));
        }

        if !report.verify_with_policy(&intent.signable_hash, policy) {
            return Err(ConclaveError::EnclaveFailure(
                "Attestation report failed cryptographic or policy verification".to_string(),
            ));
        }

        // Replay state is consumed only after every report check succeeds.
        match self
            .replay_guard
            .try_check_and_record(&hex::encode(&intent.signable_hash), unix_time_secs())
        {
            Ok(()) => Ok(()),
            Err(ReplayGuardError::Duplicate) => Err(ConclaveError::EnclaveFailure(
                "Attestation replay detected".to_string(),
            )),
            Err(ReplayGuardError::CapacitySaturated) => Err(ConclaveError::EnclaveFailure(
                "Attestation replay guard capacity is saturated".to_string(),
            )),
            Err(ReplayGuardError::LockPoisoned) => Err(ConclaveError::EnclaveFailure(
                "Attestation replay guard is unavailable".to_string(),
            )),
        }
    }

    /// Legacy compatibility entry point. The former boolean was a runtime
    /// bypass; it is intentionally ignored and attestation remains mandatory.
    pub fn verify_hardware_integrity_with_policy(
        &self,
        intent: &SwapIntent,
        attestation_json: &Option<String>,
        _legacy_enforce: bool,
    ) -> ConclaveResult<()> {
        self.verify_hardware_integrity(intent, attestation_json)
    }
}

#[async_trait(?Send)]
impl SovereignHandshake for RailProxy {
    fn prepare_intent(
        &self,
        rail_name: &str,
        request: SwapRequest,
        fdc3_context: Option<crate::protocol::intent::Fdc3Context>,
    ) -> ConclaveResult<SwapIntent> {
        let rail = self
            .rails
            .get(rail_name)
            .ok_or(ConclaveError::RailError(format!(
                "Rail {} not found",
                rail_name
            )))?;

        if rail.trust_tier() > self.min_trust_tier {
            return Err(ConclaveError::RailError(
                "Selected rail does not meet minimum trust tier requirements".to_string(),
            ));
        }

        let _ = rail.validate_request(&request)?;

        let intent = SwapIntent {
            request: request.clone(),
            signable_hash: request.get_hash_bytes(),
            rail_type: rail_name.to_string(),
            chain_context: None,
            fdc3_context,
        };

        Ok(intent)
    }

    async fn broadcast_signed_intent(
        &self,
        intent: SwapIntent,
        signature: String,
        attestation: Option<String>,
    ) -> ConclaveResult<SwapResponse> {
        self.verify_hardware_integrity(&intent, &attestation)?;

        if let Some(telemetry) = &self.telemetry {
            telemetry.track_signature(hex::encode(&intent.signable_hash));
        }

        let rail = self
            .rails
            .get(&intent.rail_type)
            .ok_or(ConclaveError::RailError(format!(
                "Rail {} not found",
                intent.rail_type
            )))?;

        rail.execute_swap(intent, signature).await
    }
}

pub struct CustomRail;
#[async_trait(?Send)]
impl SovereignRail for CustomRail {
    fn name(&self) -> &'static str {
        "custom_partner"
    }
    fn trust_tier(&self) -> TrustTier {
        TrustTier::T4
    }
    fn validate_request(&self, _request: &SwapRequest) -> ConclaveResult<Option<String>> {
        Ok(Some("Valid partner".to_string()))
    }
    async fn execute_swap(
        &self,
        intent: SwapIntent,
        _signature: String,
    ) -> ConclaveResult<SwapResponse> {
        Ok(SwapResponse {
            proof_envelope: Some("partner_proof".to_string()),
            transaction_id: format!("PARTNER-{}", hex::encode(&intent.signable_hash[..8])),
            status: "Partner processing".to_string(),
            estimated_arrival: 1200,
            rail_used: self.name().to_string(),
        })
    }
}

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::asset::{AssetIdentifier, Chain};
    use crate::protocol::business::BusinessAttribution;

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

        assert_eq!(req1.get_hash_bytes().len(), 32);
    }
}

#[cfg(test)]
mod rail_proxy_tests {
    use super::*;
    use crate::enclave::attestation::{
        AttestationLevel, AttestationPolicy, DeviceIntegrityReport, MAX_ATTESTATION_AGE_SECS,
        MAX_ATTESTATION_FUTURE_SKEW_SECS,
    };
    use crate::protocol::asset::{AssetIdentifier, AssetRegistry, Chain};
    use crate::protocol::business::BusinessRegistry;
    use crate::telemetry::TelemetryClient;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::Rng;
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
            fdc3_context: None,
        }
    }

    fn test_attestation_report(nonce: Vec<u8>, timestamp: u64) -> DeviceIntegrityReport {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

        let extension_data = "PURPOSE_SIGN|ALGORITHM_ED25519|OS_VERSION_14".to_string();

        let mut data_to_verify = Vec::new();
        data_to_verify.extend_from_slice(&nonce);
        data_to_verify.extend_from_slice(extension_data.as_bytes());
        data_to_verify.extend_from_slice(&timestamp.to_le_bytes());

        let signature = signing_key.sign(&data_to_verify).to_bytes().to_vec();

        DeviceIntegrityReport {
            level: AttestationLevel::TEE,
            challenge_nonce: nonce,
            signature,
            certificate_chain: vec![pubkey_hex, "CONCLAVE_ROOT_CA_V1".to_string()],
            timestamp,
            extension_data,
        }
    }

    fn test_attestation_json(nonce: Vec<u8>) -> String {
        serde_json::to_string(&test_attestation_report(nonce, unix_time_secs()))
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

        assert!(proxy
            .verify_hardware_integrity(&intent, &attestation)
            .is_ok());

        let replay_result = proxy.verify_hardware_integrity(&intent, &attestation);
        assert!(matches!(
            replay_result,
            Err(ConclaveError::EnclaveFailure(message)) if message.contains("replay")
        ));
    }

    #[test]
    fn test_forged_report_is_rejected_without_consuming_replay_state() {
        let proxy = test_proxy();
        let intent = test_intent(vec![4; 32]);
        let mut forged_report =
            test_attestation_report(intent.signable_hash.clone(), unix_time_secs());
        forged_report.signature[0] ^= 0xFF;

        let forged_json = Some(serde_json::to_string(&forged_report).unwrap());
        let forged_result = proxy.verify_hardware_integrity(&intent, &forged_json);
        assert!(matches!(
            forged_result,
            Err(ConclaveError::EnclaveFailure(message)) if message.contains("cryptographic")
        ));

        let valid_json = Some(test_attestation_json(intent.signable_hash.clone()));
        assert!(proxy
            .verify_hardware_integrity(&intent, &valid_json)
            .is_ok());
    }

    #[test]
    fn test_wrong_nonce_is_rejected_before_replay_recording() {
        let proxy = test_proxy();
        let intent = test_intent(vec![5; 32]);
        let report = test_attestation_report(vec![6; 32], unix_time_secs());
        let attestation = Some(serde_json::to_string(&report).unwrap());

        let result = proxy.verify_hardware_integrity(&intent, &attestation);
        assert!(matches!(
            result,
            Err(ConclaveError::EnclaveFailure(message)) if message.contains("does not match")
        ));

        let valid_json = Some(test_attestation_json(intent.signable_hash.clone()));
        assert!(proxy
            .verify_hardware_integrity(&intent, &valid_json)
            .is_ok());
    }

    #[test]
    fn test_untrusted_root_is_rejected_without_consuming_replay_state() {
        let proxy = test_proxy();
        let intent = test_intent(vec![7; 32]);
        let mut report = test_attestation_report(intent.signable_hash.clone(), unix_time_secs());
        report.certificate_chain[1] = "UNTRUSTED_ROOT".to_string();
        let attestation = Some(serde_json::to_string(&report).unwrap());

        let result = proxy.verify_hardware_integrity(&intent, &attestation);
        assert!(matches!(
            result,
            Err(ConclaveError::EnclaveFailure(message)) if message.contains("cryptographic")
        ));

        let valid_json = Some(test_attestation_json(intent.signable_hash.clone()));
        assert!(proxy
            .verify_hardware_integrity(&intent, &valid_json)
            .is_ok());
    }

    #[test]
    fn test_stale_and_future_reports_are_rejected() {
        let now = unix_time_secs();

        let stale_proxy = test_proxy();
        let stale_intent = test_intent(vec![8; 32]);
        let stale_report = test_attestation_report(
            stale_intent.signable_hash.clone(),
            now.saturating_sub(MAX_ATTESTATION_AGE_SECS + 1),
        );
        let stale_json = Some(serde_json::to_string(&stale_report).unwrap());
        assert!(matches!(
            stale_proxy.verify_hardware_integrity(&stale_intent, &stale_json),
            Err(ConclaveError::EnclaveFailure(message)) if message.contains("cryptographic")
        ));

        let future_proxy = test_proxy();
        let future_intent = test_intent(vec![10; 32]);
        let future_report = test_attestation_report(
            future_intent.signable_hash.clone(),
            now.saturating_add(MAX_ATTESTATION_FUTURE_SKEW_SECS + 1),
        );
        let future_json = Some(serde_json::to_string(&future_report).unwrap());
        assert!(matches!(
            future_proxy.verify_hardware_integrity(&future_intent, &future_json),
            Err(ConclaveError::EnclaveFailure(message)) if message.contains("cryptographic")
        ));
    }

    #[test]
    fn test_configured_attestation_policy_is_enforced() {
        let policy = AttestationPolicy::production()
            .with_trusted_roots(vec!["TEST_ROOT".to_string()])
            .unwrap()
            .with_allowed_levels(vec![AttestationLevel::TEE])
            .unwrap();
        let proxy = test_proxy().with_attestation_policy(policy);
        let intent = test_intent(vec![12; 32]);
        let mut report = test_attestation_report(intent.signable_hash.clone(), unix_time_secs());
        report.certificate_chain[1] = "TEST_ROOT".to_string();
        let attestation = Some(serde_json::to_string(&report).unwrap());

        assert!(proxy
            .verify_hardware_integrity(&intent, &attestation)
            .is_ok());
    }

    #[test]
    fn test_attestation_is_always_required() {
        let proxy = test_proxy();
        let intent = test_intent(vec![9; 32]);
        let no_attestation = None;

        let result = proxy
            .verify_hardware_integrity(&intent, &no_attestation)
            .expect_err("attestation must be mandatory");
        assert!(matches!(
            result,
            ConclaveError::EnclaveFailure(message) if message.contains("required")
        ));
    }

    #[test]
    fn test_legacy_policy_flag_cannot_disable_attestation() {
        let proxy = test_proxy();
        let intent = test_intent(vec![11; 32]);
        let no_attestation = None;

        let result = proxy.verify_hardware_integrity_with_policy(&intent, &no_attestation, false);

        assert!(matches!(
            result,
            Err(ConclaveError::EnclaveFailure(message)) if message.contains("required")
        ));
    }

    #[test]
    fn test_trust_tier_enforcement() {
        let proxy = test_proxy();
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

        let proxy = proxy.with_min_trust_tier(TrustTier::T3);
        assert!(proxy.prepare_intent("x402", request.clone(), None).is_ok());

        let proxy = proxy.with_min_trust_tier(TrustTier::T1);
        assert!(proxy.prepare_intent("x402", request.clone(), None).is_ok());
    }

    #[tokio::test]
    async fn test_proof_envelope_injection() {
        let mut rail_proxy = test_proxy();
        rail_proxy = rail_proxy.with_min_trust_tier(TrustTier::T4);
        rail_proxy.register_rail(Box::new(CustomRail));

        let mut intent = test_intent(vec![13; 32]);
        intent.rail_type = "custom_partner".to_string();
        let attestation = Some(test_attestation_json(intent.signable_hash.clone()));

        let response = rail_proxy
            .broadcast_signed_intent(intent, "sig".to_string(), attestation)
            .await
            .unwrap();
        assert!(response.proof_envelope.is_some());
    }

    #[test]
    fn test_discover_best_rail() {
        let proxy = test_proxy().with_min_trust_tier(TrustTier::T3);

        let request = SwapRequest {
            from_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            to_asset: AssetIdentifier {
                chain: Chain::ETHEREUM,
                symbol: "ETH".to_string(),
            },
            amount: 100,
            recipient_address: "addr".to_string(),
            attribution: None,
        };

        let rail = proxy.discover_best_rail(&request).unwrap();
        assert_eq!(rail, "x402");
    }

    #[test]
    fn test_prepare_intent_with_fdc3() {
        let proxy = test_proxy();
        let request = SwapRequest {
            from_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            to_asset: AssetIdentifier {
                chain: Chain::ETHEREUM,
                symbol: "ETH".to_string(),
            },
            amount: 100,
            recipient_address: "addr".to_string(),
            attribution: None,
        };

        let fdc3 = crate::protocol::intent::Fdc3Context::instrument("BTC", "BITCOIN");
        let intent = proxy.prepare_intent("x402", request, Some(fdc3)).unwrap();

        assert!(intent.fdc3_context.is_some());
        assert_eq!(intent.fdc3_context.unwrap().context_type, "fdc3.instrument");
    }
}

#[cfg(test)]
mod fdc3_integration_tests {
    use super::*;
    use crate::protocol::asset::{AssetIdentifier, AssetRegistry, Chain};
    use crate::protocol::business::BusinessRegistry;
    use crate::protocol::intent::Fdc3Context;
    use std::sync::Arc;

    fn setup_proxy() -> RailProxy {
        RailProxy::new(
            "https://gateway.conxian.com".to_string(),
            reqwest::Client::new(),
            Arc::new(AssetRegistry::new()),
            Arc::new(BusinessRegistry::new()),
        )
    }

    #[test]
    fn test_resolve_fdc3_instrument_to_intent() {
        let proxy = setup_proxy();
        let fdc3 = Fdc3Context::instrument("USDC", "ETHEREUM");

        // Use proxy to resolve FDC3 context into a request
        // In a real flow, this might be a dedicated method like 'resolve_fdc3_context'
        let request = SwapRequest {
            from_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            to_asset: AssetIdentifier {
                chain: Chain::ETHEREUM,
                symbol: "USDC".to_string(),
            },
            amount: 1000,
            recipient_address: "0x123".to_string(),
            attribution: None,
        };

        let intent = proxy
            .prepare_intent("x402", request, Some(fdc3.clone()))
            .unwrap();

        assert!(intent.fdc3_context.is_some());
        let ctx = intent.fdc3_context.unwrap();
        assert_eq!(ctx.context_type, "fdc3.instrument");
        assert_eq!(ctx.id.get("ticker").unwrap(), "USDC");
    }
}
