pub(crate) mod bisq;
pub(crate) mod boltz;
pub(crate) mod changelly;
pub(crate) mod ntt;
pub(crate) mod wormhole;
pub(crate) mod x402;

use crate::enclave::attestation::{AttestationPolicy, DeviceIntegrityReport};
use crate::enclave::replay_guard::{ReplayGuard, ReplayGuardError};
use crate::enclave::{
    SignerProvenance, SignerVerification, SigningAlgorithm, ValueBearingPurpose,
    ValueBearingSignRequest, ValueBearingSignResponse, VALUE_BEARING_POLICY_ID,
};
use crate::protocol::asset::AssetRegistry;
use crate::protocol::business::BusinessRegistry;
use crate::protocol::intent::{SwapIntent, SwapRequest, SwapResponse};
use crate::protocol::solver::{SolverBid, SolverManager};
use crate::telemetry::{TelemetryClient, TelemetryEvent};
use crate::{ConclaveError, ConclaveResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

mod sealed {
    pub(super) trait SovereignRail {}
}

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

/// Canonical operation-context domain for typed settlement authorization.
pub const SETTLEMENT_OPERATION_DOMAIN: &str = "conxian/settlement/v1";

/// Built-in settlement adapters remain quarantined until their wire contract
/// and gateway compatibility are versioned and evidenced.
pub(crate) const BUILTIN_ADAPTER_DISPATCH_DISABLED_MESSAGE: &str =
    "Built-in settlement adapter dispatch is disabled pending a versioned wire contract and gateway compatibility evidence";

/// Reject built-in adapter dispatch before any adapter can construct or send a
/// request containing typed authorization or device evidence.
pub(crate) fn reject_builtin_adapter_dispatch() -> ConclaveResult<()> {
    Err(ConclaveError::Unsupported(
        BUILTIN_ADAPTER_DISPATCH_DISABLED_MESSAGE.to_string(),
    ))
}

/// Internal representation of a settlement rail (e.g. x402, Wormhole, NTT).
///
/// This trait is deliberately private and sealed. Downstream crates cannot
/// implement it, obtain a built-in rail, or invoke a rail with an opaque raw
/// signature. The only execution input is the private `VerifiedOperation`
/// created by a checked dispatcher or a `cfg(test)` fixture.
#[async_trait(?Send)]
#[allow(dead_code)]
trait SovereignRail: sealed::SovereignRail + Send + Sync {
    fn name(&self) -> &'static str;
    fn trust_tier(&self) -> TrustTier;
    fn validate_request(&self, request: &SwapRequest) -> ConclaveResult<Option<String>>;
    async fn execute_swap(&self, operation: VerifiedOperation) -> ConclaveResult<SwapResponse>;
}

/// Typed settlement authorization envelope. Its fields and constructor are
/// inaccessible outside this module; production code can only obtain one from
/// a provider-verified value-bearing response after the complete intent,
/// operation-key, policy, attestation, and replay bindings match.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct VerifiedOperation {
    intent: SwapIntent,
    authorization: VerifiedOperationAuthorization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VerifiedOperationAuthorization {
    canonical_intent_hash: [u8; 32],
    operation_binding: [u8; 32],
    algorithm: SigningAlgorithm,
    signature_hex: String,
    public_key_hex: String,
    attestation: DeviceIntegrityReport,
    provenance: SignerProvenance,
    verification: SignerVerification,
    policy_id: String,
    proof_set_digest: [u8; 32],
    proof_count: usize,
    replay_authorization: ReplayAuthorization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplayAuthorization {
    operation_binding: [u8; 32],
    token: [u8; 32],
}

impl VerifiedOperation {
    fn intent(&self) -> &SwapIntent {
        &self.intent
    }

    fn authorization(&self) -> &VerifiedOperationAuthorization {
        &self.authorization
    }

    fn into_parts(self) -> (SwapIntent, VerifiedOperationAuthorization) {
        (self.intent, self.authorization)
    }

    /// Test-only fixture constructor. This is intentionally not a production
    /// verification path and is not compiled into downstream library builds.
    #[cfg(test)]
    fn from_test_fixture(intent: SwapIntent, signature: String) -> Self {
        let canonical_intent_hash: [u8; 32] = intent
            .canonical_hash()
            .try_into()
            .expect("canonical fixture hash must be 32 bytes");
        let replay_authorization = ReplayAuthorization {
            operation_binding: canonical_intent_hash,
            token: Sha256::digest(
                [
                    b"CONXIAN-TEST-LEGACY-SETTLEMENT/v1".as_slice(),
                    canonical_intent_hash.as_slice(),
                ]
                .concat(),
            )
            .into(),
        };
        let fixture_request = ValueBearingSignRequest::new(
            crate::enclave::OperationContext::new(
                SETTLEMENT_OPERATION_DOMAIN,
                ValueBearingPurpose::Settlement,
                canonical_intent_hash.to_vec(),
            )
            .expect("legacy fixture context should be valid"),
            SigningAlgorithm::Ed25519,
            crate::enclave::TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID)
                .expect("legacy fixture policy should be valid"),
            canonical_intent_hash,
            crate::enclave::SignerKeyBinding::new("legacy-settlement-fixture", "m/0", vec![0; 32])
                .expect("legacy fixture key binding should be valid"),
            None,
        )
        .expect("legacy fixture request should be valid");
        let fixture_proof_set =
            crate::enclave::proof::test_fixture_set_for_request(&fixture_request)
                .expect("legacy fixture proof set should be valid");
        Self {
            intent,
            authorization: VerifiedOperationAuthorization {
                canonical_intent_hash,
                operation_binding: canonical_intent_hash,
                algorithm: SigningAlgorithm::EcdsaSecp256k1,
                signature_hex: signature,
                public_key_hex: String::new(),
                attestation: DeviceIntegrityReport {
                    report_version: 0,
                    report_type:
                        crate::enclave::attestation::AttestationReportType::DeviceIntegrity,
                    level: crate::enclave::attestation::AttestationLevel::TEE,
                    challenge_nonce: canonical_intent_hash.to_vec(),
                    signature: Vec::new(),
                    attested_operation_public_key: Vec::new(),
                    signer_key_binding: None,
                    certificate_chain: Vec::new(),
                    timestamp: 0,
                    extension_data: String::new(),
                    extensions: Vec::new(),
                },
                provenance: SignerProvenance::HardwareBacked,
                verification: SignerVerification::ProviderVerified,
                policy_id: VALUE_BEARING_POLICY_ID.to_string(),
                proof_set_digest: *fixture_proof_set.canonical_digest(),
                proof_count: fixture_proof_set.proof_count(),
                replay_authorization,
            },
        }
    }

    fn from_value_bearing(
        intent: SwapIntent,
        request: &ValueBearingSignRequest,
        response: ValueBearingSignResponse,
    ) -> ConclaveResult<Self> {
        let canonical_intent_hash: [u8; 32] = intent
            .canonical_hash()
            .try_into()
            .map_err(|_| ConclaveError::InvalidPayload)?;
        if intent.signable_hash != canonical_intent_hash {
            return Err(ConclaveError::EnclaveFailure(
                "typed settlement authorization requires the canonical intent hash".to_string(),
            ));
        }

        if request.message_digest() != &canonical_intent_hash {
            return Err(ConclaveError::EnclaveFailure(
                "typed settlement authorization digest does not match the canonical intent"
                    .to_string(),
            ));
        }

        let operation_context = request.operation_context();
        if operation_context.purpose() != ValueBearingPurpose::Settlement {
            return Err(ConclaveError::EnclaveFailure(
                "typed settlement authorization requires settlement purpose".to_string(),
            ));
        }
        if operation_context.domain() != SETTLEMENT_OPERATION_DOMAIN {
            return Err(ConclaveError::EnclaveFailure(
                "typed settlement authorization domain does not match the canonical settlement domain"
                    .to_string(),
            ));
        }
        if operation_context.context() != canonical_intent_hash.as_slice() {
            return Err(ConclaveError::EnclaveFailure(
                "typed settlement authorization context does not match the canonical intent"
                    .to_string(),
            ));
        }

        let requirement = request.trust_requirement();
        if requirement.policy_id() != VALUE_BEARING_POLICY_ID
            || response.signer_capability().provenance() != requirement.minimum_provenance()
            || response.signer_capability().verification() != requirement.required_verification()
            || response.signer_capability().policy_id() != Some(requirement.policy_id())
        {
            return Err(ConclaveError::Unsupported(
                "typed settlement authorization has insufficient signer provenance or policy"
                    .to_string(),
            ));
        }

        let request_binding = request.operation_binding()?;
        if response.operation_binding() != &request_binding
            || response.message_digest() != request.message_digest()
            || response.algorithm() != request.algorithm()
            || response.key_binding() != request.key_binding()
        {
            return Err(ConclaveError::EnclaveFailure(
                "typed settlement authorization operation binding does not match the request"
                    .to_string(),
            ));
        }

        let proof_set = response.proof_set().ok_or_else(|| {
            ConclaveError::Unsupported(
                "typed settlement authorization is missing an independently verified proof set"
                    .to_string(),
            )
        })?;
        if !proof_set.matches_binding(
            requirement.policy_id(),
            request.message_digest(),
            operation_context.purpose(),
            request.message_digest(),
            &request_binding,
        ) {
            return Err(ConclaveError::EnclaveFailure(
                "typed settlement proof set is not bound to the requested operation".to_string(),
            ));
        }
        if proof_set.proof_count() == 0 {
            return Err(ConclaveError::Unsupported(
                "typed settlement authorization requires at least one verified proof".to_string(),
            ));
        }

        let replay_authorization = response.replay_authorization().ok_or_else(|| {
            ConclaveError::Unsupported(
                "typed settlement authorization is missing manager replay authorization"
                    .to_string(),
            )
        })?;
        if replay_authorization.operation_binding() != response.operation_binding() {
            return Err(ConclaveError::EnclaveFailure(
                "typed settlement replay authorization does not match the operation binding"
                    .to_string(),
            ));
        }

        let attestation = response.attestation();
        if attestation.challenge_nonce != canonical_intent_hash
            || attestation.attested_operation_public_key != response.key_binding().public_key()
        {
            return Err(ConclaveError::EnclaveFailure(
                "typed settlement attestation is not bound to the canonical operation key"
                    .to_string(),
            ));
        }

        let signature_hex = response.sign_response().signature_hex.clone();
        let public_key_hex = response.sign_response().public_key_hex.clone();
        let token = settlement_replay_token(
            &canonical_intent_hash,
            &request_binding,
            &signature_hex,
            attestation,
        );

        Ok(Self {
            intent,
            authorization: VerifiedOperationAuthorization {
                canonical_intent_hash,
                operation_binding: request_binding,
                algorithm: request.algorithm(),
                signature_hex,
                public_key_hex,
                attestation: attestation.clone(),
                provenance: response.signer_capability().provenance(),
                verification: response.signer_capability().verification(),
                policy_id: requirement.policy_id().to_string(),
                proof_set_digest: *proof_set.canonical_digest(),
                proof_count: proof_set.proof_count(),
                replay_authorization: ReplayAuthorization {
                    operation_binding: *replay_authorization.operation_binding(),
                    token,
                },
            },
        })
    }
}

fn settlement_replay_token(
    canonical_intent_hash: &[u8; 32],
    operation_binding: &[u8; 32],
    signature_hex: &str,
    attestation: &DeviceIntegrityReport,
) -> [u8; 32] {
    let mut material = Vec::new();
    material.extend_from_slice(b"CONXIAN-SETTLEMENT-REPLAY/v1");
    material.extend_from_slice(canonical_intent_hash);
    material.extend_from_slice(operation_binding);
    material.extend_from_slice(signature_hex.as_bytes());
    material.extend_from_slice(attestation.get_device_fingerprint().as_bytes());
    Sha256::digest(material).into()
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
    ///
    /// Deprecated migration shim: this legacy API carries an opaque signature
    /// string and is not a rail execution boundary. Production builds always
    /// return `Unsupported` until a typed operation-signature envelope binds
    /// the algorithm, operation public key, provider evidence, and complete
    /// canonical intent hash. The old request-only hash format is rejected.
    #[deprecated(
        note = "Use the future typed operation-signature API; raw signatures are rejected."
    )]
    async fn broadcast_signed_intent(
        &self,
        intent: SwapIntent,
        signature: String,
        attestation: Option<String>,
    ) -> ConclaveResult<SwapResponse>;
}

/// Checked dispatcher for sovereign settlement rails.
///
/// Built-in rails and the internal `SovereignRail` boundary are intentionally
/// not part of the downstream API. The old raw-signature rail surface is kept
/// only as a deprecated, fail-closed migration shim:
///
/// ```compile_fail
/// use conxius_enclave_sdk::protocol::rails::{x402::X402Rail, SovereignRail};
/// fn main() {}
/// ```
pub struct RailProxy {
    pub gateway_url: String,
    pub client: reqwest::Client,
    pub registry: Arc<AssetRegistry>,
    pub business: Arc<BusinessRegistry>,
    rails: HashMap<String, Box<dyn SovereignRail>>,
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
            attestation_policy: default_attestation_policy(),
            replay_guard: Arc::new(ReplayGuard::new(1000, 300)),
            telemetry: None,
        }
    }

    pub fn with_telemetry(mut self, telemetry: Arc<TelemetryClient>) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    fn validate_request_assets(&self, request: &SwapRequest) -> ConclaveResult<()> {
        self.registry.validate_asset(&request.from_asset)?;
        self.registry.validate_asset(&request.to_asset)?;
        Ok(())
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

    #[cfg(test)]
    fn register_rail(&mut self, rail: Box<dyn SovereignRail>) {
        self.rails.insert(rail.name().to_string(), rail);
    }

    pub fn discover_best_rail(&self, request: &SwapRequest) -> ConclaveResult<String> {
        self.validate_request_assets(request)?;
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

    /// Preflight the typed operation dispatch boundary before any provider
    /// public-key lookup or value-bearing signing occurs.
    ///
    /// Validate the typed dispatch boundary before any provider public-key
    /// lookup or value-bearing signing occurs. Raw-signature rejection remains
    /// confined to the deprecated `broadcast_signed_intent` shim below.
    pub(crate) fn preflight_typed_dispatch(&self, intent: &SwapIntent) -> ConclaveResult<()> {
        self.validate_request_assets(&intent.request)?;
        if intent.signable_hash != intent.canonical_hash() {
            return Err(ConclaveError::EnclaveFailure(
                "Swap intent canonical hash mismatch; legacy request-only hashes are rejected"
                    .to_string(),
            ));
        }
        if !self.rails.contains_key(&intent.rail_type) {
            return Err(ConclaveError::RailError(format!(
                "Rail {} not found",
                intent.rail_type
            )));
        }

        Ok(())
    }

    fn verify_hardware_integrity(
        &self,
        intent: &SwapIntent,
        attestation_json: &Option<String>,
    ) -> ConclaveResult<()> {
        self.verify_hardware_integrity_with_attestation_policy_at_time(
            intent,
            attestation_json,
            &self.attestation_policy,
            unix_time_secs(),
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
        self.verify_hardware_integrity_with_attestation_policy_at_time(
            intent,
            attestation_json,
            policy,
            unix_time_secs(),
        )
    }

    fn verify_hardware_integrity_with_attestation_policy_at_time(
        &self,
        intent: &SwapIntent,
        attestation_json: &Option<String>,
        policy: &AttestationPolicy,
        now_secs: u64,
    ) -> ConclaveResult<()> {
        let canonical_hash = intent.canonical_hash();
        if intent.signable_hash != canonical_hash {
            return Err(ConclaveError::EnclaveFailure(
                "Swap intent canonical hash mismatch; legacy request-only hashes are rejected"
                    .to_string(),
            ));
        }

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

        if !report.verify_at_time_with_policy(&intent.signable_hash, now_secs, policy) {
            return Err(ConclaveError::EnclaveFailure(
                "Attestation report failed cryptographic or policy verification".to_string(),
            ));
        }

        // Replay state is consumed only after every report check succeeds.
        match self
            .replay_guard
            .try_check_and_record(&hex::encode(&intent.signable_hash), now_secs)
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

    #[cfg(test)]
    fn verify_hardware_integrity_at_time(
        &self,
        intent: &SwapIntent,
        attestation_json: &Option<String>,
        now_secs: u64,
    ) -> ConclaveResult<()> {
        self.verify_hardware_integrity_with_attestation_policy_at_time(
            intent,
            attestation_json,
            &self.attestation_policy,
            now_secs,
        )
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

    pub(crate) fn authorize_verified_operation(
        &self,
        intent: SwapIntent,
        request: &ValueBearingSignRequest,
        response: ValueBearingSignResponse,
    ) -> ConclaveResult<VerifiedOperation> {
        VerifiedOperation::from_value_bearing(intent, request, response)
    }

    pub(crate) async fn dispatch_verified_operation(
        &self,
        operation: VerifiedOperation,
    ) -> ConclaveResult<SwapResponse> {
        let intent = operation.intent();
        let authorization = operation.authorization();
        if intent.signable_hash != intent.canonical_hash() {
            return Err(ConclaveError::EnclaveFailure(
                "Swap intent canonical hash mismatch; legacy request-only hashes are rejected"
                    .to_string(),
            ));
        }

        let canonical_intent_hash: [u8; 32] = intent
            .canonical_hash()
            .try_into()
            .map_err(|_| ConclaveError::InvalidPayload)?;
        if authorization.canonical_intent_hash != canonical_intent_hash
            || authorization.replay_authorization.operation_binding
                != authorization.operation_binding
            || authorization.proof_count == 0
            || authorization.proof_set_digest == [0; 32]
        {
            return Err(ConclaveError::EnclaveFailure(
                "typed settlement authorization proof-set binding is incomplete or inconsistent"
                    .to_string(),
            ));
        }

        let rail_name = intent.rail_type.clone();
        let rail = self
            .rails
            .get(&rail_name)
            .ok_or(ConclaveError::RailError(format!(
                "Rail {} not found",
                rail_name
            )))?;

        if rail.name() != rail_name {
            return Err(ConclaveError::RailError(
                "Rail identity does not match the selected operation rail".to_string(),
            ));
        }

        match self.replay_guard.try_check_and_record(
            &hex::encode(authorization.replay_authorization.token),
            unix_time_secs(),
        ) {
            Ok(()) => {}
            Err(ReplayGuardError::Duplicate) => {
                return Err(ConclaveError::EnclaveFailure(
                    "typed settlement authorization replay detected".to_string(),
                ));
            }
            Err(ReplayGuardError::CapacitySaturated) => {
                return Err(ConclaveError::EnclaveFailure(
                    "typed settlement replay guard capacity is saturated".to_string(),
                ));
            }
            Err(ReplayGuardError::LockPoisoned) => {
                return Err(ConclaveError::EnclaveFailure(
                    "typed settlement replay guard is unavailable".to_string(),
                ));
            }
        }

        if let Some(telemetry) = &self.telemetry {
            let _ = telemetry.track_event(TelemetryEvent::SignedIntent);
        }

        rail.execute_swap(operation).await
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
        self.validate_request_assets(&request)?;
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

        let mut intent = SwapIntent {
            request: request.clone(),
            signable_hash: Vec::new(),
            rail_type: rail_name.to_string(),
            chain_context: None,
            fdc3_context,
        };
        intent.signable_hash = intent.canonical_hash();

        Ok(intent)
    }

    async fn broadcast_signed_intent(
        &self,
        intent: SwapIntent,
        signature: String,
        attestation: Option<String>,
    ) -> ConclaveResult<SwapResponse> {
        self.validate_request_assets(&intent.request)?;
        #[cfg(not(test))]
        {
            let _ = (intent, signature, attestation);
            return Err(ConclaveError::Unsupported(
                "Typed operation-signature envelope required; raw signatures are not verified and are never forwarded in production"
                    .to_string(),
            ));
        }

        #[cfg(test)]
        {
            let canonical_hash = intent.canonical_hash();
            if intent.signable_hash != canonical_hash {
                return Err(ConclaveError::EnclaveFailure(
                    "Swap intent canonical hash mismatch; legacy request-only hashes are rejected"
                        .to_string(),
                ));
            }

            // This branch exists only for local unit-test rail fixtures. It is
            // intentionally not compiled into downstream production builds.
            ensure_operation_signature_is_bound(&signature)?;
            self.verify_hardware_integrity(&intent, &attestation)?;

            let operation = VerifiedOperation::from_test_fixture(intent, signature);
            self.dispatch_verified_operation(operation).await
        }
    }
}

#[cfg(test)]
struct CustomRail;
#[cfg(test)]
impl sealed::SovereignRail for CustomRail {}
#[async_trait(?Send)]
#[cfg(test)]
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
    async fn execute_swap(&self, operation: VerifiedOperation) -> ConclaveResult<SwapResponse> {
        let (intent, _authorization) = operation.into_parts();
        Ok(SwapResponse {
            proof_envelope: Some("partner_proof".to_string()),
            transaction_id: format!("PARTNER-{}", hex::encode(&intent.signable_hash[..8])),
            status: "Partner processing".to_string(),
            estimated_arrival: 1200,
            rail_used: self.name().to_string(),
        })
    }
}

#[cfg(test)]
struct FailingRail;
#[cfg(test)]
impl sealed::SovereignRail for FailingRail {}
#[async_trait(?Send)]
#[cfg(test)]
impl SovereignRail for FailingRail {
    fn name(&self) -> &'static str {
        "failing_partner"
    }

    fn trust_tier(&self) -> TrustTier {
        TrustTier::T4
    }

    fn validate_request(&self, _request: &SwapRequest) -> ConclaveResult<Option<String>> {
        Ok(Some("Valid failing fixture rail".to_string()))
    }

    async fn execute_swap(&self, _operation: VerifiedOperation) -> ConclaveResult<SwapResponse> {
        Err(ConclaveError::RailError(
            "fixture rail failed after replay authorization".to_string(),
        ))
    }
}

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn default_attestation_policy() -> AttestationPolicy {
    #[cfg(test)]
    {
        AttestationPolicy::test_fixture()
    }

    #[cfg(not(test))]
    {
        AttestationPolicy::production()
    }
}

#[cfg(test)]
fn ensure_operation_signature_is_bound(signature: &str) -> ConclaveResult<()> {
    #[cfg(test)]
    {
        let _ = signature;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::asset::{AssetIdentifier, Chain};
    use crate::protocol::business::BusinessAttribution;

    const TEST_EVM_ADDRESS: &str = "0x52908400098527886E0F7030069857D2E4169EE7";

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
            recipient_address: TEST_EVM_ADDRESS.to_string(),
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
        parse_extension_data, test_signing_key, AttestationAlgorithm, AttestationLevel,
        AttestationPolicy, AttestationPurpose, AttestationReportType, DeviceIntegrityReport,
        SignerKeyBindingEvidence, ATTESTATION_ENVELOPE_VERSION, MAX_ATTESTATION_AGE_SECS,
        MAX_ATTESTATION_FUTURE_SKEW_SECS,
    };
    use crate::enclave::{EnclaveManager, SignRequest, SignResponse, SignerCapability};
    use crate::protocol::asset::{AssetIdentifier, AssetRegistry, Chain};
    use crate::protocol::business::BusinessRegistry;
    use crate::telemetry::{
        TelemetryClient, TelemetryDeliveryStatus, TelemetryPolicy, TestTransport, TransportError,
        TransportResponse,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::sync::Arc;
    use std::time::Duration;

    const TEST_MERCHANT_ENDPOINT: &str = "https://merchant.invalid/x402";

    fn test_proxy() -> RailProxy {
        RailProxy::new(
            "https://gateway.conxian-labs.com".to_string(),
            reqwest::Client::new(),
            Arc::new(AssetRegistry::new()),
            Arc::new(BusinessRegistry::new()),
        )
    }

    fn telemetry_test_policy() -> TelemetryPolicy {
        TelemetryPolicy::new(Duration::from_millis(25), 0, Duration::ZERO)
            .expect("telemetry test policy should be bounded")
    }

    fn telemetry_client_with_responses(
        responses: impl IntoIterator<Item = Result<TransportResponse, TransportError>>,
    ) -> (Arc<TelemetryClient>, Arc<TestTransport>) {
        let transport = Arc::new(TestTransport::with_responses(responses));
        let client = TelemetryClient::with_test_transport(
            "http://telemetry.invalid",
            "",
            telemetry_test_policy(),
            Arc::clone(&transport),
        )
        .expect("telemetry test client should be constructible");
        (Arc::new(client), transport)
    }

    async fn wait_for_telemetry_status(
        client: &TelemetryClient,
        expected: TelemetryDeliveryStatus,
    ) {
        for _ in 0..50 {
            if client.delivery_status() == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(client.delivery_status(), expected);
    }

    fn test_intent(seed: Vec<u8>) -> SwapIntent {
        let request = SwapRequest {
            from_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            to_asset: AssetIdentifier {
                chain: Chain::ETHEREUM,
                symbol: "ETH".to_string(),
            },
            amount: 42,
            recipient_address: format!("0x{}", hex::encode(seed)),
            attribution: None,
        };

        let mut intent = SwapIntent {
            signable_hash: Vec::new(),
            request,
            rail_type: "x402".to_string(),
            chain_context: None,
            fdc3_context: None,
        };
        intent.signable_hash = intent.canonical_hash();
        intent
    }

    #[test]
    fn typed_dispatch_preflight_is_validation_only() {
        let proxy = test_proxy();
        let intent = test_intent(vec![30; 32]);

        assert!(proxy.preflight_typed_dispatch(&intent).is_ok());

        let mut legacy_intent = intent;
        legacy_intent.signable_hash = legacy_intent.request.get_hash_bytes();
        assert!(matches!(
            proxy.preflight_typed_dispatch(&legacy_intent),
            Err(ConclaveError::EnclaveFailure(message))
                if message.contains("legacy request-only hashes are rejected")
        ));
    }

    fn test_attestation_report(nonce: Vec<u8>, timestamp: u64) -> DeviceIntegrityReport {
        let signing_key = test_signing_key();
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

        let extension_data = "PURPOSE_SIGN|ALGORITHM_ED25519|OS_VERSION_14".to_string();
        let extensions = parse_extension_data(&extension_data).expect("valid extensions");

        let mut report = DeviceIntegrityReport {
            report_version: ATTESTATION_ENVELOPE_VERSION,
            report_type: AttestationReportType::DeviceIntegrity,
            level: AttestationLevel::TEE,
            challenge_nonce: nonce,
            signature: Vec::new(),
            attested_operation_public_key: signing_key.verifying_key().to_bytes().to_vec(),
            signer_key_binding: None,
            certificate_chain: vec![pubkey_hex, "CONCLAVE_ROOT_CA_V1".to_string()],
            timestamp,
            extension_data,
            extensions,
        };
        report
            .sign_with_ed25519_key(&signing_key)
            .expect("fixture should sign");
        report
    }

    fn test_attestation_json(nonce: Vec<u8>) -> String {
        test_attestation_json_at(nonce, unix_time_secs())
    }

    fn test_attestation_json_at(nonce: Vec<u8>, timestamp: u64) -> String {
        serde_json::to_string(&test_attestation_report(nonce, timestamp))
            .expect("attestation should serialize")
    }

    struct SettlementFixtureProvider {
        operation_key: SigningKey,
        replay_guard: ReplayGuard,
        policy_id: String,
    }

    impl SettlementFixtureProvider {
        fn new(policy_id: &str) -> Self {
            Self {
                operation_key: SigningKey::from_bytes(&[7u8; 32]),
                replay_guard: ReplayGuard::new(300, 32),
                policy_id: policy_id.to_string(),
            }
        }

        fn operation_public_key(&self) -> Vec<u8> {
            self.operation_key.verifying_key().to_bytes().to_vec()
        }

        fn response_for(&self, request: &ValueBearingSignRequest) -> SignResponse {
            let attestation_key = test_signing_key();
            let operation_public_key = self.operation_key.verifying_key().to_bytes();
            let extension_data =
                "PURPOSE_SIGN|ALGORITHM_ED25519|TEE_ENABLED|HARDWARE_ROOT_OF_TRUST|OS_VERSION_14"
                    .to_string();
            let extensions = parse_extension_data(&extension_data).expect("valid extensions");
            let mut report = DeviceIntegrityReport {
                report_version: ATTESTATION_ENVELOPE_VERSION,
                report_type: AttestationReportType::DeviceIntegrity,
                level: AttestationLevel::TEE,
                challenge_nonce: request.message_digest().to_vec(),
                signature: Vec::new(),
                attested_operation_public_key: operation_public_key.to_vec(),
                signer_key_binding: None,
                certificate_chain: vec![
                    hex::encode(attestation_key.verifying_key().to_bytes()),
                    "CONCLAVE_ROOT_CA_V1".to_string(),
                ],
                timestamp: unix_time_secs(),
                extension_data,
                extensions,
            };
            let attestation_algorithm = match request.algorithm() {
                SigningAlgorithm::EcdsaSecp256k1 => AttestationAlgorithm::EcdsaSecp256k1,
                SigningAlgorithm::SchnorrSecp256k1 => AttestationAlgorithm::SchnorrSecp256k1,
                SigningAlgorithm::Ed25519 => AttestationAlgorithm::Ed25519,
            };
            report.signer_key_binding = Some(
                SignerKeyBindingEvidence::new(
                    request.key_binding().key_id(),
                    request.key_binding().derivation_path(),
                    request.key_binding().public_key(),
                    &operation_public_key,
                    request.message_digest(),
                    request.operation_context().purpose().canonical_token(),
                    AttestationPurpose::Sign,
                    attestation_algorithm,
                )
                .expect("fixture signer binding should construct"),
            );
            report
                .sign_with_ed25519_key(&attestation_key)
                .expect("fixture report should sign");

            SignResponse {
                signature_hex: hex::encode(
                    self.operation_key.sign(request.message_digest()).to_bytes(),
                ),
                public_key_hex: hex::encode(operation_public_key),
                device_attestation: Some(
                    serde_json::to_string(&report).expect("fixture report should serialize"),
                ),
            }
        }
    }

    impl EnclaveManager for SettlementFixtureProvider {
        fn initialize(&self) -> ConclaveResult<()> {
            Ok(())
        }

        fn generate_key(&self, key_id: &str) -> ConclaveResult<String> {
            Ok(key_id.to_string())
        }

        fn get_public_key(&self, _derivation_path: &str) -> ConclaveResult<String> {
            Ok(hex::encode(self.operation_key.verifying_key().to_bytes()))
        }

        fn sign(&self, _request: SignRequest) -> ConclaveResult<SignResponse> {
            Err(ConclaveError::EnclaveFailure(
                "settlement fixture raw sign must not be called".to_string(),
            ))
        }

        fn signer_capability(&self) -> SignerCapability {
            SignerCapability::provider_verified(self.policy_id.clone())
                .expect("fixture policy should be valid")
        }

        fn value_bearing_replay_guard(&self) -> Option<&ReplayGuard> {
            Some(&self.replay_guard)
        }

        fn sign_value_bearing_provider(
            &self,
            request: &ValueBearingSignRequest,
        ) -> ConclaveResult<SignResponse> {
            Ok(self.response_for(request))
        }
    }

    fn settlement_request_with_context(
        digest: [u8; 32],
        public_key: Vec<u8>,
        policy_id: &str,
        domain: &str,
        purpose: ValueBearingPurpose,
        context: Vec<u8>,
    ) -> ValueBearingSignRequest {
        ValueBearingSignRequest::new(
            crate::enclave::OperationContext::new(domain, purpose, context)
                .expect("fixture operation context should be valid"),
            SigningAlgorithm::Ed25519,
            crate::enclave::TrustRequirement::hardware_backed(policy_id)
                .expect("fixture policy should be valid"),
            digest,
            crate::enclave::SignerKeyBinding::new(
                "settlement-test-key",
                "m/44'/501'/0'/0/0",
                public_key,
            )
            .expect("fixture key binding should be valid"),
            None,
        )
        .expect("fixture signing request should be valid")
    }

    fn settlement_request(
        digest: [u8; 32],
        public_key: Vec<u8>,
        policy_id: &str,
    ) -> ValueBearingSignRequest {
        settlement_request_with_context(
            digest,
            public_key,
            policy_id,
            SETTLEMENT_OPERATION_DOMAIN,
            ValueBearingPurpose::Settlement,
            digest.to_vec(),
        )
    }

    fn custom_settlement_intent(seed: Vec<u8>) -> SwapIntent {
        let mut intent = test_intent(seed);
        intent.rail_type = "custom_partner".to_string();
        intent.signable_hash = intent.canonical_hash();
        intent
    }

    fn failing_settlement_intent(seed: Vec<u8>) -> SwapIntent {
        let mut intent = custom_settlement_intent(seed);
        intent.rail_type = "failing_partner".to_string();
        intent.signable_hash = intent.canonical_hash();
        intent
    }

    fn authorize_fixture_operation(
        proxy: &RailProxy,
        provider: &SettlementFixtureProvider,
        intent: SwapIntent,
    ) -> VerifiedOperation {
        let digest: [u8; 32] = intent
            .canonical_hash()
            .try_into()
            .expect("canonical intent hash should be 32 bytes");
        let request = settlement_request(
            digest,
            provider.operation_public_key(),
            VALUE_BEARING_POLICY_ID,
        );
        let response = provider
            .sign_value_bearing(request.clone())
            .expect("fixture provider should issue typed evidence")
            .with_test_proof_set(&request)
            .expect("fixture proof set should verify");
        proxy
            .authorize_verified_operation(intent, &request, response)
            .expect("fixture evidence should authorize the typed operation")
    }

    #[test]
    fn typed_settlement_envelope_rejects_intent_digest_key_and_policy_mismatch() {
        let proxy = test_proxy();
        let intent = custom_settlement_intent(vec![31; 32]);
        let digest: [u8; 32] = intent
            .canonical_hash()
            .try_into()
            .expect("canonical intent hash should be 32 bytes");

        let provider = SettlementFixtureProvider::new(VALUE_BEARING_POLICY_ID);
        let valid_request = settlement_request(
            digest,
            provider.operation_public_key(),
            VALUE_BEARING_POLICY_ID,
        );
        let valid_response = provider
            .sign_value_bearing(valid_request.clone())
            .expect("fixture provider should issue typed evidence")
            .with_test_proof_set(&valid_request)
            .expect("fixture proof set should verify");

        let wrong_purpose_request = settlement_request_with_context(
            digest,
            provider.operation_public_key(),
            VALUE_BEARING_POLICY_ID,
            SETTLEMENT_OPERATION_DOMAIN,
            ValueBearingPurpose::Transaction,
            digest.to_vec(),
        );
        let wrong_purpose_response = provider
            .sign_value_bearing(wrong_purpose_request.clone())
            .expect("fixture provider should issue wrong-purpose evidence");
        assert!(matches!(
            proxy.authorize_verified_operation(
                intent.clone(),
                &wrong_purpose_request,
                wrong_purpose_response,
            ),
            Err(ConclaveError::EnclaveFailure(message))
                if message.contains("requires settlement purpose")
        ));

        let wrong_domain_request = settlement_request_with_context(
            digest,
            provider.operation_public_key(),
            VALUE_BEARING_POLICY_ID,
            "conxian/settlement/other-v1",
            ValueBearingPurpose::Settlement,
            digest.to_vec(),
        );
        let wrong_domain_response = provider
            .sign_value_bearing(wrong_domain_request.clone())
            .expect("fixture provider should issue wrong-domain evidence");
        assert!(matches!(
            proxy.authorize_verified_operation(
                intent.clone(),
                &wrong_domain_request,
                wrong_domain_response,
            ),
            Err(ConclaveError::EnclaveFailure(message))
                if message.contains("canonical settlement domain")
        ));

        let wrong_context_request = settlement_request_with_context(
            digest,
            provider.operation_public_key(),
            VALUE_BEARING_POLICY_ID,
            SETTLEMENT_OPERATION_DOMAIN,
            ValueBearingPurpose::Settlement,
            vec![0xA5; 32],
        );
        let wrong_context_response = provider
            .sign_value_bearing(wrong_context_request.clone())
            .expect("fixture provider should issue same-digest altered-context evidence");
        assert!(matches!(
            proxy.authorize_verified_operation(
                intent.clone(),
                &wrong_context_request,
                wrong_context_response,
            ),
            Err(ConclaveError::EnclaveFailure(message))
                if message.contains("context does not match")
        ));

        let mut tampered_intent = intent.clone();
        tampered_intent.chain_context = Some("tampered-context".to_string());
        assert!(matches!(
            proxy.authorize_verified_operation(
                tampered_intent,
                &valid_request,
                valid_response.clone(),
            ),
            Err(ConclaveError::EnclaveFailure(message))
                if message.contains("canonical intent hash")
        ));

        let wrong_digest_request = settlement_request(
            [0xA1; 32],
            provider.operation_public_key(),
            VALUE_BEARING_POLICY_ID,
        );
        let wrong_digest_response = provider
            .sign_value_bearing(wrong_digest_request.clone())
            .expect("fixture provider should issue mismatched digest evidence");
        assert!(matches!(
            proxy.authorize_verified_operation(
                intent.clone(),
                &wrong_digest_request,
                wrong_digest_response,
            ),
            Err(ConclaveError::EnclaveFailure(message))
                if message.contains("digest does not match")
        ));

        let other_key = SigningKey::from_bytes(&[8u8; 32]);
        let wrong_key_request = settlement_request(
            digest,
            other_key.verifying_key().to_bytes().to_vec(),
            VALUE_BEARING_POLICY_ID,
        );
        assert!(matches!(
            proxy.authorize_verified_operation(
                intent.clone(),
                &wrong_key_request,
                valid_response.clone(),
            ),
            Err(ConclaveError::EnclaveFailure(message))
                if message.contains("operation binding does not match")
        ));

        let wrong_policy = "conxian.test.wrong-policy";
        let wrong_policy_request =
            settlement_request(digest, provider.operation_public_key(), wrong_policy);
        assert!(matches!(
            proxy.authorize_verified_operation(intent, &wrong_policy_request, valid_response),
            Err(ConclaveError::Unsupported(message))
                if message.contains("insufficient signer provenance or policy")
        ));
    }

    #[test]
    fn typed_settlement_envelope_rejects_missing_attestation_and_replay_authorization() {
        let proxy = test_proxy();
        let intent = custom_settlement_intent(vec![32; 32]);
        let digest: [u8; 32] = intent
            .canonical_hash()
            .try_into()
            .expect("canonical intent hash should be 32 bytes");
        let provider = SettlementFixtureProvider::new(VALUE_BEARING_POLICY_ID);
        let request = settlement_request(
            digest,
            provider.operation_public_key(),
            VALUE_BEARING_POLICY_ID,
        );

        let verified_without_proof_set = ValueBearingSignResponse::from_provider(
            &request,
            provider.response_for(&request),
            provider.signer_capability(),
        )
        .expect("provider evidence should verify before proof composition");
        assert!(matches!(
            proxy.authorize_verified_operation(
                intent.clone(),
                &request,
                verified_without_proof_set,
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("independently verified proof set")
        ));

        let mut missing_attestation = provider.response_for(&request);
        missing_attestation.device_attestation = None;
        assert!(matches!(
            ValueBearingSignResponse::from_provider(
                &request,
                missing_attestation,
                provider.signer_capability(),
            ),
            Err(ConclaveError::Unsupported(message)) if message.contains("evidence")
        ));

        let verified_without_manager_replay = ValueBearingSignResponse::from_provider(
            &request,
            provider.response_for(&request),
            provider.signer_capability(),
        )
        .expect("provider evidence should verify before manager replay is attached")
        .with_test_proof_set(&request)
        .expect("fixture proof set should verify");
        assert!(matches!(
            proxy.authorize_verified_operation(intent, &request, verified_without_manager_replay),
            Err(ConclaveError::Unsupported(message))
                if message.contains("missing manager replay authorization")
        ));
    }

    #[tokio::test]
    async fn typed_settlement_authorization_replay_is_rejected() {
        let mut proxy = test_proxy().with_min_trust_tier(TrustTier::T4);
        proxy.register_rail(Box::new(CustomRail));
        let provider = SettlementFixtureProvider::new(VALUE_BEARING_POLICY_ID);
        let operation =
            authorize_fixture_operation(&proxy, &provider, custom_settlement_intent(vec![33; 32]));
        let replay = operation.clone();

        assert!(proxy.dispatch_verified_operation(operation).await.is_ok());
        assert!(matches!(
            proxy.dispatch_verified_operation(replay).await,
            Err(ConclaveError::EnclaveFailure(message))
                if message.contains("typed settlement authorization replay detected")
        ));
    }

    #[tokio::test]
    async fn typed_settlement_replay_is_consumed_before_downstream_failure() {
        let mut proxy = test_proxy().with_min_trust_tier(TrustTier::T4);
        proxy.register_rail(Box::new(FailingRail));
        let provider = SettlementFixtureProvider::new(VALUE_BEARING_POLICY_ID);
        let operation =
            authorize_fixture_operation(&proxy, &provider, failing_settlement_intent(vec![34; 32]));
        let replay = operation.clone();

        // Replay authorization is intentionally consumed before adapter
        // execution; this test documents the current process-local semantics.
        assert!(matches!(
            proxy.dispatch_verified_operation(operation).await,
            Err(ConclaveError::RailError(message))
                if message.contains("failed after replay authorization")
        ));
        assert!(matches!(
            proxy.dispatch_verified_operation(replay).await,
            Err(ConclaveError::EnclaveFailure(message))
                if message.contains("typed settlement authorization replay detected")
        ));
    }

    #[tokio::test]
    async fn test_rail_proxy_with_telemetry() {
        let registry = Arc::new(AssetRegistry::new());
        let business = Arc::new(BusinessRegistry::new());
        let telemetry = Arc::new(TelemetryClient::new(
            "https://telemetry.invalid".to_string(),
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

    #[tokio::test]
    async fn test_canonical_intent_hash_mismatch_is_rejected_before_replay_recording() {
        let proxy = test_proxy();
        let mut intent = test_intent(vec![14; 32]);
        let canonical_hash = intent.signable_hash.clone();
        intent.signable_hash[0] ^= 0xFF;
        let forged_attestation = Some(test_attestation_json(intent.signable_hash.clone()));

        #[allow(deprecated)]
        let result = proxy
            .broadcast_signed_intent(
                intent.clone(),
                "opaque-signature".to_string(),
                forged_attestation,
            )
            .await;
        assert!(matches!(
            result,
            Err(ConclaveError::EnclaveFailure(message))
                if message.contains("canonical hash mismatch")
        ));

        // The rejected mismatch must not consume replay state for the real
        // canonical intent hash.
        intent.signable_hash = canonical_hash.clone();
        let valid_attestation = Some(test_attestation_json(canonical_hash));
        assert!(proxy
            .verify_hardware_integrity(&intent, &valid_attestation)
            .is_ok());
    }

    #[test]
    fn test_stale_and_future_reports_are_rejected() {
        const NOW_SECS: u64 = 1_000_000;

        let future_boundary_proxy = test_proxy();
        let future_boundary_intent = test_intent(vec![8; 32]);
        let future_boundary_json = Some(test_attestation_json_at(
            future_boundary_intent.signable_hash.clone(),
            NOW_SECS + MAX_ATTESTATION_FUTURE_SKEW_SECS,
        ));
        assert!(future_boundary_proxy
            .verify_hardware_integrity_at_time(
                &future_boundary_intent,
                &future_boundary_json,
                NOW_SECS,
            )
            .is_ok());

        let future_over_boundary_proxy = test_proxy();
        let future_over_boundary_intent = test_intent(vec![9; 32]);
        let future_over_boundary_json = Some(test_attestation_json_at(
            future_over_boundary_intent.signable_hash.clone(),
            NOW_SECS + MAX_ATTESTATION_FUTURE_SKEW_SECS + 1,
        ));
        assert!(matches!(
            future_over_boundary_proxy.verify_hardware_integrity_at_time(
                &future_over_boundary_intent,
                &future_over_boundary_json,
                NOW_SECS,
            ),
            Err(ConclaveError::EnclaveFailure(message))
                if message == "Attestation report failed cryptographic or policy verification"
        ));

        let stale_boundary_proxy = test_proxy();
        let stale_boundary_intent = test_intent(vec![10; 32]);
        let stale_boundary_json = Some(test_attestation_json_at(
            stale_boundary_intent.signable_hash.clone(),
            NOW_SECS - MAX_ATTESTATION_AGE_SECS,
        ));
        assert!(stale_boundary_proxy
            .verify_hardware_integrity_at_time(
                &stale_boundary_intent,
                &stale_boundary_json,
                NOW_SECS,
            )
            .is_ok());

        let stale_over_boundary_proxy = test_proxy();
        let stale_over_boundary_intent = test_intent(vec![11; 32]);
        let stale_over_boundary_json = Some(test_attestation_json_at(
            stale_over_boundary_intent.signable_hash.clone(),
            NOW_SECS - MAX_ATTESTATION_AGE_SECS - 1,
        ));
        assert!(matches!(
            stale_over_boundary_proxy.verify_hardware_integrity_at_time(
                &stale_over_boundary_intent,
                &stale_over_boundary_json,
                NOW_SECS,
            ),
            Err(ConclaveError::EnclaveFailure(message))
                if message == "Attestation report failed cryptographic or policy verification"
        ));
    }

    #[test]
    fn test_configured_attestation_policy_is_enforced() {
        let policy = AttestationPolicy::production()
            .with_test_trusted_roots(vec!["TEST_ROOT".to_string()])
            .unwrap()
            .with_allowed_levels(vec![AttestationLevel::TEE])
            .unwrap();
        let proxy = test_proxy().with_attestation_policy(policy);
        let intent = test_intent(vec![12; 32]);
        let mut report = test_attestation_report(intent.signable_hash.clone(), unix_time_secs());
        report.certificate_chain[1] = "TEST_ROOT".to_string();
        report
            .sign_with_ed25519_key(&test_signing_key())
            .expect("fixture should sign");
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
    fn test_legacy_request_only_hash_is_rejected() {
        let proxy = test_proxy();
        let mut intent = test_intent(vec![15; 32]);
        intent.signable_hash = intent.request.get_hash_bytes();

        let result = proxy.verify_hardware_integrity(&intent, &None);
        assert!(matches!(
            result,
            Err(ConclaveError::EnclaveFailure(message))
                if message.contains("legacy request-only hashes are rejected")
        ));
    }

    #[test]
    fn test_malformed_attestation_is_rejected_without_consuming_replay_state() {
        let proxy = test_proxy();
        let intent = test_intent(vec![15; 32]);
        let malformed = Some("{not-json".to_string());

        let result = proxy.verify_hardware_integrity(&intent, &malformed);
        assert!(matches!(
            result,
            Err(ConclaveError::EnclaveFailure(message)) if message.contains("Invalid attestation JSON")
        ));

        let valid = Some(test_attestation_json(intent.signable_hash.clone()));
        assert!(proxy.verify_hardware_integrity(&intent, &valid).is_ok());
    }

    #[test]
    fn test_wrong_purpose_is_rejected_without_consuming_replay_state() {
        let proxy = test_proxy();
        let intent = test_intent(vec![16; 32]);
        let mut report = test_attestation_report(intent.signable_hash.clone(), unix_time_secs());
        report.extension_data =
            "PURPOSE_VIEW|ALGORITHM_ED25519|TEE_ENABLED|HARDWARE_ROOT_OF_TRUST".to_string();
        report.extensions = parse_extension_data(&report.extension_data).expect("valid extensions");
        report
            .sign_with_ed25519_key(&test_signing_key())
            .expect("fixture should sign");
        let wrong_purpose = Some(serde_json::to_string(&report).unwrap());

        let result = proxy.verify_hardware_integrity(&intent, &wrong_purpose);
        assert!(matches!(
            result,
            Err(ConclaveError::EnclaveFailure(message)) if message.contains("cryptographic")
        ));

        let valid = Some(test_attestation_json(intent.signable_hash.clone()));
        assert!(proxy.verify_hardware_integrity(&intent, &valid).is_ok());
    }

    #[test]
    fn test_legacy_policy_flag_cannot_disable_attestation() {
        let proxy = test_proxy();
        let intent = test_intent(vec![11; 32]);
        let no_attestation = None;

        for legacy_enforce in [false, true] {
            let result = proxy.verify_hardware_integrity_with_policy(
                &intent,
                &no_attestation,
                legacy_enforce,
            );

            assert!(matches!(
                result,
                Err(ConclaveError::EnclaveFailure(message)) if message.contains("required")
            ));
        }
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
            recipient_address: TEST_MERCHANT_ENDPOINT.to_string(),
            attribution: None,
        };

        let proxy = proxy.with_min_trust_tier(TrustTier::T3);
        assert!(proxy.prepare_intent("x402", request.clone(), None).is_ok());

        let proxy = proxy.with_min_trust_tier(TrustTier::T1);
        assert!(proxy.prepare_intent("x402", request.clone(), None).is_ok());
    }

    #[tokio::test]
    async fn test_legacy_opaque_signature_path_is_test_only() {
        let mut rail_proxy = test_proxy();
        rail_proxy = rail_proxy.with_min_trust_tier(TrustTier::T4);
        rail_proxy.register_rail(Box::new(CustomRail));

        let mut intent = test_intent(vec![13; 32]);
        intent.rail_type = "custom_partner".to_string();
        intent.signable_hash = intent.canonical_hash();
        let attestation = Some(test_attestation_json(intent.signable_hash.clone()));

        // This deliberately opaque value is accepted only because this unit
        // test is compiled with the internal cfg(test) compatibility path.
        #[allow(deprecated)]
        let response = rail_proxy
            .broadcast_signed_intent(intent, "sig".to_string(), attestation)
            .await
            .unwrap();
        assert!(response.proof_envelope.is_some());
    }

    #[tokio::test]
    async fn test_disabled_telemetry_does_not_block_verified_dispatch() {
        let mut rail_proxy = test_proxy()
            .with_min_trust_tier(TrustTier::T4)
            .with_telemetry(Arc::new(TelemetryClient::disabled()));
        rail_proxy.register_rail(Box::new(CustomRail));

        let mut intent = test_intent(vec![16; 32]);
        intent.rail_type = "custom_partner".to_string();
        intent.signable_hash = intent.canonical_hash();
        let attestation = Some(test_attestation_json(intent.signable_hash.clone()));

        #[allow(deprecated)]
        let response = rail_proxy
            .broadcast_signed_intent(intent, "sig".to_string(), attestation)
            .await
            .expect("disabled telemetry must not block verified dispatch");

        assert!(response.proof_envelope.is_some());
        assert_eq!(
            rail_proxy
                .telemetry
                .as_ref()
                .expect("telemetry should remain attached")
                .delivery_status(),
            crate::telemetry::TelemetryDeliveryStatus::Disabled
        );
    }

    #[tokio::test]
    async fn enabled_telemetry_failure_does_not_change_verified_rail_result() {
        let (telemetry, transport) =
            telemetry_client_with_responses([Err(TransportError::Network)]);
        let mut rail_proxy = test_proxy()
            .with_min_trust_tier(TrustTier::T4)
            .with_telemetry(Arc::clone(&telemetry));
        rail_proxy.register_rail(Box::new(CustomRail));

        let intent = custom_settlement_intent(vec![17; 32]);
        let attestation = Some(test_attestation_json(intent.signable_hash.clone()));

        #[allow(deprecated)]
        let response = rail_proxy
            .broadcast_signed_intent(intent, "sig".to_string(), attestation)
            .await
            .expect("telemetry failure must not block verified dispatch");

        assert_eq!(response.proof_envelope.as_deref(), Some("partner_proof"));
        assert_eq!(response.rail_used, "custom_partner");
        wait_for_telemetry_status(&telemetry, TelemetryDeliveryStatus::Failed).await;
        assert_eq!(transport.request_count(), 1);
        assert_eq!(
            telemetry.last_failure().map(|failure| failure.kind),
            Some(crate::telemetry::TelemetryFailureKind::Network)
        );
    }

    #[tokio::test]
    async fn pre_dispatch_attestation_failure_does_not_schedule_telemetry() {
        let (telemetry, transport) =
            telemetry_client_with_responses([Ok(TransportResponse { status: 204 })]);
        let mut rail_proxy = test_proxy()
            .with_min_trust_tier(TrustTier::T4)
            .with_telemetry(Arc::clone(&telemetry));
        rail_proxy.register_rail(Box::new(CustomRail));

        let intent = custom_settlement_intent(vec![18; 32]);
        #[allow(deprecated)]
        let result = rail_proxy
            .broadcast_signed_intent(intent, "sig".to_string(), None)
            .await;

        assert!(matches!(
            result,
            Err(ConclaveError::EnclaveFailure(message)) if message.contains("attestation required")
        ));
        assert_eq!(telemetry.delivery_status(), TelemetryDeliveryStatus::Idle);
        assert_eq!(telemetry.failure_count(), 0);
        assert_eq!(transport.request_count(), 0);
    }

    #[tokio::test]
    async fn pre_dispatch_replay_failure_does_not_schedule_additional_telemetry() {
        let (telemetry, transport) = telemetry_client_with_responses([
            Ok(TransportResponse { status: 204 }),
            Ok(TransportResponse { status: 204 }),
        ]);
        let mut rail_proxy = test_proxy()
            .with_min_trust_tier(TrustTier::T4)
            .with_telemetry(Arc::clone(&telemetry));
        rail_proxy.register_rail(Box::new(CustomRail));

        let intent = custom_settlement_intent(vec![19; 32]);
        let attestation = Some(test_attestation_json(intent.signable_hash.clone()));

        #[allow(deprecated)]
        rail_proxy
            .broadcast_signed_intent(intent.clone(), "sig".to_string(), attestation.clone())
            .await
            .expect("initial verified dispatch should succeed");
        wait_for_telemetry_status(&telemetry, TelemetryDeliveryStatus::Delivered).await;
        assert_eq!(transport.request_count(), 1);

        #[allow(deprecated)]
        let replay_result = rail_proxy
            .broadcast_signed_intent(intent, "sig".to_string(), attestation)
            .await;
        assert!(matches!(
            replay_result,
            Err(ConclaveError::EnclaveFailure(message)) if message.contains("replay")
        ));
        assert_eq!(transport.request_count(), 1);
        assert_eq!(
            telemetry.delivery_status(),
            TelemetryDeliveryStatus::Delivered
        );
    }

    #[tokio::test]
    async fn built_in_adapter_dispatch_is_quarantined_before_network() {
        let proxy = test_proxy().with_min_trust_tier(TrustTier::T4);
        let client = reqwest::Client::new();
        let gateway_url = "http://127.0.0.1:9/should-not-connect".to_string();
        let adapters: Vec<(&str, Box<dyn SovereignRail>)> = vec![
            (
                "bisq",
                Box::new(bisq::BisqRail {
                    gateway_url: gateway_url.clone(),
                    http_client: client.clone(),
                }),
            ),
            (
                "boltz",
                Box::new(boltz::BoltzRail {
                    gateway_url: gateway_url.clone(),
                    http_client: client.clone(),
                }),
            ),
            (
                "changelly",
                Box::new(changelly::ChangellyRail {
                    gateway_url: gateway_url.clone(),
                    http_client: client.clone(),
                }),
            ),
            (
                "ntt",
                Box::new(ntt::NTTRail {
                    gateway_url: gateway_url.clone(),
                    http_client: client.clone(),
                }),
            ),
            (
                "wormhole",
                Box::new(wormhole::WormholeRail {
                    gateway_url: gateway_url.clone(),
                    http_client: client.clone(),
                }),
            ),
            (
                "x402",
                Box::new(x402::X402Rail {
                    gateway_url,
                    http_client: client,
                }),
            ),
        ];

        for (index, (rail_name, adapter)) in adapters.into_iter().enumerate() {
            let mut intent = test_intent(vec![index as u8 + 40; 32]);
            intent.rail_type = rail_name.to_string();
            intent.signable_hash = intent.canonical_hash();
            let provider = SettlementFixtureProvider::new(VALUE_BEARING_POLICY_ID);
            let operation = authorize_fixture_operation(&proxy, &provider, intent);

            let result = adapter.execute_swap(operation).await;

            assert!(
                matches!(
                    result,
                    Err(ConclaveError::Unsupported(message))
                        if message == BUILTIN_ADAPTER_DISPATCH_DISABLED_MESSAGE
                            && !message.contains("https://")
                            && !message.contains("PURPOSE_SIGN")
                            && !message.contains("CONXIAN-SETTLEMENT-REPLAY")
                ),
                "{rail_name} must fail closed before network dispatch"
            );
        }
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
            recipient_address: TEST_MERCHANT_ENDPOINT.to_string(),
            attribution: None,
        };

        let rail = proxy.discover_best_rail(&request).unwrap();
        assert_eq!(rail, "x402");
    }

    #[test]
    fn default_rail_policy_and_ordering_remain_unchanged() {
        assert!(TrustTier::T1 < TrustTier::T2);
        assert!(TrustTier::T2 < TrustTier::T3);
        assert!(TrustTier::T3 < TrustTier::T4);

        let proxy = test_proxy();
        assert_eq!(proxy.min_trust_tier(), TrustTier::T4);

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
            recipient_address: TEST_MERCHANT_ENDPOINT.to_string(),
            attribution: None,
        };

        assert_eq!(proxy.discover_best_rail(&request).unwrap(), "x402");
    }

    #[test]
    fn test_quarantined_asset_cannot_enter_routing() {
        let proxy = test_proxy();
        let request = SwapRequest {
            from_asset: AssetIdentifier {
                chain: Chain::MEZO,
                symbol: "BTC".to_string(),
            },
            to_asset: AssetIdentifier {
                chain: Chain::ETHEREUM,
                symbol: "ETH".to_string(),
            },
            amount: 100,
            recipient_address: TEST_MERCHANT_ENDPOINT.to_string(),
            attribution: None,
        };

        assert!(matches!(
            proxy.discover_best_rail(&request),
            Err(ConclaveError::Unsupported(message)) if message.contains("quarantined")
        ));
        assert!(matches!(
            proxy.prepare_intent("x402", request, None),
            Err(ConclaveError::Unsupported(message)) if message.contains("quarantined")
        ));
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
            recipient_address: TEST_MERCHANT_ENDPOINT.to_string(),
            attribution: None,
        };

        let fdc3 = crate::protocol::intent::Fdc3Context::instrument("BTC", "BITCOIN");
        let intent = proxy.prepare_intent("x402", request, Some(fdc3)).unwrap();

        assert!(intent.fdc3_context.is_some());
        assert_eq!(
            intent.fdc3_context.as_ref().unwrap().context_type,
            "fdc3.instrument"
        );
        assert_eq!(intent.signable_hash, intent.canonical_hash());
    }
}

#[cfg(test)]
mod fdc3_integration_tests {
    use super::*;
    use crate::protocol::asset::{AssetIdentifier, AssetRegistry, Chain};
    use crate::protocol::business::BusinessRegistry;
    use crate::protocol::intent::Fdc3Context;
    use std::sync::Arc;

    const TEST_MERCHANT_ENDPOINT: &str = "https://merchant.invalid/x402";

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
            recipient_address: TEST_MERCHANT_ENDPOINT.to_string(),
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
