#[cfg(any(test, feature = "development-simulators"))]
pub mod android_strongbox;
pub mod attestation;
#[cfg(any(test, feature = "development-simulators"))]
pub mod cloud;
#[cfg(not(target_arch = "wasm32"))]
pub mod nitro;
pub mod proof;
pub mod proofs;
pub mod replay_guard;

pub use proofs::{
    authorize_settlement_with_proofs, authorize_value_bearing_with_proofs,
    deserialize_proof_bundle_json, sign_value_bearing_with_proof_authorization,
    ProofBoundValueBearingAuthorization, ProofBundle, ProofEnvelope, ProofKind, ProofPolicy,
    ProofReplayKey, ProofRequirement, ProofVerificationContext, ProofVerifier,
    ProofVerifierRegistry, ProofVerifierStatus, UnlistedProofPolicy, VerifiedProofReceipt,
    VerifiedProofSet, FIDO_PROOF_VERIFIER_ID, MAX_PROOF_TRANSPORT_BYTES, PHONE_PROOF_VERIFIER_ID,
    PROOF_CONTEXT_DOMAIN, PROOF_ENVELOPE_DOMAIN, PROOF_ENVELOPE_VERSION, PROOF_POLICY_DOMAIN,
    PROOF_REPLAY_DOMAIN, SERVER_PROOF_VERIFIER_ID, SETTLEMENT_PROOF_AUDIENCE,
    SETTLEMENT_PROOF_PURPOSE, TEE_PROOF_VERIFIER_ID, TPM_PROOF_VERIFIER_ID, USER_PROOF_VERIFIER_ID,
};

#[cfg(test)]
mod hardware_attestation_tests;

use crate::enclave::attestation::{
    AttestationAlgorithm, AttestationPolicy, AttestationPurpose, DeviceIntegrityReport,
    SignerKeyBindingEvidence,
};
#[cfg(test)]
use crate::enclave::attestation::{AttestationExtension, AttestationLevel};
use crate::enclave::replay_guard::{ReplayGuard, ReplayGuardError};
use crate::{ConclaveError, ConclaveResult};
use ed25519_dalek::Verifier as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Domain separator for all value-bearing signing request bindings.
pub const VALUE_BEARING_SIGNING_DOMAIN: &str = "CONXIAN-VALUE-BEARING-SIGNING/v1";
pub const VALUE_BEARING_PROOF_POLICY_DOMAIN: &str = "CONXIAN-VALUE-BEARING-PROOF-POLICY/v1";
pub const VALUE_BEARING_POLICY_ID: &str = "conxian.production.signing.v1";

const MAX_CONTEXT_BYTES: usize = 4096;
const MAX_IDENTIFIER_BYTES: usize = 256;

fn validate_identifier(value: &str) -> ConclaveResult<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(crate::ConclaveError::InvalidPayload);
    }

    Ok(())
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) -> ConclaveResult<()> {
    let length = u32::try_from(value.len()).map_err(|_| crate::ConclaveError::InvalidPayload)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SigningAlgorithm {
    EcdsaSecp256k1,
    SchnorrSecp256k1,
    Ed25519,
}

impl SigningAlgorithm {
    fn canonical_tag(self) -> u8 {
        match self {
            Self::EcdsaSecp256k1 => 1,
            Self::SchnorrSecp256k1 => 2,
            Self::Ed25519 => 3,
        }
    }

    fn public_key_length_is_valid(self, length: usize) -> bool {
        match self {
            Self::EcdsaSecp256k1 => length == 33 || length == 65,
            Self::SchnorrSecp256k1 | Self::Ed25519 => length == 32,
        }
    }

    fn attestation_algorithm(self) -> AttestationAlgorithm {
        match self {
            Self::EcdsaSecp256k1 => AttestationAlgorithm::EcdsaSecp256k1,
            Self::SchnorrSecp256k1 => AttestationAlgorithm::SchnorrSecp256k1,
            Self::Ed25519 => AttestationAlgorithm::Ed25519,
        }
    }
}

/// Purpose for which a value-bearing signing request is authorized.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ValueBearingPurpose {
    Transaction,
    Settlement,
    Authorization,
}

impl ValueBearingPurpose {
    pub fn canonical_token(self) -> &'static str {
        match self {
            Self::Transaction => "TRANSACTION",
            Self::Settlement => "SETTLEMENT",
            Self::Authorization => "AUTHORIZATION",
        }
    }

    fn canonical_tag(self) -> u8 {
        match self {
            Self::Transaction => 1,
            Self::Settlement => 2,
            Self::Authorization => 3,
        }
    }
}

/// Explicit operation context used to domain-separate value-bearing requests.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OperationContext {
    domain: String,
    purpose: ValueBearingPurpose,
    context: Vec<u8>,
}

impl OperationContext {
    pub fn new(
        domain: impl Into<String>,
        purpose: ValueBearingPurpose,
        context: Vec<u8>,
    ) -> ConclaveResult<Self> {
        let domain = domain.into();
        validate_identifier(&domain)?;
        if context.is_empty() || context.len() > MAX_CONTEXT_BYTES {
            return Err(crate::ConclaveError::InvalidPayload);
        }

        Ok(Self {
            domain,
            purpose,
            context,
        })
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn purpose(&self) -> ValueBearingPurpose {
        self.purpose
    }

    pub fn context(&self) -> &[u8] {
        &self.context
    }

    fn append_canonical(&self, output: &mut Vec<u8>) -> ConclaveResult<()> {
        append_len_prefixed(output, self.domain.as_bytes())?;
        output.push(self.purpose.canonical_tag());
        append_len_prefixed(output, &self.context)
    }
}

/// Provenance class of the signer implementation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SignerProvenance {
    Software,
    HardwareBacked,
}

/// Verification status of the signer/provider evidence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SignerVerification {
    Unverified,
    ProviderVerified,
}

/// Typed capability advertised by an enclave manager.
///
/// The only capability available to existing managers is software/unverified.
/// Provider-verified capabilities are crate-issued by a future hardware-backed
/// provider integration after its attestation and key-binding checks complete.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SignerCapability {
    provenance: SignerProvenance,
    verification: SignerVerification,
    policy_id: Option<String>,
}

impl SignerCapability {
    pub const fn software_unverified() -> Self {
        Self {
            provenance: SignerProvenance::Software,
            verification: SignerVerification::Unverified,
            policy_id: None,
        }
    }

    pub fn provenance(&self) -> SignerProvenance {
        self.provenance
    }

    pub fn verification(&self) -> SignerVerification {
        self.verification
    }

    pub fn policy_id(&self) -> Option<&str> {
        self.policy_id.as_deref()
    }

    fn satisfies(&self, requirement: &TrustRequirement) -> bool {
        self.provenance == requirement.minimum_provenance
            && self.verification == requirement.required_verification
            && self.policy_id.as_deref() == Some(requirement.policy_id.as_str())
    }

    #[allow(dead_code)]
    pub(crate) fn provider_verified(policy_id: impl Into<String>) -> ConclaveResult<Self> {
        let policy_id = policy_id.into();
        validate_identifier(&policy_id)?;
        Ok(Self {
            provenance: SignerProvenance::HardwareBacked,
            verification: SignerVerification::ProviderVerified,
            policy_id: Some(policy_id),
        })
    }
}

/// Minimum trust and policy identity required for a value-bearing operation.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TrustRequirement {
    minimum_provenance: SignerProvenance,
    required_verification: SignerVerification,
    policy_id: String,
}

impl TrustRequirement {
    /// Creates the only trust requirement currently valid for value-bearing use.
    pub fn hardware_backed(policy_id: impl Into<String>) -> ConclaveResult<Self> {
        let policy_id = policy_id.into();
        validate_identifier(&policy_id)?;
        Ok(Self {
            minimum_provenance: SignerProvenance::HardwareBacked,
            required_verification: SignerVerification::ProviderVerified,
            policy_id,
        })
    }

    pub fn minimum_provenance(&self) -> SignerProvenance {
        self.minimum_provenance
    }

    pub fn required_verification(&self) -> SignerVerification {
        self.required_verification
    }

    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    fn append_canonical(&self, output: &mut Vec<u8>) -> ConclaveResult<()> {
        output.push(match self.minimum_provenance {
            SignerProvenance::Software => 1,
            SignerProvenance::HardwareBacked => 2,
        });
        output.push(match self.required_verification {
            SignerVerification::Unverified => 1,
            SignerVerification::ProviderVerified => 2,
        });
        append_len_prefixed(output, self.policy_id.as_bytes())
    }
}

/// Public-key and derivation identity that a value-bearing signature must bind.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SignerKeyBinding {
    key_id: String,
    derivation_path: String,
    public_key: Vec<u8>,
}

impl SignerKeyBinding {
    pub fn new(
        key_id: impl Into<String>,
        derivation_path: impl Into<String>,
        public_key: Vec<u8>,
    ) -> ConclaveResult<Self> {
        let key_id = key_id.into();
        let derivation_path = derivation_path.into();
        validate_identifier(&key_id)?;
        validate_identifier(&derivation_path)?;
        if public_key.is_empty() || public_key.len() > 65 {
            return Err(crate::ConclaveError::InvalidPayload);
        }

        Ok(Self {
            key_id,
            derivation_path,
            public_key,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn derivation_path(&self) -> &str {
        &self.derivation_path
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn append_canonical(&self, output: &mut Vec<u8>) -> ConclaveResult<()> {
        append_len_prefixed(output, self.key_id.as_bytes())?;
        append_len_prefixed(output, self.derivation_path.as_bytes())?;
        append_len_prefixed(output, &self.public_key)
    }
}

/// Explicit value-bearing signing request.
///
/// This type deliberately cannot be converted into [`SignRequest`]. A caller
/// must provide a domain-separated operation context, algorithm, provider
/// policy identity, digest, and expected public-key binding before reaching the
/// value-bearing boundary.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ValueBearingSignRequest {
    operation_context: OperationContext,
    algorithm: SigningAlgorithm,
    trust_requirement: TrustRequirement,
    message_digest: [u8; 32],
    key_binding: SignerKeyBinding,
    taproot_tweak: Option<Vec<u8>>,
    expected_proof_policy: Option<proof::ProofSetPolicy>,
}

impl ValueBearingSignRequest {
    pub fn new(
        operation_context: OperationContext,
        algorithm: SigningAlgorithm,
        trust_requirement: TrustRequirement,
        message_digest: [u8; 32],
        key_binding: SignerKeyBinding,
        taproot_tweak: Option<Vec<u8>>,
    ) -> ConclaveResult<Self> {
        if !algorithm.public_key_length_is_valid(key_binding.public_key.len()) {
            return Err(crate::ConclaveError::InvalidPayload);
        }
        if taproot_tweak
            .as_ref()
            .is_some_and(|tweak| tweak.len() != 32)
        {
            return Err(crate::ConclaveError::InvalidPayload);
        }

        Ok(Self {
            operation_context,
            algorithm,
            trust_requirement,
            message_digest,
            key_binding,
            taproot_tweak,
            expected_proof_policy: None,
        })
    }

    pub fn operation_context(&self) -> &OperationContext {
        &self.operation_context
    }

    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    pub fn trust_requirement(&self) -> &TrustRequirement {
        &self.trust_requirement
    }

    pub fn message_digest(&self) -> &[u8; 32] {
        &self.message_digest
    }

    pub fn key_binding(&self) -> &SignerKeyBinding {
        &self.key_binding
    }

    pub fn taproot_tweak(&self) -> Option<&[u8]> {
        self.taproot_tweak.as_deref()
    }

    /// Returns the exact proof policy expected for this value-bearing request.
    /// A missing policy remains source-compatible for existing callers, but
    /// the private value-bearing rail boundary rejects such a request.
    pub fn expected_proof_policy(&self) -> Option<&proof::ProofSetPolicy> {
        self.expected_proof_policy.as_ref()
    }

    pub fn expected_proof_policy_digest(&self) -> Option<&[u8; 32]> {
        self.expected_proof_policy
            .as_ref()
            .map(proof::ProofSetPolicy::canonical_digest)
    }

    /// Binds a complete, exact proof policy to this request. The operation,
    /// purpose, and signer policy identity must agree before the policy can
    /// enter the signing domain.
    pub fn with_proof_policy(
        mut self,
        expected_proof_policy: proof::ProofSetPolicy,
    ) -> ConclaveResult<Self> {
        if expected_proof_policy.policy_id() != self.trust_requirement.policy_id()
            || expected_proof_policy.operation_digest() != &self.message_digest
            || expected_proof_policy.purpose() != self.operation_context.purpose()
        {
            return Err(ConclaveError::InvalidPayload);
        }

        self.expected_proof_policy = Some(expected_proof_policy);
        Ok(self)
    }

    /// Returns the canonical digest binding every security-relevant request
    /// field under [`VALUE_BEARING_SIGNING_DOMAIN`].
    pub fn operation_binding(&self) -> ConclaveResult<[u8; 32]> {
        let mut canonical = Vec::new();
        append_len_prefixed(&mut canonical, VALUE_BEARING_SIGNING_DOMAIN.as_bytes())?;
        self.operation_context.append_canonical(&mut canonical)?;
        canonical.push(self.algorithm.canonical_tag());
        self.trust_requirement.append_canonical(&mut canonical)?;
        canonical.extend_from_slice(&self.message_digest);
        self.key_binding.append_canonical(&mut canonical)?;
        match &self.taproot_tweak {
            Some(tweak) => {
                canonical.push(1);
                append_len_prefixed(&mut canonical, tweak)?;
            }
            None => canonical.push(0),
        }
        append_len_prefixed(&mut canonical, VALUE_BEARING_PROOF_POLICY_DOMAIN.as_bytes())?;
        match self.expected_proof_policy_digest() {
            Some(policy_digest) => {
                canonical.push(1);
                append_len_prefixed(&mut canonical, policy_digest)?;
            }
            None => canonical.push(0),
        }

        Ok(Sha256::digest(canonical).into())
    }
}

/// Explicit value-bearing unlock request.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ValueBearingUnlockRequest {
    operation_context: OperationContext,
    trust_requirement: TrustRequirement,
}

impl ValueBearingUnlockRequest {
    pub fn new(operation_context: OperationContext, trust_requirement: TrustRequirement) -> Self {
        Self {
            operation_context,
            trust_requirement,
        }
    }

    pub fn operation_context(&self) -> &OperationContext {
        &self.operation_context
    }

    pub fn trust_requirement(&self) -> &TrustRequirement {
        &self.trust_requirement
    }
}

/// Opaque session returned only by a future provider-verified unlock path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueBearingSession {
    capability: SignerCapability,
    operation_binding: [u8; 32],
}

impl ValueBearingSession {
    pub fn signer_capability(&self) -> &SignerCapability {
        &self.capability
    }

    pub fn operation_binding(&self) -> &[u8; 32] {
        &self.operation_binding
    }

    #[allow(dead_code)]
    pub(crate) fn from_provider(
        request: &ValueBearingUnlockRequest,
        capability: SignerCapability,
    ) -> ConclaveResult<Self> {
        if !capability.satisfies(&request.trust_requirement) {
            return Err(crate::ConclaveError::Unsupported(
                "provider capability does not satisfy value-bearing trust policy".to_string(),
            ));
        }

        let mut canonical = Vec::new();
        append_len_prefixed(&mut canonical, VALUE_BEARING_SIGNING_DOMAIN.as_bytes())?;
        request.operation_context.append_canonical(&mut canonical)?;
        request.trust_requirement.append_canonical(&mut canonical)?;
        Ok(Self {
            capability,
            operation_binding: Sha256::digest(canonical).into(),
        })
    }
}

/// Replay authorization issued only after a provider-verified value-bearing
/// response has passed the manager-owned replay guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValueBearingReplayAuthorization {
    operation_binding: [u8; 32],
}

impl ValueBearingReplayAuthorization {
    fn new(operation_binding: [u8; 32]) -> Self {
        Self { operation_binding }
    }

    pub(crate) fn operation_binding(&self) -> &[u8; 32] {
        &self.operation_binding
    }
}

/// Typed result that can only be issued by a provider-verified signing path.
#[derive(Debug, Clone)]
pub struct ValueBearingSignResponse {
    response: SignResponse,
    capability: SignerCapability,
    operation_binding: [u8; 32],
    algorithm: SigningAlgorithm,
    message_digest: [u8; 32],
    key_binding: SignerKeyBinding,
    attestation: DeviceIntegrityReport,
    proof_set: Option<proof::VerifiedProofSet>,
    expected_proof_policy_digest: Option<[u8; 32]>,
    replay_authorization: Option<ValueBearingReplayAuthorization>,
}

impl ValueBearingSignResponse {
    pub fn sign_response(&self) -> &SignResponse {
        &self.response
    }

    pub fn signer_capability(&self) -> &SignerCapability {
        &self.capability
    }

    pub fn operation_binding(&self) -> &[u8; 32] {
        &self.operation_binding
    }

    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    pub fn message_digest(&self) -> &[u8; 32] {
        &self.message_digest
    }

    pub fn key_binding(&self) -> &SignerKeyBinding {
        &self.key_binding
    }

    /// Complete attestation evidence that was verified before this response
    /// crossed the typed provider boundary.
    pub fn attestation(&self) -> &DeviceIntegrityReport {
        &self.attestation
    }

    /// Independently verified proof factors attached to this response. Legacy
    /// device reports are never silently upgraded into this set.
    pub fn proof_set(&self) -> Option<&proof::VerifiedProofSet> {
        self.proof_set.as_ref()
    }

    pub(crate) fn expected_proof_policy_digest(&self) -> Option<&[u8; 32]> {
        self.expected_proof_policy_digest.as_ref()
    }

    /// Returns replay authorization only for responses returned by the common
    /// manager boundary. Direct test-only evidence construction is not enough
    /// to authorize settlement.
    pub(crate) fn replay_authorization(&self) -> Option<&ValueBearingReplayAuthorization> {
        self.replay_authorization.as_ref()
    }

    fn with_replay_authorization(
        mut self,
        replay_authorization: ValueBearingReplayAuthorization,
    ) -> Self {
        self.replay_authorization = Some(replay_authorization);
        self
    }

    /// Attaches a verified proof set only after checking the exact request
    /// binding and expected canonical policy digest. There is intentionally no
    /// unchecked public attachment path.
    pub fn with_verified_proof_set(
        mut self,
        request: &ValueBearingSignRequest,
        proof_set: proof::VerifiedProofSet,
    ) -> ConclaveResult<Self> {
        let expected_policy = request.expected_proof_policy().ok_or_else(|| {
            ConclaveError::Unsupported(
                "verified proof attachment requires an expected proof policy".to_string(),
            )
        })?;
        let request_binding = request.operation_binding()?;
        if self.operation_binding != request_binding
            || self.message_digest != *request.message_digest()
            || self.algorithm != request.algorithm()
            || self.key_binding != *request.key_binding()
        {
            return Err(ConclaveError::EnclaveFailure(
                "verified proof attachment does not match the signing request".to_string(),
            ));
        }
        if proof_set.policy_digest() != expected_policy.policy_digest() {
            return Err(ConclaveError::EnclaveFailure(
                "verified proof attachment policy digest does not match the request-side expected policy"
                    .to_string(),
            ));
        }
        if proof_set.proof_count() == 0
            || !proof_set.matches_binding(
                expected_policy,
                request.message_digest(),
                request.operation_context().purpose(),
            )
        {
            return Err(ConclaveError::EnclaveFailure(
                "verified proof attachment does not match the exact expected proof policy"
                    .to_string(),
            ));
        }

        self.proof_set = Some(proof_set);
        self.expected_proof_policy_digest = Some(*expected_policy.policy_digest());
        Ok(self)
    }

    #[cfg(test)]
    pub(crate) fn with_test_proof_set(
        self,
        request: &ValueBearingSignRequest,
    ) -> ConclaveResult<Self> {
        let proof_set = proof::test_fixture_set_for_request(request)?;
        self.with_verified_proof_set(request, proof_set)
    }

    #[cfg(test)]
    pub(crate) fn with_test_unchecked_proof_set(
        mut self,
        proof_set: proof::VerifiedProofSet,
    ) -> Self {
        self.proof_set = Some(proof_set);
        self
    }

    #[allow(dead_code)]
    pub(crate) fn from_provider(
        request: &ValueBearingSignRequest,
        response: SignResponse,
        capability: SignerCapability,
    ) -> ConclaveResult<Self> {
        let now_secs = trusted_unix_time_secs()?;
        Self::from_provider_at_time(request, response, capability, now_secs)
    }

    fn from_provider_at_time(
        request: &ValueBearingSignRequest,
        response: SignResponse,
        capability: SignerCapability,
        now_secs: u64,
    ) -> ConclaveResult<Self> {
        if !capability.satisfies(&request.trust_requirement) {
            return Err(crate::ConclaveError::Unsupported(
                "provider capability does not satisfy value-bearing trust policy".to_string(),
            ));
        }

        let signature = hex::decode(&response.signature_hex)
            .map_err(|_| crate::ConclaveError::InvalidPayload)?;
        if signature.is_empty() || !signature.iter().any(|byte| *byte != 0) {
            return Err(crate::ConclaveError::Unsupported(
                "provider returned no usable value-bearing signature".to_string(),
            ));
        }

        let public_key = hex::decode(&response.public_key_hex)
            .map_err(|_| crate::ConclaveError::InvalidPayload)?;
        if public_key != request.key_binding.public_key {
            return Err(crate::ConclaveError::Unsupported(
                "provider response is not bound to the requested signing key".to_string(),
            ));
        }

        let attestation_json = response
            .device_attestation
            .as_deref()
            .filter(|evidence| !evidence.is_empty())
            .ok_or_else(|| {
                crate::ConclaveError::Unsupported(
                    "provider response is missing required value-bearing evidence".to_string(),
                )
            })?;
        let report: DeviceIntegrityReport = serde_json::from_str(attestation_json)
            .map_err(|_| crate::ConclaveError::InvalidPayload)?;
        let policy = value_bearing_attestation_policy(request)?;
        if !report.verify_at_time_with_policy(request.message_digest(), now_secs, &policy) {
            return Err(crate::ConclaveError::Unsupported(
                "provider response failed complete value-bearing attestation policy verification"
                    .to_string(),
            ));
        }

        if report.attested_operation_public_key != public_key {
            return Err(crate::ConclaveError::Unsupported(
                "attestation leaf is not bound to the operation signing key".to_string(),
            ));
        }

        let expected_binding = SignerKeyBindingEvidence::new(
            request.key_binding.key_id(),
            request.key_binding.derivation_path(),
            request.key_binding.public_key(),
            &public_key,
            request.message_digest(),
            request.operation_context.purpose().canonical_token(),
            AttestationPurpose::Sign,
            request.algorithm.attestation_algorithm(),
        )?;
        if report.signer_key_binding.as_ref() != Some(&expected_binding) {
            return Err(crate::ConclaveError::Unsupported(
                "attestation evidence is not bound to the requested value-bearing operation"
                    .to_string(),
            ));
        }

        verify_operation_signature(request, &response)?;

        Ok(Self {
            response,
            capability,
            operation_binding: request.operation_binding()?,
            algorithm: request.algorithm(),
            message_digest: *request.message_digest(),
            key_binding: request.key_binding().clone(),
            attestation: report,
            proof_set: None,
            expected_proof_policy_digest: None,
            replay_authorization: None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub algorithm: SigningAlgorithm,
    pub message_hash: Vec<u8>,
    pub derivation_path: String,
    pub key_id: String,
    pub taproot_tweak: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignResponse {
    pub signature_hex: String,
    pub public_key_hex: String,
    pub device_attestation: Option<String>,
}

pub trait EnclaveManager: Send + Sync {
    fn initialize(&self) -> ConclaveResult<()>;
    /// Legacy unlock is opt-in. A default implementation must not claim that a
    /// session exists when an implementation has not established one.
    fn unlock(&self, _secret: &str, _salt: &[u8]) -> ConclaveResult<()> {
        Err(ConclaveError::Unsupported(
            "enclave unlock is not implemented by this manager".to_string(),
        ))
    }
    fn generate_key(&self, key_id: &str) -> ConclaveResult<String>;
    fn get_public_key(&self, derivation_path: &str) -> ConclaveResult<String>;
    fn sign(&self, request: SignRequest) -> ConclaveResult<SignResponse>;

    /// Existing implementations default to software/unverified provenance.
    /// A future hardware-backed provider must explicitly supply a provider-issued
    /// capability and override the value-bearing methods below.
    fn signer_capability(&self) -> SignerCapability {
        SignerCapability::software_unverified()
    }

    /// Returns manager-owned replay state for the typed value-bearing boundary.
    /// A provider that cannot supply safe in-process replay containment must
    /// leave this unavailable so signing fails closed.
    fn value_bearing_replay_guard(&self) -> Option<&ReplayGuard> {
        None
    }

    /// Provider-only operation. Implementations must return a response for the
    /// exact typed request and must never route through [`Self::sign`].
    fn sign_value_bearing_provider(
        &self,
        _request: &ValueBearingSignRequest,
    ) -> ConclaveResult<SignResponse> {
        Err(crate::ConclaveError::Unsupported(
            "value-bearing signing provider contract is unavailable".to_string(),
        ))
    }

    /// Value-bearing unlock never falls back to legacy unlock or software state.
    fn unlock_value_bearing(
        &self,
        request: ValueBearingUnlockRequest,
    ) -> ConclaveResult<ValueBearingSession> {
        if !self
            .signer_capability()
            .satisfies(&request.trust_requirement)
        {
            return Err(crate::ConclaveError::Unsupported(
                "value-bearing unlock requires a provider-verified hardware enclave".to_string(),
            ));
        }

        Err(crate::ConclaveError::Unsupported(
            "value-bearing unlock provider contract is unavailable".to_string(),
        ))
    }

    /// Value-bearing signing never delegates to the legacy [`Self::sign`] path.
    fn sign_value_bearing(
        &self,
        request: ValueBearingSignRequest,
    ) -> ConclaveResult<ValueBearingSignResponse> {
        sign_value_bearing_with_trusted_clock(self, request, trusted_unix_time_secs())
    }
}

fn sign_value_bearing_with_trusted_clock<E: EnclaveManager + ?Sized>(
    enclave: &E,
    request: ValueBearingSignRequest,
    trusted_now_secs: ConclaveResult<u64>,
) -> ConclaveResult<ValueBearingSignResponse> {
    if !enclave
        .signer_capability()
        .satisfies(&request.trust_requirement)
    {
        return Err(crate::ConclaveError::Unsupported(
            "value-bearing signing requires a provider-verified hardware enclave".to_string(),
        ));
    }

    // Acquire the trusted clock before invoking the provider. A clock failure
    // must not call provider code or consume replay state.
    let now_secs = trusted_now_secs?;
    let response = enclave.sign_value_bearing_provider(&request)?;
    let verified = ValueBearingSignResponse::from_provider_at_time(
        &request,
        response,
        enclave.signer_capability(),
        now_secs,
    )?;
    let replay_guard = enclave.value_bearing_replay_guard().ok_or_else(|| {
        crate::ConclaveError::Unsupported(
            "value-bearing replay protection is unavailable".to_string(),
        )
    })?;
    let replay_key = hex::encode(verified.operation_binding());
    replay_guard
        .try_check_and_record(&replay_key, now_secs)
        .map_err(map_replay_guard_error)?;

    let operation_binding = *verified.operation_binding();
    Ok(verified.with_replay_authorization(ValueBearingReplayAuthorization::new(operation_binding)))
}

/// A production-safe placeholder for a provider that has not been configured.
/// Every operation fails closed; it never fabricates keys, signatures, or
/// attestation evidence.
pub struct UnavailableEnclave;

impl EnclaveManager for UnavailableEnclave {
    fn initialize(&self) -> ConclaveResult<()> {
        Err(ConclaveError::Unsupported(
            "hardware-backed enclave provider is unavailable".to_string(),
        ))
    }

    fn generate_key(&self, _key_id: &str) -> ConclaveResult<String> {
        Err(ConclaveError::Unsupported(
            "hardware-backed key generation is unavailable".to_string(),
        ))
    }

    fn get_public_key(&self, _derivation_path: &str) -> ConclaveResult<String> {
        Err(ConclaveError::Unsupported(
            "hardware-backed public-key derivation is unavailable".to_string(),
        ))
    }

    fn sign(&self, _request: SignRequest) -> ConclaveResult<SignResponse> {
        Err(ConclaveError::Unsupported(
            "hardware-backed signing provider is unavailable".to_string(),
        ))
    }
}

/// Signs a value-bearing operation through the common fail-closed boundary.
///
/// Legacy `EnclaveManager::sign` remains available only for explicitly isolated
/// development/test drivers. This helper calls the typed provider-only method
/// and never bridges a typed request through raw signing.
pub(crate) fn sign_value_bearing(
    enclave: &dyn EnclaveManager,
    request: ValueBearingSignRequest,
) -> ConclaveResult<ValueBearingSignResponse> {
    enclave.sign_value_bearing(request)
}

fn value_bearing_attestation_policy(
    request: &ValueBearingSignRequest,
) -> ConclaveResult<AttestationPolicy> {
    if request.trust_requirement().policy_id() != VALUE_BEARING_POLICY_ID {
        return Err(ConclaveError::Unsupported(
            "value-bearing policy identity is unavailable".to_string(),
        ));
    }

    let policy = {
        #[cfg(test)]
        {
            AttestationPolicy::test_fixture()
        }

        #[cfg(not(test))]
        {
            AttestationPolicy::production()
        }
    };
    Ok(policy
        .with_required_purpose(crate::enclave::attestation::AttestationPurpose::Sign)
        .with_required_algorithm(request.algorithm.attestation_algorithm()))
}

fn verify_operation_signature(
    request: &ValueBearingSignRequest,
    response: &SignResponse,
) -> ConclaveResult<()> {
    let signature_bytes = hex::decode(&response.signature_hex)
        .map_err(|_| ConclaveError::CryptoError("invalid signature encoding".to_string()))?;
    let public_key_bytes = hex::decode(&response.public_key_hex)
        .map_err(|_| ConclaveError::CryptoError("invalid public-key encoding".to_string()))?;

    let valid = match request.algorithm {
        SigningAlgorithm::EcdsaSecp256k1 => {
            if signature_bytes.len() != 64 && signature_bytes.len() != 65 {
                false
            } else {
                let signature = secp256k1::ecdsa::Signature::from_compact(&signature_bytes[..64]);
                let public_key = secp256k1::PublicKey::from_slice(&public_key_bytes);
                let bound_public_key =
                    secp256k1::PublicKey::from_slice(request.key_binding.public_key());
                match (signature, public_key, bound_public_key) {
                    (Ok(signature), Ok(public_key), Ok(bound_public_key)) => {
                        if public_key != bound_public_key
                            || secp256k1::ecdsa::verify(
                                &signature,
                                secp256k1::Message::from_digest(*request.message_digest()),
                                &bound_public_key,
                            )
                            .is_err()
                        {
                            false
                        } else if signature_bytes.len() == 64 {
                            true
                        } else {
                            let recovery_id = parse_ecdsa_recovery_id(signature_bytes[64])?;
                            let recoverable =
                                match secp256k1::ecdsa::RecoverableSignature::from_compact(
                                    &signature_bytes[..64],
                                    recovery_id,
                                ) {
                                    Ok(recoverable) => recoverable,
                                    Err(_) => {
                                        return Err(ConclaveError::CryptoError(
                                            "invalid ECDSA recoverable signature".to_string(),
                                        ))
                                    }
                                };

                            match recoverable.recover_ecdsa(secp256k1::Message::from_digest(
                                *request.message_digest(),
                            )) {
                                Ok(recovered_key) => recovered_key == bound_public_key,
                                Err(_) => false,
                            }
                        }
                    }
                    _ => false,
                }
            }
        }
        SigningAlgorithm::SchnorrSecp256k1 => {
            let signature_array: [u8; 64] = match signature_bytes.try_into() {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Err(ConclaveError::CryptoError(
                        "invalid Schnorr signature".to_string(),
                    ))
                }
            };
            let public_key_array: [u8; 32] = match public_key_bytes.try_into() {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Err(ConclaveError::CryptoError(
                        "invalid Schnorr public key".to_string(),
                    ))
                }
            };
            let signature = secp256k1::schnorr::Signature::from_byte_array(signature_array);
            let public_key =
                secp256k1::XOnlyPublicKey::from_byte_array(public_key_array).map_err(|_| {
                    ConclaveError::CryptoError("invalid Schnorr public key".to_string())
                })?;
            secp256k1::schnorr::verify(&signature, request.message_digest(), &public_key).is_ok()
        }
        SigningAlgorithm::Ed25519 => {
            let public_key_array: [u8; 32] = match public_key_bytes.try_into() {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Err(ConclaveError::CryptoError(
                        "invalid Ed25519 public key".to_string(),
                    ))
                }
            };
            let public_key =
                ed25519_dalek::VerifyingKey::from_bytes(&public_key_array).map_err(|_| {
                    ConclaveError::CryptoError("invalid Ed25519 public key".to_string())
                })?;
            let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
                .map_err(|_| ConclaveError::CryptoError("invalid Ed25519 signature".to_string()))?;
            public_key
                .verify(request.message_digest(), &signature)
                .is_ok()
        }
    };

    if valid {
        Ok(())
    } else {
        Err(ConclaveError::CryptoError(
            "value-bearing signature does not verify against its request".to_string(),
        ))
    }
}

fn unix_time_secs_at(now: SystemTime) -> ConclaveResult<u64> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ConclaveError::ClockUnavailable)
}

/// Trusted process clock used by security-sensitive consumption paths. Tests
/// may exercise their private deterministic helpers, but production callers
/// cannot select the authorization-consumption timestamp.
pub(crate) fn trusted_unix_time_secs() -> ConclaveResult<u64> {
    unix_time_secs_at(SystemTime::now())
}

#[cfg(test)]
pub(crate) fn trusted_unix_time_secs_at(now: SystemTime) -> ConclaveResult<u64> {
    unix_time_secs_at(now)
}

#[cfg(test)]
fn test_unix_time_secs() -> u64 {
    trusted_unix_time_secs().expect("test host clock should be after the Unix epoch")
}

fn map_replay_guard_error(error: ReplayGuardError) -> ConclaveError {
    match error {
        ReplayGuardError::InvalidInput => ConclaveError::InvalidPayload,
        ReplayGuardError::ClockRollback => ConclaveError::ClockRollback,
        error => ConclaveError::Unsupported(format!(
            "value-bearing replay protection rejected operation: {error}"
        )),
    }
}

fn parse_ecdsa_recovery_id(value: u8) -> ConclaveResult<secp256k1::ecdsa::RecoveryId> {
    // Providers emit the compact 0..=3 form; retain the Ethereum-compatible
    // 27..=30 encoding already supported by protocol verification, and reject
    // every other recovery identifier.
    let normalized = match value {
        0..=3 => value,
        27..=30 => value - 27,
        _ => return Err(ConclaveError::InvalidPayload),
    };

    secp256k1::ecdsa::RecoveryId::try_from(i32::from(normalized))
        .map_err(|_| ConclaveError::InvalidPayload)
}

#[cfg(test)]
mod enclave_tests {
    use super::*;
    use crate::enclave::android_strongbox::CoreEnclaveManager;
    use crate::enclave::cloud::CloudEnclave;
    use ed25519_dalek::{Signer as _, SigningKey};
    use secp256k1::{ecdsa::RecoverableSignature, Message, SecretKey};
    use std::collections::{HashMap, VecDeque};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    use std::time::{Duration, SystemTime};

    struct DefaultMockEnclave {
        raw_sign_calls: AtomicUsize,
    }

    impl EnclaveManager for DefaultMockEnclave {
        fn initialize(&self) -> ConclaveResult<()> {
            Ok(())
        }

        fn generate_key(&self, key_id: &str) -> ConclaveResult<String> {
            Ok(key_id.to_string())
        }

        fn get_public_key(&self, _derivation_path: &str) -> ConclaveResult<String> {
            Ok("02".repeat(33))
        }

        fn sign(&self, _request: SignRequest) -> ConclaveResult<SignResponse> {
            self.raw_sign_calls.fetch_add(1, Ordering::Relaxed);
            Err(crate::ConclaveError::EnclaveFailure(
                "legacy sign path was invoked".to_string(),
            ))
        }
    }

    struct FixtureProvider {
        operation_key: SigningKey,
        replay_guard: ReplayGuard,
        queued_responses: Mutex<VecDeque<SignResponse>>,
        provider_calls: AtomicUsize,
    }

    impl FixtureProvider {
        fn new(max_entries: usize) -> Self {
            Self {
                operation_key: SigningKey::from_bytes(&[7u8; 32]),
                replay_guard: ReplayGuard::new(300, max_entries),
                queued_responses: Mutex::new(VecDeque::new()),
                provider_calls: AtomicUsize::new(0),
            }
        }

        fn queue_response(&self, response: SignResponse) {
            self.queued_responses.lock().unwrap().push_back(response);
        }

        fn response_for(&self, request: &ValueBearingSignRequest) -> SignResponse {
            let attestation_key = attestation::test_signing_key();
            let operation_public_key = self.operation_key.verifying_key().to_bytes();
            let extension_data =
                "PURPOSE_SIGN|ALGORITHM_ED25519|TEE_ENABLED|HARDWARE_ROOT_OF_TRUST|OS_VERSION_14"
                    .to_string();
            let extensions = attestation::parse_extension_data(&extension_data)
                .expect("fixture extensions should parse");
            let mut report = DeviceIntegrityReport {
                report_version: attestation::ATTESTATION_ENVELOPE_VERSION,
                report_type: attestation::AttestationReportType::DeviceIntegrity,
                level: AttestationLevel::TEE,
                challenge_nonce: request.message_digest().to_vec(),
                signature: Vec::new(),
                attested_operation_public_key: operation_public_key.to_vec(),
                signer_key_binding: Some(
                    SignerKeyBindingEvidence::new(
                        request.key_binding().key_id(),
                        request.key_binding().derivation_path(),
                        request.key_binding().public_key(),
                        &operation_public_key,
                        request.message_digest(),
                        request.operation_context().purpose().canonical_token(),
                        AttestationPurpose::Sign,
                        request.algorithm().attestation_algorithm(),
                    )
                    .expect("fixture key binding should be constructible"),
                ),
                certificate_chain: vec![
                    hex::encode(attestation_key.verifying_key().to_bytes()),
                    "CONCLAVE_ROOT_CA_V1".to_string(),
                ],
                timestamp: test_unix_time_secs(),
                extension_data,
                extensions,
            };
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

        fn response_with_report(
            &self,
            request: &ValueBearingSignRequest,
            mut report: DeviceIntegrityReport,
        ) -> SignResponse {
            report
                .sign_with_ed25519_key(&attestation::test_signing_key())
                .expect("fixture report should sign");
            SignResponse {
                signature_hex: hex::encode(
                    self.operation_key.sign(request.message_digest()).to_bytes(),
                ),
                public_key_hex: hex::encode(self.operation_key.verifying_key().to_bytes()),
                device_attestation: Some(
                    serde_json::to_string(&report).expect("fixture report should serialize"),
                ),
            }
        }
    }

    fn assert_binding_tamper_rejected(mutate: impl FnOnce(&mut SignerKeyBindingEvidence)) {
        let provider = FixtureProvider::new(16);
        let request = ed25519_value_request([0xA5; 32]);
        let valid_response = provider.response_for(&request);
        let mut report: DeviceIntegrityReport = serde_json::from_str(
            valid_response
                .device_attestation
                .as_deref()
                .expect("fixture attestation"),
        )
        .unwrap();
        mutate(report.signer_key_binding.as_mut().expect("fixture binding"));

        assert!(matches!(
            ValueBearingSignResponse::from_provider(
                &request,
                provider.response_with_report(&request, report),
                provider.signer_capability(),
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("not bound to the requested value-bearing operation")
        ));
    }

    impl EnclaveManager for FixtureProvider {
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
                "fixture provider raw sign must not be called".to_string(),
            ))
        }

        fn signer_capability(&self) -> SignerCapability {
            SignerCapability::provider_verified(VALUE_BEARING_POLICY_ID).unwrap()
        }

        fn value_bearing_replay_guard(&self) -> Option<&ReplayGuard> {
            Some(&self.replay_guard)
        }

        fn sign_value_bearing_provider(
            &self,
            request: &ValueBearingSignRequest,
        ) -> ConclaveResult<SignResponse> {
            self.provider_calls.fetch_add(1, Ordering::Relaxed);
            if let Some(response) = self.queued_responses.lock().unwrap().pop_front() {
                Ok(response)
            } else {
                Ok(self.response_for(request))
            }
        }
    }

    fn value_request() -> ValueBearingSignRequest {
        let operation_context = OperationContext::new(
            "conxian.test/value-bearing",
            ValueBearingPurpose::Transaction,
            b"operation-context".to_vec(),
        )
        .unwrap();
        let trust_requirement =
            TrustRequirement::hardware_backed("conxian.production.signing.v1").unwrap();
        let key_binding =
            SignerKeyBinding::new("test-key", "m/86'/0'/0'/0/0", vec![2u8; 33]).unwrap();

        ValueBearingSignRequest::new(
            operation_context,
            SigningAlgorithm::EcdsaSecp256k1,
            trust_requirement,
            [7u8; 32],
            key_binding,
            None,
        )
        .unwrap()
    }

    fn ed25519_value_request(digest: [u8; 32]) -> ValueBearingSignRequest {
        let operation_context = OperationContext::new(
            "conxian.test/ed25519",
            ValueBearingPurpose::Transaction,
            digest.to_vec(),
        )
        .unwrap();
        let trust_requirement = TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID).unwrap();
        let operation_key = SigningKey::from_bytes(&[7u8; 32]);
        let key_binding = SignerKeyBinding::new(
            "fixture-key",
            "m/44'/501'/0'/0/0",
            operation_key.verifying_key().to_bytes().to_vec(),
        )
        .unwrap();

        ValueBearingSignRequest::new(
            operation_context,
            SigningAlgorithm::Ed25519,
            trust_requirement,
            digest,
            key_binding,
            None,
        )
        .unwrap()
    }

    fn ecdsa_value_request(digest: [u8; 32], public_key: Vec<u8>) -> ValueBearingSignRequest {
        let operation_context = OperationContext::new(
            "conxian.test/ecdsa",
            ValueBearingPurpose::Transaction,
            digest.to_vec(),
        )
        .unwrap();
        let trust_requirement = TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID).unwrap();
        let key_binding =
            SignerKeyBinding::new("ecdsa-test-key", "m/44'/60'/0'/0/0", public_key).unwrap();

        ValueBearingSignRequest::new(
            operation_context,
            SigningAlgorithm::EcdsaSecp256k1,
            trust_requirement,
            digest,
            key_binding,
            None,
        )
        .unwrap()
    }

    fn unlock_request() -> ValueBearingUnlockRequest {
        let operation_context = OperationContext::new(
            "conxian.test/value-bearing",
            ValueBearingPurpose::Transaction,
            b"unlock-context".to_vec(),
        )
        .unwrap();
        let trust_requirement =
            TrustRequirement::hardware_backed("conxian.production.signing.v1").unwrap();
        ValueBearingUnlockRequest::new(operation_context, trust_requirement)
    }

    #[test]
    fn trusted_security_clock_rejects_pre_epoch_without_defaulting_to_zero() {
        let pre_epoch = SystemTime::UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .expect("pre-epoch fixture should be representable");

        assert_eq!(
            trusted_unix_time_secs_at(pre_epoch),
            Err(ConclaveError::ClockUnavailable)
        );
    }

    #[test]
    fn value_bearing_request_is_domain_separated_and_key_bound() {
        let request = value_request();
        let binding = request.operation_binding().unwrap();

        let changed_context = OperationContext::new(
            "different.domain",
            ValueBearingPurpose::Transaction,
            b"operation-context".to_vec(),
        )
        .unwrap();
        let changed_request = ValueBearingSignRequest::new(
            changed_context,
            request.algorithm(),
            request.trust_requirement().clone(),
            *request.message_digest(),
            request.key_binding().clone(),
            None,
        )
        .unwrap();

        assert_ne!(binding, changed_request.operation_binding().unwrap());
        assert_eq!(request.key_binding().public_key().len(), 33);
        assert_eq!(
            request.trust_requirement().policy_id(),
            "conxian.production.signing.v1"
        );
    }

    #[test]
    fn current_managers_are_software_unverified() {
        let core = CoreEnclaveManager::new();
        let cloud = CloudEnclave::new("https://kms.test".to_string()).unwrap();

        assert!(CoreEnclaveManager::is_software_only());
        assert!(CloudEnclave::is_software_only());

        for manager in [&core as &dyn EnclaveManager, &cloud as &dyn EnclaveManager] {
            let capability = manager.signer_capability();
            assert_eq!(capability.provenance(), SignerProvenance::Software);
            assert_eq!(capability.verification(), SignerVerification::Unverified);
            assert!(capability.policy_id().is_none());
        }
    }

    #[test]
    fn current_managers_reject_value_bearing_unlock_and_signing() {
        let core = CoreEnclaveManager::new();
        let cloud = CloudEnclave::new("https://kms.test".to_string()).unwrap();

        for manager in [&core as &dyn EnclaveManager, &cloud as &dyn EnclaveManager] {
            assert!(matches!(
                manager.unlock_value_bearing(unlock_request()),
                Err(crate::ConclaveError::Unsupported(message))
                    if message.contains("value-bearing")
            ));
            assert!(matches!(
                manager.sign_value_bearing(value_request()),
                Err(crate::ConclaveError::Unsupported(message))
                    if message.contains("value-bearing")
            ));
        }
    }

    #[test]
    fn default_manager_cannot_pass_value_bearing_boundary() {
        let manager = DefaultMockEnclave {
            raw_sign_calls: AtomicUsize::new(0),
        };
        let capability = manager.signer_capability();
        assert_eq!(capability.provenance(), SignerProvenance::Software);
        assert_eq!(capability.verification(), SignerVerification::Unverified);

        assert!(matches!(
            manager.unlock("development-secret", b"salt"),
            Err(crate::ConclaveError::Unsupported(message))
                if message.contains("unlock")
        ));
        assert!(matches!(
            manager.unlock_value_bearing(unlock_request()),
            Err(crate::ConclaveError::Unsupported(message))
                if message.contains("value-bearing")
        ));
        assert!(matches!(
            manager.sign_value_bearing(value_request()),
            Err(crate::ConclaveError::Unsupported(message))
                if message.contains("value-bearing")
        ));
        assert_eq!(manager.raw_sign_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn value_bearing_provider_response_requires_attestation() {
        let request = value_request();
        let capability =
            SignerCapability::provider_verified(request.trust_requirement().policy_id()).unwrap();
        let response = SignResponse {
            signature_hex: "01".to_string(),
            public_key_hex: hex::encode(request.key_binding().public_key()),
            device_attestation: None,
        };

        assert!(matches!(
            ValueBearingSignResponse::from_provider(&request, response, capability),
            Err(crate::ConclaveError::Unsupported(message))
                if message.contains("evidence")
        ));
    }

    #[test]
    fn malformed_provider_response_is_rejected_before_signature_use() {
        let request = value_request();
        let capability =
            SignerCapability::provider_verified(request.trust_requirement().policy_id()).unwrap();
        let response = SignResponse {
            signature_hex: "01".to_string(),
            public_key_hex: hex::encode(request.key_binding().public_key()),
            device_attestation: Some("{".to_string()),
        };

        assert!(matches!(
            ValueBearingSignResponse::from_provider(&request, response, capability),
            Err(ConclaveError::InvalidPayload)
        ));
    }

    #[test]
    fn ecdsa_recovery_id_for_bound_key_is_accepted() {
        let secret_key = SecretKey::from_secret_bytes([3u8; 32]).unwrap();
        let public_key = secret_key.public_key();
        let message_digest = [0x42u8; 32];
        let recoverable = RecoverableSignature::sign_ecdsa_recoverable(
            Message::from_digest(message_digest),
            &secret_key,
        );
        let (recovery_id, compact_signature) = recoverable.serialize_compact();
        let request = ecdsa_value_request(message_digest, public_key.serialize().to_vec());

        for encoded_recovery_id in [recovery_id.to_u8(), 27 + recovery_id.to_u8()] {
            let mut signature = compact_signature.to_vec();
            signature.push(encoded_recovery_id);
            let response = SignResponse {
                signature_hex: hex::encode(signature),
                public_key_hex: hex::encode(public_key.serialize()),
                device_attestation: None,
            };

            assert!(verify_operation_signature(&request, &response).is_ok());
        }
    }

    #[test]
    fn ecdsa_recovery_id_mismatch_with_bound_key_is_rejected() {
        let secret_key = SecretKey::from_secret_bytes([3u8; 32]).unwrap();
        let public_key = secret_key.public_key();
        let message_digest = [0x43u8; 32];
        let recoverable = RecoverableSignature::sign_ecdsa_recoverable(
            Message::from_digest(message_digest),
            &secret_key,
        );
        let (recovery_id, compact_signature) = recoverable.serialize_compact();
        let request = ecdsa_value_request(message_digest, public_key.serialize().to_vec());
        let mut signature = compact_signature.to_vec();
        signature.push((recovery_id.to_u8() + 1) % 4);
        let response = SignResponse {
            signature_hex: hex::encode(signature),
            public_key_hex: hex::encode(public_key.serialize()),
            device_attestation: None,
        };

        assert!(verify_operation_signature(&request, &response).is_err());
    }

    #[test]
    fn software_attestation_cannot_be_promoted_to_value_bearing() {
        let request = value_request();
        let capability =
            SignerCapability::provider_verified(request.trust_requirement().policy_id()).unwrap();
        let report = DeviceIntegrityReport {
            report_version: attestation::ATTESTATION_ENVELOPE_VERSION,
            report_type: attestation::AttestationReportType::DeviceIntegrity,
            level: AttestationLevel::Software,
            challenge_nonce: request.message_digest().to_vec(),
            signature: vec![1u8; 64],
            attested_operation_public_key: request.key_binding().public_key().to_vec(),
            signer_key_binding: None,
            certificate_chain: vec![hex::encode([0x11u8; 32]), "software-root".to_string()],
            timestamp: 1,
            extension_data: "PURPOSE_SIGN|ALGORITHM_ECDSA_SECP256K1".to_string(),
            extensions: vec![
                AttestationExtension::PurposeSign,
                AttestationExtension::AlgorithmEcdsaSecp256k1,
            ],
        };
        let response = SignResponse {
            signature_hex: "01".to_string(),
            public_key_hex: hex::encode(request.key_binding().public_key()),
            device_attestation: Some(serde_json::to_string(&report).unwrap()),
        };

        assert!(matches!(
            ValueBearingSignResponse::from_provider(&request, response, capability),
            Err(crate::ConclaveError::Unsupported(message))
                if message.contains("attestation")
        ));
    }

    #[test]
    fn software_capability_cannot_create_value_bearing_session() {
        assert!(matches!(
            ValueBearingSession::from_provider(
                &unlock_request(),
                SignerCapability::software_unverified(),
            ),
            Err(crate::ConclaveError::Unsupported(message))
                if message.contains("trust policy")
        ));
    }

    #[test]
    fn test_cloud_enclave_ed25519_signing_remains_non_production() {
        let enclave = CloudEnclave::new("https://kms.test".to_string()).unwrap();
        let message = b"hello world";
        let request = SignRequest {
            algorithm: SigningAlgorithm::Ed25519,
            message_hash: message.to_vec(),
            derivation_path: "m/44'/501'/0'/0'".to_string(),
            key_id: "test-key".to_string(),
            taproot_tweak: None,
        };

        let response = enclave.sign(request).unwrap();
        assert!(!response.signature_hex.is_empty());
        assert_eq!(response.public_key_hex.len(), 64); // 32 bytes hex
        let attestation = response.device_attestation.expect("test fixture evidence");
        let report: DeviceIntegrityReport = serde_json::from_str(&attestation).unwrap();
        assert_eq!(report.level, AttestationLevel::TEE);
        assert!(!report.verify_with_policy(message, &attestation::AttestationPolicy::production()));
    }

    #[test]
    fn production_value_signing_rejects_simulated_provider() {
        let enclave = CloudEnclave::new("https://kms.test".to_string()).unwrap();
        let request = SignRequest {
            algorithm: SigningAlgorithm::Ed25519,
            message_hash: b"production boundary".to_vec(),
            derivation_path: "m/44'/501'/0'/0'".to_string(),
            key_id: "test-key".to_string(),
            taproot_tweak: None,
        };
        let response = enclave.sign(request.clone()).unwrap();

        let attestation = response
            .device_attestation
            .expect("simulated fixture evidence");
        let report: DeviceIntegrityReport = serde_json::from_str(&attestation).unwrap();
        assert!(!report.verify_with_policy(&request.message_hash, &AttestationPolicy::production()));
    }

    #[test]
    fn typed_provider_response_requires_attestation_leaf_operation_key_binding() {
        let provider = FixtureProvider::new(16);
        let request = ed25519_value_request([0xA5; 32]);
        let response = provider.response_for(&request);
        let capability = provider.signer_capability();
        let verified = ValueBearingSignResponse::from_provider(&request, response, capability)
            .expect("matching typed fixture should verify");

        assert_eq!(
            verified.sign_response().public_key_hex,
            hex::encode(request.key_binding().public_key())
        );
    }

    #[test]
    fn valid_report_and_signature_from_different_operation_key_are_rejected() {
        let provider = FixtureProvider::new(16);
        let request = ed25519_value_request([0xA5; 32]);
        let other_key = SigningKey::from_bytes(&[8u8; 32]);
        let other_binding = SignerKeyBinding::new(
            "different-key",
            "m/44'/501'/0'/0/0",
            other_key.verifying_key().to_bytes().to_vec(),
        )
        .unwrap();
        let different_request = ValueBearingSignRequest::new(
            OperationContext::new(
                "conxian.test/ed25519",
                ValueBearingPurpose::Transaction,
                [0xA5; 32].to_vec(),
            )
            .unwrap(),
            SigningAlgorithm::Ed25519,
            TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID).unwrap(),
            [0xA5; 32],
            other_binding,
            None,
        )
        .unwrap();

        assert!(matches!(
            ValueBearingSignResponse::from_provider(
                &different_request,
                provider.response_for(&request),
                provider.signer_capability(),
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("requested signing key")
        ));
    }

    #[test]
    fn attestation_leaf_operation_key_mismatch_is_rejected_after_report_verification() {
        let provider = FixtureProvider::new(16);
        let request = ed25519_value_request([0xA5; 32]);
        let valid_response = provider.response_for(&request);
        let mut report: DeviceIntegrityReport = serde_json::from_str(
            valid_response
                .device_attestation
                .as_deref()
                .expect("fixture attestation"),
        )
        .unwrap();
        report.attested_operation_public_key = SigningKey::from_bytes(&[8u8; 32])
            .verifying_key()
            .to_bytes()
            .to_vec();

        assert!(matches!(
            ValueBearingSignResponse::from_provider(
                &request,
                provider.response_with_report(&request, report),
                provider.signer_capability(),
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("attestation leaf")
        ));
    }

    #[test]
    fn signed_binding_rejects_key_id_tampering() {
        assert_binding_tamper_rejected(|binding| binding.requested_key_id_hash[0] ^= 0x01);
    }

    #[test]
    fn signed_binding_rejects_derivation_path_tampering() {
        assert_binding_tamper_rejected(|binding| binding.requested_derivation_path_hash[0] ^= 0x01);
    }

    #[test]
    fn signed_binding_rejects_expected_public_key_tampering() {
        assert_binding_tamper_rejected(|binding| binding.expected_public_key_hash[0] ^= 0x01);
    }

    #[test]
    fn signed_binding_rejects_returned_public_key_tampering() {
        assert_binding_tamper_rejected(|binding| binding.returned_public_key_hash[0] ^= 0x01);
    }

    #[test]
    fn signed_binding_rejects_operation_digest_tampering() {
        assert_binding_tamper_rejected(|binding| binding.operation_digest_hash[0] ^= 0x01);
    }

    #[test]
    fn signed_binding_rejects_operation_purpose_tampering() {
        assert_binding_tamper_rejected(|binding| binding.operation_purpose_hash[0] ^= 0x01);
    }

    #[test]
    fn signed_binding_rejects_purpose_tampering() {
        assert_binding_tamper_rejected(|binding| binding.purpose_hash[0] ^= 0x01);
    }

    #[test]
    fn signed_binding_rejects_algorithm_tampering() {
        assert_binding_tamper_rejected(|binding| binding.algorithm_hash[0] ^= 0x01);
    }

    #[test]
    fn changing_requested_operation_purpose_is_rejected() {
        let provider = FixtureProvider::new(16);
        let request = ed25519_value_request([0xA5; 32]);
        let changed_context = OperationContext::new(
            "conxian.test/ed25519",
            ValueBearingPurpose::Settlement,
            [0xA5; 32].to_vec(),
        )
        .unwrap();
        let changed_request = ValueBearingSignRequest::new(
            changed_context,
            request.algorithm(),
            request.trust_requirement().clone(),
            *request.message_digest(),
            request.key_binding().clone(),
            None,
        )
        .unwrap();

        assert!(matches!(
            ValueBearingSignResponse::from_provider(
                &changed_request,
                provider.response_for(&request),
                provider.signer_capability(),
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("not bound to the requested value-bearing operation")
        ));
    }

    #[test]
    fn complete_attestation_policy_rejects_wrong_root_purpose_algorithm_nonce_and_stale_report() {
        let provider = FixtureProvider::new(16);
        let request = ed25519_value_request([0xA5; 32]);
        let valid_response = provider.response_for(&request);
        let valid_report: DeviceIntegrityReport = serde_json::from_str(
            valid_response
                .device_attestation
                .as_deref()
                .expect("fixture attestation"),
        )
        .unwrap();

        let mut wrong_root = valid_report.clone();
        wrong_root.certificate_chain[1] = "UNTRUSTED_ROOT".to_string();
        assert!(ValueBearingSignResponse::from_provider(
            &request,
            provider.response_with_report(&request, wrong_root),
            provider.signer_capability(),
        )
        .is_err());

        let mut wrong_purpose = valid_report.clone();
        wrong_purpose.extension_data =
            "PURPOSE_VERIFY|ALGORITHM_ED25519|TEE_ENABLED|HARDWARE_ROOT_OF_TRUST|OS_VERSION_14"
                .to_string();
        wrong_purpose.extensions =
            attestation::parse_extension_data(&wrong_purpose.extension_data).unwrap();
        assert!(ValueBearingSignResponse::from_provider(
            &request,
            provider.response_with_report(&request, wrong_purpose),
            provider.signer_capability(),
        )
        .is_err());

        let mut wrong_algorithm = valid_report.clone();
        wrong_algorithm.extension_data =
            "PURPOSE_SIGN|ALGORITHM_ECDSA_SECP256K1|TEE_ENABLED|HARDWARE_ROOT_OF_TRUST|OS_VERSION_14"
                .to_string();
        wrong_algorithm.extensions =
            attestation::parse_extension_data(&wrong_algorithm.extension_data).unwrap();
        assert!(ValueBearingSignResponse::from_provider(
            &request,
            provider.response_with_report(&request, wrong_algorithm),
            provider.signer_capability(),
        )
        .is_err());

        let mut wrong_nonce = valid_report.clone();
        wrong_nonce.challenge_nonce = vec![0xFF; 32];
        assert!(ValueBearingSignResponse::from_provider(
            &request,
            provider.response_with_report(&request, wrong_nonce),
            provider.signer_capability(),
        )
        .is_err());

        let mut stale = valid_report;
        stale.timestamp = test_unix_time_secs()
            .saturating_sub(attestation::MAX_ATTESTATION_AGE_SECS.saturating_add(1));
        assert!(ValueBearingSignResponse::from_provider(
            &request,
            provider.response_with_report(&request, stale),
            provider.signer_capability(),
        )
        .is_err());

        let production_report: DeviceIntegrityReport = serde_json::from_str(
            provider
                .response_for(&request)
                .device_attestation
                .as_deref()
                .expect("fixture attestation"),
        )
        .unwrap();
        assert!(!production_report
            .verify_with_policy(request.message_digest(), &AttestationPolicy::production(),));
    }

    #[test]
    fn value_bearing_clock_failure_precedes_provider_and_replay_recording() {
        let provider = FixtureProvider::new(16);
        let request = ed25519_value_request([0xA5; 32]);
        let pre_epoch = SystemTime::UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .expect("pre-epoch fixture should be representable");

        assert!(matches!(
            sign_value_bearing_with_trusted_clock(
                &provider,
                request.clone(),
                trusted_unix_time_secs_at(pre_epoch),
            ),
            Err(ConclaveError::ClockUnavailable)
        ));
        assert_eq!(provider.provider_calls.load(Ordering::Relaxed), 0);

        // The failed clock acquisition did not consume the operation replay
        // key; the first valid attempt can still succeed.
        assert!(provider.sign_value_bearing(request.clone()).is_ok());
        assert!(matches!(
            provider.sign_value_bearing(request),
            Err(ConclaveError::Unsupported(message))
                if message.contains("replay protection") && message.contains("already")
        ));
    }

    #[test]
    fn invalid_provider_evidence_does_not_consume_replay_state_and_valid_replay_is_rejected() {
        let provider = FixtureProvider::new(16);
        let request = ed25519_value_request([0xA5; 32]);
        let mut invalid = provider.response_for(&request);
        invalid.device_attestation = None;
        provider.queue_response(invalid);

        assert!(provider.sign_value_bearing(request.clone()).is_err());
        assert!(provider.sign_value_bearing(request.clone()).is_ok());
        assert!(matches!(
            provider.sign_value_bearing(request),
            Err(ConclaveError::Unsupported(message))
                if message.contains("replay protection") && message.contains("already")
        ));
    }

    #[test]
    fn invalid_key_binding_does_not_consume_replay_state() {
        let provider = FixtureProvider::new(16);
        let request = ed25519_value_request([0xA5; 32]);
        let valid_response = provider.response_for(&request);
        let mut report: DeviceIntegrityReport = serde_json::from_str(
            valid_response
                .device_attestation
                .as_deref()
                .expect("fixture attestation"),
        )
        .unwrap();
        report
            .signer_key_binding
            .as_mut()
            .expect("fixture binding")
            .requested_key_id_hash[0] ^= 0x01;
        provider.queue_response(provider.response_with_report(&request, report));

        assert!(provider.sign_value_bearing(request.clone()).is_err());
        assert!(provider.sign_value_bearing(request.clone()).is_ok());
        assert!(matches!(
            provider.sign_value_bearing(request),
            Err(ConclaveError::Unsupported(message))
                if message.contains("replay protection") && message.contains("already")
        ));
    }

    #[test]
    fn value_bearing_replay_saturation_fails_closed_without_live_eviction() {
        let provider = FixtureProvider::new(1);
        let first = ed25519_value_request([1u8; 32]);
        let second = ed25519_value_request([2u8; 32]);

        assert!(provider.sign_value_bearing(first.clone()).is_ok());
        assert!(matches!(
            provider.sign_value_bearing(second),
            Err(ConclaveError::Unsupported(message))
                if message.contains("replay protection") && message.contains("saturated")
        ));
        assert!(matches!(
            provider.sign_value_bearing(first),
            Err(ConclaveError::Unsupported(message))
                if message.contains("replay protection") && message.contains("already")
        ));
    }

    #[test]
    fn migrated_primary_signers_never_call_legacy_raw_sign_when_typed_signing_rejects() {
        let manager = std::sync::Arc::new(DefaultMockEnclave {
            raw_sign_calls: AtomicUsize::new(0),
        });
        let ethereum = crate::protocol::ethereum::EthereumManager::new(manager.as_ref());
        let ark = crate::protocol::ark::ArkManager::new(manager.clone());
        let bitvm = crate::protocol::bitvm::BitVmManager::new(manager.clone());
        let business_registry = crate::protocol::business::BusinessRegistry::new();
        business_registry.register_business(crate::protocol::business::BusinessProfile {
            id: "test-business".to_string(),
            name: "Test Business".to_string(),
            public_key: String::new(),
            active: true,
        });
        let business =
            crate::protocol::business::BusinessManager::new(manager.as_ref(), &business_registry);
        let chain_abstraction = crate::protocol::chain_abstraction::ChainAbstractionService::new(
            manager.clone(),
            std::sync::Arc::new(crate::protocol::asset::AssetRegistry::new()),
        );
        let yield_engine = crate::protocol::economy::YieldEngine::new(manager.as_ref());

        assert!(ethereum
            .sign_transaction_hash([0x11; 32], "m/44'/60'/0'/0/0", "legacy-mock")
            .is_err());
        assert!(ark
            .sign_forfeit_transaction([0x11; 32], "m/44'/0'/0'/0/0")
            .is_err());
        assert!(bitvm
            .sign_challenge(
                crate::protocol::bitvm::BitVmChallenge {
                    challenge_hash: [0x11; 32],
                    tap_index: 0,
                    total_taps: 364,
                },
                "m/86'/0'/0'/0/0",
                "legacy-mock",
            )
            .is_err());
        assert!(business
            .generate_attribution("test-business", "user", HashMap::new())
            .is_err());
        assert!(chain_abstraction
            .sign_for_chain(crate::protocol::chain_abstraction::ChainSignatureRequest {
                target_chain: crate::protocol::asset::Chain::BITCOIN,
                payload: vec![0x11; 32],
                derivation_path: "m/44'/0'/0'/0/0".to_string(),
            })
            .is_err());
        assert!(yield_engine
            .prepare_gas_sponsored_tx(crate::protocol::economy::GasFeeIntent {
                tx_payload: vec![0x11; 32],
                estimated_fee_sbtc: 1,
            })
            .is_err());
        assert_eq!(manager.raw_sign_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn software_manager_cannot_satisfy_migrated_primary_signers() {
        let cloud = std::sync::Arc::new(CloudEnclave::new("https://kms.test".to_string()).unwrap());
        let bitcoin = crate::protocol::bitcoin::BitcoinManager::new(cloud.clone());
        let ethereum = crate::protocol::ethereum::EthereumManager::new(cloud.as_ref());
        let solana = crate::protocol::solana::SolanaManager::new(cloud.as_ref());
        let stacks = crate::protocol::stacks::StacksManager::new(cloud.as_ref());

        assert!(bitcoin
            .taproot()
            .sign_taproot_sighash([0x22; 32], "m/86'/0'/0'/0/0", "btc-key")
            .is_err());
        assert!(ethereum
            .sign_transaction_hash([0x22; 32], "m/44'/60'/0'/0/0", "eth-key")
            .is_err());
        assert!(solana
            .sign_transaction_hash([0x22; 32], "m/44'/501'/0'/0/0", "sol-key")
            .is_err());
        assert!(stacks
            .sign_prepared_transaction(
                crate::protocol::stacks::StacksTransactionIntent {
                    payload: vec![1],
                    message_hash: vec![0x22; 32],
                },
                "stx-key",
            )
            .is_err());

        let ark = crate::protocol::ark::ArkManager::new(cloud.clone());
        let bitvm = crate::protocol::bitvm::BitVmManager::new(cloud.clone());
        let business_registry = crate::protocol::business::BusinessRegistry::new();
        business_registry.register_business(crate::protocol::business::BusinessProfile {
            id: "software-business".to_string(),
            name: "Software Business".to_string(),
            public_key: String::new(),
            active: true,
        });
        let business =
            crate::protocol::business::BusinessManager::new(cloud.as_ref(), &business_registry);
        let chain_abstraction = crate::protocol::chain_abstraction::ChainAbstractionService::new(
            cloud.clone(),
            std::sync::Arc::new(crate::protocol::asset::AssetRegistry::new()),
        );
        let yield_engine = crate::protocol::economy::YieldEngine::new(cloud.as_ref());

        assert!(ark
            .sign_forfeit_transaction([0x22; 32], "m/44'/0'/0'/0/0")
            .is_err());
        assert!(bitvm
            .sign_challenge(
                crate::protocol::bitvm::BitVmChallenge {
                    challenge_hash: [0x22; 32],
                    tap_index: 0,
                    total_taps: 364,
                },
                "m/86'/0'/0'/0/0",
                "software-key",
            )
            .is_err());
        assert!(business
            .generate_attribution("software-business", "user", HashMap::new())
            .is_err());
        assert!(chain_abstraction
            .sign_for_chain(crate::protocol::chain_abstraction::ChainSignatureRequest {
                target_chain: crate::protocol::asset::Chain::BITCOIN,
                payload: vec![0x22; 32],
                derivation_path: "m/44'/0'/0'/0/0".to_string(),
            })
            .is_err());
        assert!(yield_engine
            .prepare_gas_sponsored_tx(crate::protocol::economy::GasFeeIntent {
                tx_payload: vec![0x22; 32],
                estimated_fee_sbtc: 1,
            })
            .is_err());
    }
}
