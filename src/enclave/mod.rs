#[cfg(any(test, feature = "development-simulators"))]
pub mod android_strongbox;
pub mod attestation;
#[cfg(any(test, feature = "development-simulators"))]
pub mod cloud;
pub mod replay_guard;

#[cfg(test)]
mod hardware_attestation_tests;

use crate::enclave::attestation::{
    AttestationAlgorithm, AttestationExtension, AttestationLevel, AttestationPolicy,
    DeviceIntegrityReport,
};
use crate::{ConclaveError, ConclaveResult};
use ed25519_dalek::Verifier as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separator for all value-bearing signing request bindings.
pub const VALUE_BEARING_SIGNING_DOMAIN: &str = "CONXIAN-VALUE-BEARING-SIGNING/v1";

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

/// Typed result that can only be issued by a provider-verified signing path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueBearingSignResponse {
    response: SignResponse,
    capability: SignerCapability,
    operation_binding: [u8; 32],
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

    #[allow(dead_code)]
    pub(crate) fn from_provider(
        request: &ValueBearingSignRequest,
        response: SignResponse,
        capability: SignerCapability,
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
        let algorithm_evidence = report
            .extensions
            .iter()
            .filter_map(AttestationExtension::algorithm)
            .collect::<Vec<_>>();
        if report.level == AttestationLevel::Software
            || report.challenge_nonce != request.message_digest
            || report.signature.is_empty()
            || report.certificate_chain.len() < 2
            || !report
                .extensions
                .contains(&AttestationExtension::PurposeSign)
            || algorithm_evidence.len() != 1
            || algorithm_evidence[0] != request.algorithm.attestation_algorithm()
        {
            return Err(crate::ConclaveError::Unsupported(
                "provider response is missing required value-bearing evidence".to_string(),
            ));
        }

        let legacy_request = SignRequest {
            algorithm: request.algorithm,
            message_hash: request.message_digest.to_vec(),
            derivation_path: request.key_binding.derivation_path.clone(),
            key_id: request.key_binding.key_id.clone(),
            taproot_tweak: request.taproot_tweak.clone(),
        };
        verify_operation_signature(&legacy_request, &response)?;

        Ok(Self {
            response,
            capability,
            operation_binding: request.operation_binding()?,
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
        if !self
            .signer_capability()
            .satisfies(&request.trust_requirement)
        {
            return Err(crate::ConclaveError::Unsupported(
                "value-bearing signing requires a provider-verified hardware enclave".to_string(),
            ));
        }

        Err(crate::ConclaveError::Unsupported(
            "value-bearing signing provider contract is unavailable".to_string(),
        ))
    }
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
/// Raw `EnclaveManager::sign` remains available for explicitly isolated
/// development/test drivers, but every protocol wrapper that can produce a
/// transaction or settlement signature must use this helper. Production uses
/// the unavailable provider policy until a real provider verifier is wired in.
pub(crate) fn sign_value_bearing(
    enclave: &dyn EnclaveManager,
    request: SignRequest,
) -> ConclaveResult<SignResponse> {
    let response = enclave.sign(request.clone())?;
    let required_algorithm = match request.algorithm {
        SigningAlgorithm::EcdsaSecp256k1 => AttestationAlgorithm::EcdsaSecp256k1,
        SigningAlgorithm::SchnorrSecp256k1 => AttestationAlgorithm::SchnorrSecp256k1,
        SigningAlgorithm::Ed25519 => AttestationAlgorithm::Ed25519,
    };
    let policy = value_bearing_policy().with_required_algorithm(required_algorithm);
    validate_value_bearing_response(&request, &response, &policy)?;
    Ok(response)
}

fn value_bearing_policy() -> AttestationPolicy {
    #[cfg(test)]
    {
        AttestationPolicy::test_fixture()
    }

    #[cfg(not(test))]
    {
        AttestationPolicy::production()
    }
}

pub(crate) fn validate_value_bearing_response(
    request: &SignRequest,
    response: &SignResponse,
    policy: &AttestationPolicy,
) -> ConclaveResult<()> {
    if response.signature_hex.is_empty() || response.public_key_hex.is_empty() {
        return Err(ConclaveError::EnclaveFailure(
            "value-bearing signer returned an incomplete signature".to_string(),
        ));
    }

    let attestation_json = response.device_attestation.as_ref().ok_or_else(|| {
        ConclaveError::EnclaveFailure(
            "value-bearing signing requires device attestation".to_string(),
        )
    })?;
    let report: DeviceIntegrityReport = serde_json::from_str(attestation_json).map_err(|e| {
        ConclaveError::EnclaveFailure(format!("invalid value-bearing attestation: {e}"))
    })?;

    if report.challenge_nonce != request.message_hash {
        return Err(ConclaveError::EnclaveFailure(
            "value-bearing attestation is not bound to the signing request".to_string(),
        ));
    }

    if !report.verify_with_policy(&request.message_hash, policy) {
        return Err(ConclaveError::Unsupported(
            "value-bearing signing requires a verified hardware provider".to_string(),
        ));
    }

    let expected_algorithm_extension = match request.algorithm {
        SigningAlgorithm::EcdsaSecp256k1 => AttestationExtension::AlgorithmEcdsaSecp256k1,
        SigningAlgorithm::SchnorrSecp256k1 => AttestationExtension::AlgorithmSchnorrSecp256k1,
        SigningAlgorithm::Ed25519 => AttestationExtension::AlgorithmEd25519,
    };
    if !report.extensions.contains(&expected_algorithm_extension) {
        return Err(ConclaveError::EnclaveFailure(
            "attestation algorithm does not match the signing request".to_string(),
        ));
    }

    verify_operation_signature(request, response)
}

fn verify_operation_signature(
    request: &SignRequest,
    response: &SignResponse,
) -> ConclaveResult<()> {
    let signature_bytes = hex::decode(&response.signature_hex)
        .map_err(|_| ConclaveError::CryptoError("invalid signature encoding".to_string()))?;
    let public_key_bytes = hex::decode(&response.public_key_hex)
        .map_err(|_| ConclaveError::CryptoError("invalid public-key encoding".to_string()))?;

    let valid = match request.algorithm {
        SigningAlgorithm::EcdsaSecp256k1 => {
            if !(signature_bytes.len() == 64 || signature_bytes.len() == 65)
                || (signature_bytes.len() == 65 && signature_bytes[64] > 3)
            {
                false
            } else {
                let signature = secp256k1::ecdsa::Signature::from_compact(&signature_bytes[..64]);
                let public_key = secp256k1::PublicKey::from_slice(&public_key_bytes);
                match (signature, public_key) {
                    (Ok(signature), Ok(public_key)) => secp256k1::ecdsa::verify(
                        &signature,
                        secp256k1::Message::from_digest(
                            request
                                .message_hash
                                .as_slice()
                                .try_into()
                                .map_err(|_| ConclaveError::InvalidPayload)?,
                        ),
                        &public_key,
                    )
                    .is_ok(),
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
            let message: [u8; 32] = request
                .message_hash
                .as_slice()
                .try_into()
                .map_err(|_| ConclaveError::InvalidPayload)?;
            secp256k1::schnorr::verify(&signature, &message, &public_key).is_ok()
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
            public_key.verify(&request.message_hash, &signature).is_ok()
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

#[cfg(test)]
mod enclave_tests {
    use super::*;
    use crate::enclave::android_strongbox::CoreEnclaveManager;
    use crate::enclave::cloud::CloudEnclave;

    struct DefaultMockEnclave;

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
            Err(crate::ConclaveError::EnclaveFailure(
                "legacy sign path was invoked".to_string(),
            ))
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
        let manager = DefaultMockEnclave;
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
                if message.contains("evidence")
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

        let result =
            validate_value_bearing_response(&request, &response, &AttestationPolicy::production());
        assert!(matches!(
            result,
            Err(ConclaveError::Unsupported(message))
                if message.contains("verified hardware provider")
        ));
    }

    #[test]
    fn test_fixture_value_signing_requires_matching_typed_algorithm() {
        let enclave = CloudEnclave::new("https://kms.test".to_string()).unwrap();

        for algorithm in [SigningAlgorithm::EcdsaSecp256k1, SigningAlgorithm::Ed25519] {
            let request = SignRequest {
                algorithm,
                message_hash: vec![0xA5; 32],
                derivation_path: "m/44'/501'/0'/0'".to_string(),
                key_id: "test-key".to_string(),
                taproot_tweak: None,
            };

            let response = enclave.sign(request.clone()).unwrap();
            sign_value_bearing(&enclave, request).expect("typed fixture must verify");
            assert!(!response.signature_hex.is_empty());
        }

        let schnorr_request = SignRequest {
            algorithm: SigningAlgorithm::SchnorrSecp256k1,
            message_hash: vec![0xA5; 32],
            derivation_path: "m/44'/501'/0'/0'".to_string(),
            key_id: "test-key".to_string(),
            taproot_tweak: None,
        };
        assert!(matches!(
            enclave.sign(schnorr_request),
            Err(ConclaveError::Unsupported(message)) if message.contains("Schnorr")
        ));
    }
}
