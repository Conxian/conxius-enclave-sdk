//! Typed proof evidence and fail-closed proof-set composition.
//!
//! This module deliberately separates the subject of a proof from the
//! mechanism that produced it. Raw evidence is accepted as unverified input;
//! only an exact mechanism verifier can create one of the private-field
//! verified proof types. The production registry currently has no provider
//! implementations, so production verification rejects explicitly.

use super::ValueBearingPurpose;
#[cfg(test)]
use super::ValueBearingSignRequest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Versioned domain separator for canonical proof contexts.
pub const PROOF_CONTEXT_VERSION: u16 = 1;
pub const PROOF_CONTEXT_DOMAIN: &str = "CONXIAN-PROOF-CONTEXT/v1";
pub const PROOF_REQUIREMENT_VERSION: u16 = 1;
pub const PROOF_REQUIREMENT_DOMAIN: &str = "CONXIAN-PROOF-REQUIREMENT/v1";
pub const PROOF_POLICY_VERSION: u16 = 1;
pub const PROOF_POLICY_DOMAIN: &str = "CONXIAN-PROOF-POLICY/v1";
pub const PROOF_SET_DOMAIN: &str = "CONXIAN-PROOF-SET/v1";

/// Bounds applied before unverified evidence is retained in memory.
pub const MAX_PROOF_COUNT: usize = 16;
pub const MAX_EVIDENCE_BYTES: usize = 4096;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_NONCE_BYTES: usize = 128;
pub const MAX_SUBJECT_BINDING_BYTES: usize = 256;
pub const MAX_REPLAY_IDENTITY_BYTES: usize = 256;
pub const MAX_FRESHNESS_SECS: u64 = 86_400;

/// The independently authenticated subject of a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProofSubject {
    Server,
    User,
    PhoneDevice,
}

impl ProofSubject {
    fn canonical_tag(self) -> u8 {
        match self {
            Self::Server => 1,
            Self::User => 2,
            Self::PhoneDevice => 3,
        }
    }
}

/// The exact mechanism/category represented by a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProofType {
    ServerIdentity,
    UserAuthorization,
    PhoneDeviceAttestation,
    TeeAttestation,
    Fido2WebAuthnAssertion,
    TpmQuote,
}

impl ProofType {
    fn canonical_tag(self) -> u8 {
        match self {
            Self::ServerIdentity => 1,
            Self::UserAuthorization => 2,
            Self::PhoneDeviceAttestation => 3,
            Self::TeeAttestation => 4,
            Self::Fido2WebAuthnAssertion => 5,
            Self::TpmQuote => 6,
        }
    }

    #[cfg(test)]
    fn canonical_token(self) -> &'static str {
        match self {
            Self::ServerIdentity => "server-identity",
            Self::UserAuthorization => "user-authorization",
            Self::PhoneDeviceAttestation => "phone-device-attestation",
            Self::TeeAttestation => "tee-attestation",
            Self::Fido2WebAuthnAssertion => "fido2-webauthn-assertion",
            Self::TpmQuote => "tpm-quote",
        }
    }

    /// Returns whether the mechanism is valid for the stated subject.
    pub fn is_subject_allowed(self, subject: ProofSubject) -> bool {
        match self {
            Self::ServerIdentity => subject == ProofSubject::Server,
            Self::UserAuthorization | Self::Fido2WebAuthnAssertion => subject == ProofSubject::User,
            Self::PhoneDeviceAttestation => subject == ProofSubject::PhoneDevice,
            Self::TeeAttestation | Self::TpmQuote => {
                matches!(subject, ProofSubject::Server | ProofSubject::PhoneDevice)
            }
        }
    }
}

/// Exact proof mechanism/subject identity used for dispatch and policy lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProofKey {
    proof_type: ProofType,
    subject: ProofSubject,
}

impl ProofKey {
    pub const fn new(proof_type: ProofType, subject: ProofSubject) -> Self {
        Self {
            proof_type,
            subject,
        }
    }

    pub fn proof_type(self) -> ProofType {
        self.proof_type
    }

    pub fn subject(self) -> ProofSubject {
        self.subject
    }

    pub fn is_subject_mechanism_pair_valid(self) -> bool {
        self.proof_type.is_subject_allowed(self.subject)
    }
}

/// Input validation failures that occur before a verifier is selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProofInputError {
    #[error("proof field exceeds its configured bound")]
    ValueTooLarge,
    #[error("proof field contains a control character")]
    ControlCharacter,
    #[error("proof field must not be empty")]
    EmptyValue,
    #[error("proof policy requires at least one exact proof requirement")]
    EmptyRequirementSet,
    #[error("proof policy contains too many requirements")]
    RequirementCountExceeded,
    #[error("proof policy contains a mechanism/subject mismatch")]
    InvalidSubjectMechanismPair,
    #[error("proof policy contains duplicate exact requirements")]
    DuplicateRequirement,
    #[error("proof policy freshness bounds are invalid")]
    InvalidFreshnessBounds,
}

fn validate_text(value: &str) -> Result<(), ProofInputError> {
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(ProofInputError::ValueTooLarge);
    }
    if value.chars().any(char::is_control) {
        return Err(ProofInputError::ControlCharacter);
    }
    Ok(())
}

fn validate_required_text(value: &str) -> Result<(), ProofInputError> {
    validate_text(value)?;
    if value.is_empty() {
        return Err(ProofInputError::EmptyValue);
    }
    Ok(())
}

fn validate_bytes(value: &[u8], max: usize) -> Result<(), ProofInputError> {
    if value.len() > max {
        return Err(ProofInputError::ValueTooLarge);
    }
    Ok(())
}

fn validate_required_bytes(value: &[u8], max: usize) -> Result<(), ProofInputError> {
    validate_bytes(value, max)?;
    if value.is_empty() {
        return Err(ProofInputError::EmptyValue);
    }
    Ok(())
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ProofInputError> {
    let length = u32::try_from(value.len()).map_err(|_| ProofInputError::ValueTooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

/// Canonical context bound into every verified proof.
///
/// It contains no raw evidence. Diagnostics and downstream authorization can
/// safely retain this context and its digest without exposing provider blobs.
#[derive(Clone, PartialEq, Eq)]
pub struct ProofContext {
    key: ProofKey,
    issuer: String,
    trust_identity: String,
    nonce: Vec<u8>,
    operation_digest: [u8; 32],
    purpose: ValueBearingPurpose,
    policy_id: String,
    subject_binding: Vec<u8>,
    evidence_digest: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    freshness_secs: u64,
    replay_identity: Vec<u8>,
    canonical_digest: [u8; 32],
}

impl fmt::Debug for ProofContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofContext")
            .field("key", &self.key)
            .field("issuer", &self.issuer)
            .field("trust_identity", &self.trust_identity)
            .field("nonce_len", &self.nonce.len())
            .field("operation_digest", &self.operation_digest)
            .field("purpose", &self.purpose)
            .field("policy_id", &self.policy_id)
            .field("subject_binding_len", &self.subject_binding.len())
            .field("evidence_digest", &self.evidence_digest)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("freshness_secs", &self.freshness_secs)
            .field("replay_identity_len", &self.replay_identity.len())
            .field("canonical_digest", &self.canonical_digest)
            .finish()
    }
}

impl ProofContext {
    #[allow(clippy::too_many_arguments)]
    fn new(
        key: ProofKey,
        issuer: String,
        trust_identity: String,
        nonce: Vec<u8>,
        operation_digest: [u8; 32],
        purpose: ValueBearingPurpose,
        policy_id: String,
        subject_binding: Vec<u8>,
        evidence_digest: [u8; 32],
        issued_at: u64,
        expires_at: u64,
        freshness_secs: u64,
        replay_identity: Vec<u8>,
    ) -> Result<Self, ProofInputError> {
        validate_text(&issuer)?;
        validate_text(&trust_identity)?;
        validate_text(&policy_id)?;
        validate_bytes(&nonce, MAX_NONCE_BYTES)?;
        validate_bytes(&subject_binding, MAX_SUBJECT_BINDING_BYTES)?;
        validate_bytes(&replay_identity, MAX_REPLAY_IDENTITY_BYTES)?;

        let mut canonical = Vec::new();
        append_len_prefixed(&mut canonical, PROOF_CONTEXT_DOMAIN.as_bytes())?;
        canonical.extend_from_slice(&PROOF_CONTEXT_VERSION.to_be_bytes());
        canonical.push(key.proof_type.canonical_tag());
        canonical.push(key.subject.canonical_tag());
        append_len_prefixed(&mut canonical, issuer.as_bytes())?;
        append_len_prefixed(&mut canonical, trust_identity.as_bytes())?;
        append_len_prefixed(&mut canonical, &nonce)?;
        append_len_prefixed(&mut canonical, &operation_digest)?;
        canonical.push(purpose.canonical_tag());
        append_len_prefixed(&mut canonical, policy_id.as_bytes())?;
        append_len_prefixed(&mut canonical, &subject_binding)?;
        append_len_prefixed(&mut canonical, &evidence_digest)?;
        canonical.extend_from_slice(&issued_at.to_be_bytes());
        canonical.extend_from_slice(&expires_at.to_be_bytes());
        canonical.extend_from_slice(&freshness_secs.to_be_bytes());
        append_len_prefixed(&mut canonical, &replay_identity)?;

        Ok(Self {
            key,
            issuer,
            trust_identity,
            nonce,
            operation_digest,
            purpose,
            policy_id,
            subject_binding,
            evidence_digest,
            issued_at,
            expires_at,
            freshness_secs,
            replay_identity,
            canonical_digest: Sha256::digest(canonical).into(),
        })
    }

    pub fn key(&self) -> ProofKey {
        self.key
    }

    pub fn proof_type(&self) -> ProofType {
        self.key.proof_type
    }

    pub fn subject(&self) -> ProofSubject {
        self.key.subject
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn trust_identity(&self) -> &str {
        &self.trust_identity
    }

    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn operation_digest(&self) -> &[u8; 32] {
        &self.operation_digest
    }

    pub fn purpose(&self) -> ValueBearingPurpose {
        self.purpose
    }

    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub fn subject_binding(&self) -> &[u8] {
        &self.subject_binding
    }

    pub fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence_digest
    }

    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn freshness_secs(&self) -> u64 {
        self.freshness_secs
    }

    pub fn replay_identity(&self) -> &[u8] {
        &self.replay_identity
    }

    pub fn canonical_digest(&self) -> &[u8; 32] {
        &self.canonical_digest
    }
}

/// Raw, unverified evidence. The bytes are bounded but are never treated as
/// proof until an exact registry verifier creates a verified proof type.
#[derive(Clone, PartialEq, Eq)]
pub struct RawProofEvidence {
    context: ProofContext,
    evidence: Vec<u8>,
}

impl fmt::Debug for RawProofEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawProofEvidence")
            .field("context", &self.context)
            .field("evidence_len", &self.evidence.len())
            .field("evidence_digest", &self.context.evidence_digest())
            .finish()
    }
}

impl RawProofEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: ProofKey,
        issuer: impl Into<String>,
        trust_identity: impl Into<String>,
        nonce: Vec<u8>,
        operation_digest: [u8; 32],
        purpose: ValueBearingPurpose,
        policy_id: impl Into<String>,
        subject_binding: Vec<u8>,
        issued_at: u64,
        expires_at: u64,
        freshness_secs: u64,
        replay_identity: Vec<u8>,
        evidence: Vec<u8>,
    ) -> Result<Self, ProofInputError> {
        validate_bytes(&evidence, MAX_EVIDENCE_BYTES)?;
        let evidence_digest: [u8; 32] = Sha256::digest(&evidence).into();
        let context = ProofContext::new(
            key,
            issuer.into(),
            trust_identity.into(),
            nonce,
            operation_digest,
            purpose,
            policy_id.into(),
            subject_binding,
            evidence_digest,
            issued_at,
            expires_at,
            freshness_secs,
            replay_identity,
        )?;
        Ok(Self { context, evidence })
    }

    pub fn context(&self) -> &ProofContext {
        &self.context
    }

    pub fn key(&self) -> ProofKey {
        self.context.key()
    }

    pub fn evidence(&self) -> &[u8] {
        &self.evidence
    }

    pub fn evidence_digest(&self) -> &[u8; 32] {
        self.context.evidence_digest()
    }

    #[cfg(test)]
    pub(crate) fn test_fixture(input: TestProofEvidenceInput) -> Self {
        Self::new(
            input.key,
            input.issuer,
            input.trust_identity,
            input.nonce,
            input.operation_digest,
            input.purpose,
            input.policy_id,
            input.subject_binding,
            input.issued_at,
            input.expires_at,
            input.freshness_secs,
            input.replay_identity,
            fixture_marker(input.key.proof_type),
        )
        .expect("bounded test fixture evidence should construct")
    }
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct TestProofEvidenceInput {
    key: ProofKey,
    issuer: String,
    trust_identity: String,
    nonce: Vec<u8>,
    operation_digest: [u8; 32],
    purpose: ValueBearingPurpose,
    policy_id: String,
    subject_binding: Vec<u8>,
    issued_at: u64,
    expires_at: u64,
    freshness_secs: u64,
    replay_identity: Vec<u8>,
}

#[cfg(test)]
impl TestProofEvidenceInput {
    pub(crate) fn new(
        key: ProofKey,
        operation_digest: [u8; 32],
        purpose: ValueBearingPurpose,
    ) -> Self {
        Self {
            key,
            issuer: "test-fixture-issuer".to_string(),
            trust_identity: "test-fixture-root".to_string(),
            nonce: b"nonce".to_vec(),
            operation_digest,
            purpose,
            policy_id: "test-fixture-policy".to_string(),
            subject_binding: b"subject-binding".to_vec(),
            issued_at: 0,
            expires_at: 100,
            freshness_secs: 100,
            replay_identity: b"replay".to_vec(),
        }
    }

    pub(crate) fn from_policy(
        policy: &ProofSetPolicy,
        requirement: &ProofRequirement,
        now_secs: u64,
    ) -> Self {
        Self::new(
            requirement.key(),
            *policy.operation_digest(),
            policy.purpose(),
        )
        .with_issuer(requirement.issuer())
        .with_trust_identity(requirement.trust_identity())
        .with_nonce(policy.nonce().to_vec())
        .with_policy_id(policy.policy_id())
        .with_subject_binding(requirement.subject_binding().to_vec())
        .with_times(
            now_secs.saturating_sub(1),
            now_secs.saturating_add(policy.max_age_secs().saturating_sub(1)),
            policy.max_age_secs(),
        )
        .with_replay_identity(policy.replay_identity().to_vec())
    }

    pub(crate) fn with_key(mut self, key: ProofKey) -> Self {
        self.key = key;
        self
    }

    pub(crate) fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    pub(crate) fn with_trust_identity(mut self, trust_identity: impl Into<String>) -> Self {
        self.trust_identity = trust_identity.into();
        self
    }

    pub(crate) fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = nonce;
        self
    }

    pub(crate) fn with_operation_digest(mut self, operation_digest: [u8; 32]) -> Self {
        self.operation_digest = operation_digest;
        self
    }

    pub(crate) fn with_purpose(mut self, purpose: ValueBearingPurpose) -> Self {
        self.purpose = purpose;
        self
    }

    pub(crate) fn with_policy_id(mut self, policy_id: impl Into<String>) -> Self {
        self.policy_id = policy_id.into();
        self
    }

    pub(crate) fn with_subject_binding(mut self, subject_binding: Vec<u8>) -> Self {
        self.subject_binding = subject_binding;
        self
    }

    pub(crate) fn with_times(
        mut self,
        issued_at: u64,
        expires_at: u64,
        freshness_secs: u64,
    ) -> Self {
        self.issued_at = issued_at;
        self.expires_at = expires_at;
        self.freshness_secs = freshness_secs;
        self
    }

    pub(crate) fn with_replay_identity(mut self, replay_identity: Vec<u8>) -> Self {
        self.replay_identity = replay_identity;
        self
    }
}

/// Exact proof verification failures. No variant contains raw evidence bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProofVerificationError {
    #[error("production verifier is unavailable for this proof type")]
    UnsupportedProductionVerifier,
    #[error("test fixture verifier is not allowed by the production policy")]
    FixtureNotAllowedByProductionPolicy,
    #[error("evidence is malformed")]
    MalformedEvidence,
    #[error("evidence failed the exact proof verifier")]
    InvalidEvidence,
    #[error("proof is stale")]
    Stale,
    #[error("proof is future-dated beyond policy skew")]
    FutureDated,
    #[error("proof nonce/challenge does not match policy")]
    WrongNonce,
    #[error("proof operation digest does not match policy")]
    WrongOperationDigest,
    #[error("proof purpose does not match policy")]
    WrongPurpose,
    #[error("proof policy id does not match policy")]
    WrongPolicy,
    #[error("proof subject does not match the exact requirement")]
    WrongSubject,
    #[error("proof issuer or trust root does not match policy")]
    WrongIssuer,
    #[error("proof trust identity does not match policy")]
    WrongTrustIdentity,
    #[error("proof subject binding does not match policy")]
    WrongSubjectBinding,
    #[error("proof replay identity does not match policy")]
    WrongReplayIdentity,
    #[error("proof mechanism/subject type substitution was attempted")]
    TypeSubstitution,
    #[error("proof canonical context is invalid")]
    CanonicalContextInvalid,
    #[error("proof freshness bounds are invalid")]
    InvalidFreshness,
}

/// A verification result that retains the exact proof key for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("proof verification failed for {key:?}: {error}")]
pub struct ProofVerificationFailure {
    pub key: ProofKey,
    pub error: ProofVerificationError,
}

/// One exact required proof in a policy. There is no implicit hardware bucket.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ProofRequirement {
    key: ProofKey,
    issuer: String,
    trust_identity: String,
    subject_binding: Vec<u8>,
    canonical_digest: [u8; 32],
}

impl fmt::Debug for ProofRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofRequirement")
            .field("key", &self.key)
            .field("issuer", &self.issuer)
            .field("trust_identity", &self.trust_identity)
            .field("subject_binding_len", &self.subject_binding.len())
            .finish()
    }
}

impl ProofRequirement {
    pub fn new(
        key: ProofKey,
        issuer: impl Into<String>,
        trust_identity: impl Into<String>,
        subject_binding: Vec<u8>,
    ) -> Result<Self, ProofInputError> {
        if !key.is_subject_mechanism_pair_valid() {
            return Err(ProofInputError::InvalidSubjectMechanismPair);
        }
        let issuer = issuer.into();
        let trust_identity = trust_identity.into();
        validate_required_text(&issuer)?;
        validate_required_text(&trust_identity)?;
        validate_required_bytes(&subject_binding, MAX_SUBJECT_BINDING_BYTES)?;

        let mut canonical = Vec::new();
        append_len_prefixed(&mut canonical, PROOF_REQUIREMENT_DOMAIN.as_bytes())?;
        canonical.extend_from_slice(&PROOF_REQUIREMENT_VERSION.to_be_bytes());
        canonical.push(key.proof_type.canonical_tag());
        canonical.push(key.subject.canonical_tag());
        append_len_prefixed(&mut canonical, issuer.as_bytes())?;
        append_len_prefixed(&mut canonical, trust_identity.as_bytes())?;
        append_len_prefixed(&mut canonical, &subject_binding)?;

        Ok(Self {
            key,
            issuer,
            trust_identity,
            subject_binding,
            canonical_digest: Sha256::digest(canonical).into(),
        })
    }

    pub fn key(&self) -> ProofKey {
        self.key
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn trust_identity(&self) -> &str {
        &self.trust_identity
    }

    pub fn subject_binding(&self) -> &[u8] {
        &self.subject_binding
    }

    fn canonical_digest(&self) -> &[u8; 32] {
        &self.canonical_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum PolicyMode {
    Production,
    #[cfg(test)]
    TestFixture,
}

impl PolicyMode {
    fn canonical_tag(self) -> u8 {
        match self {
            Self::Production => 1,
            #[cfg(test)]
            Self::TestFixture => 2,
        }
    }
}

/// Explicit all-required proof policy for a value-bearing operation.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ProofSetPolicy {
    policy_id: String,
    operation_digest: [u8; 32],
    purpose: ValueBearingPurpose,
    nonce: Vec<u8>,
    replay_identity: Vec<u8>,
    max_age_secs: u64,
    max_future_skew_secs: u64,
    requirements: Vec<ProofRequirement>,
    mode: PolicyMode,
    canonical_digest: [u8; 32],
}

impl fmt::Debug for ProofSetPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofSetPolicy")
            .field("policy_id", &self.policy_id)
            .field("operation_digest", &self.operation_digest)
            .field("purpose", &self.purpose)
            .field("nonce_len", &self.nonce.len())
            .field("replay_identity_len", &self.replay_identity.len())
            .field("max_age_secs", &self.max_age_secs)
            .field("max_future_skew_secs", &self.max_future_skew_secs)
            .field("requirements", &self.requirements)
            .field("mode", &self.mode)
            .finish()
    }
}

impl ProofSetPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_id: impl Into<String>,
        operation_digest: [u8; 32],
        purpose: ValueBearingPurpose,
        nonce: Vec<u8>,
        replay_identity: Vec<u8>,
        max_age_secs: u64,
        max_future_skew_secs: u64,
        requirements: Vec<ProofRequirement>,
    ) -> Result<Self, ProofInputError> {
        Self::new_with_mode(
            policy_id,
            operation_digest,
            purpose,
            nonce,
            replay_identity,
            max_age_secs,
            max_future_skew_secs,
            requirements,
            PolicyMode::Production,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn test_fixture(
        policy_id: impl Into<String>,
        operation_digest: [u8; 32],
        purpose: ValueBearingPurpose,
        nonce: Vec<u8>,
        replay_identity: Vec<u8>,
        max_age_secs: u64,
        max_future_skew_secs: u64,
        requirements: Vec<ProofRequirement>,
    ) -> Result<Self, ProofInputError> {
        Self::new_with_mode(
            policy_id,
            operation_digest,
            purpose,
            nonce,
            replay_identity,
            max_age_secs,
            max_future_skew_secs,
            requirements,
            PolicyMode::TestFixture,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_mode(
        policy_id: impl Into<String>,
        operation_digest: [u8; 32],
        purpose: ValueBearingPurpose,
        nonce: Vec<u8>,
        replay_identity: Vec<u8>,
        max_age_secs: u64,
        max_future_skew_secs: u64,
        mut requirements: Vec<ProofRequirement>,
        mode: PolicyMode,
    ) -> Result<Self, ProofInputError> {
        let policy_id = policy_id.into();
        validate_required_text(&policy_id)?;
        validate_bytes(&nonce, MAX_NONCE_BYTES)?;
        validate_bytes(&replay_identity, MAX_REPLAY_IDENTITY_BYTES)?;
        if nonce.is_empty() || replay_identity.is_empty() {
            return Err(ProofInputError::EmptyRequirementSet);
        }
        if requirements.is_empty() {
            return Err(ProofInputError::EmptyRequirementSet);
        }
        if requirements.len() > MAX_PROOF_COUNT {
            return Err(ProofInputError::RequirementCountExceeded);
        }
        if max_age_secs == 0
            || max_age_secs > MAX_FRESHNESS_SECS
            || max_future_skew_secs > MAX_FRESHNESS_SECS
        {
            return Err(ProofInputError::InvalidFreshnessBounds);
        }

        let mut seen = BTreeMap::new();
        for requirement in &requirements {
            if seen.insert(requirement.key, ()).is_some() {
                return Err(ProofInputError::DuplicateRequirement);
            }
        }

        // Requirements are a set, not an ordered list. Canonicalize the
        // stored declaration so equality, composition, and serialization do
        // not depend on caller declaration order.
        requirements.sort_by_key(|requirement| requirement.key);

        let canonical_digest = canonical_policy_digest(&CanonicalPolicyInput {
            policy_id: &policy_id,
            operation_digest: &operation_digest,
            purpose,
            nonce: &nonce,
            replay_identity: &replay_identity,
            max_age_secs,
            max_future_skew_secs,
            requirements: &requirements,
            mode,
        })?;

        Ok(Self {
            policy_id,
            operation_digest,
            purpose,
            nonce,
            replay_identity,
            max_age_secs,
            max_future_skew_secs,
            requirements,
            mode,
            canonical_digest,
        })
    }

    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub fn operation_digest(&self) -> &[u8; 32] {
        &self.operation_digest
    }

    pub fn purpose(&self) -> ValueBearingPurpose {
        self.purpose
    }

    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn replay_identity(&self) -> &[u8] {
        &self.replay_identity
    }

    pub fn max_age_secs(&self) -> u64 {
        self.max_age_secs
    }

    pub fn max_future_skew_secs(&self) -> u64 {
        self.max_future_skew_secs
    }

    pub fn requirements(&self) -> &[ProofRequirement] {
        &self.requirements
    }

    /// Returns the versioned, domain-separated digest of every
    /// authorization-relevant policy field and the complete exact requirement
    /// set.
    pub fn canonical_digest(&self) -> &[u8; 32] {
        &self.canonical_digest
    }

    /// Alias emphasizing that this digest is the policy integrity commitment,
    /// while `policy_id` remains only a human/provider label.
    pub fn policy_digest(&self) -> &[u8; 32] {
        self.canonical_digest()
    }

    pub fn composer<'a>(&'a self, registry: &'a ProofVerifierRegistry) -> ProofSetComposer<'a> {
        ProofSetComposer {
            policy: self,
            registry,
        }
    }
}

struct CanonicalPolicyInput<'a> {
    policy_id: &'a str,
    operation_digest: &'a [u8; 32],
    purpose: ValueBearingPurpose,
    nonce: &'a [u8],
    replay_identity: &'a [u8],
    max_age_secs: u64,
    max_future_skew_secs: u64,
    requirements: &'a [ProofRequirement],
    mode: PolicyMode,
}

fn canonical_policy_digest(input: &CanonicalPolicyInput<'_>) -> Result<[u8; 32], ProofInputError> {
    let mut requirement_digests: Vec<&[u8; 32]> = input
        .requirements
        .iter()
        .map(ProofRequirement::canonical_digest)
        .collect();
    requirement_digests.sort_unstable_by(|left, right| left.as_slice().cmp(right.as_slice()));

    let mut canonical = Vec::new();
    append_len_prefixed(&mut canonical, PROOF_POLICY_DOMAIN.as_bytes())?;
    canonical.extend_from_slice(&PROOF_POLICY_VERSION.to_be_bytes());
    canonical.push(input.mode.canonical_tag());
    append_len_prefixed(&mut canonical, input.policy_id.as_bytes())?;
    append_len_prefixed(&mut canonical, input.operation_digest)?;
    canonical.push(input.purpose.canonical_tag());
    append_len_prefixed(&mut canonical, input.nonce)?;
    append_len_prefixed(&mut canonical, input.replay_identity)?;
    canonical.extend_from_slice(&input.max_age_secs.to_be_bytes());
    canonical.extend_from_slice(&input.max_future_skew_secs.to_be_bytes());
    let requirement_count = u32::try_from(requirement_digests.len())
        .map_err(|_| ProofInputError::RequirementCountExceeded)?;
    canonical.extend_from_slice(&requirement_count.to_be_bytes());
    for requirement_digest in requirement_digests {
        canonical.extend_from_slice(requirement_digest);
    }

    Ok(Sha256::digest(canonical).into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryMode {
    Production,
    #[cfg(test)]
    TestFixture,
}

/// Exact-type verifier registry. Production slots are intentionally absent
/// until concrete provider roots, collateral, runtime, and review evidence
/// exist. Test fixtures are compiled only into unit-test builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofVerifierRegistry {
    mode: RegistryMode,
}

impl ProofVerifierRegistry {
    pub const fn production() -> Self {
        Self {
            mode: RegistryMode::Production,
        }
    }

    #[cfg(test)]
    pub(crate) const fn test_fixture() -> Self {
        Self {
            mode: RegistryMode::TestFixture,
        }
    }

    pub fn verify_one(
        &self,
        raw: &RawProofEvidence,
        requirement: &ProofRequirement,
        _policy: &ProofSetPolicy,
        _now_secs: u64,
    ) -> Result<VerifiedProofArtifact, ProofVerificationFailure> {
        let key = raw.key();
        if key.proof_type() == requirement.key.proof_type()
            && key.subject() != requirement.key.subject()
        {
            return Err(ProofVerificationFailure {
                key,
                error: ProofVerificationError::WrongSubject,
            });
        }
        if key != requirement.key {
            return Err(ProofVerificationFailure {
                key,
                error: ProofVerificationError::TypeSubstitution,
            });
        }
        if !key.is_subject_mechanism_pair_valid() {
            return Err(ProofVerificationFailure {
                key,
                error: ProofVerificationError::TypeSubstitution,
            });
        }

        match self.mode {
            RegistryMode::Production => Err(ProofVerificationFailure {
                key,
                error: ProofVerificationError::UnsupportedProductionVerifier,
            }),
            #[cfg(test)]
            RegistryMode::TestFixture => {
                if _policy.mode != PolicyMode::TestFixture {
                    return Err(ProofVerificationFailure {
                        key,
                        error: ProofVerificationError::FixtureNotAllowedByProductionPolicy,
                    });
                }
                self.verify_test_fixture(raw, requirement, _policy, _now_secs)
            }
        }
    }

    #[cfg(test)]
    fn verify_test_fixture(
        &self,
        raw: &RawProofEvidence,
        requirement: &ProofRequirement,
        policy: &ProofSetPolicy,
        now_secs: u64,
    ) -> Result<VerifiedProofArtifact, ProofVerificationFailure> {
        verify_common(raw, requirement, policy, now_secs)?;
        if raw.evidence() != fixture_marker(raw.key().proof_type).as_slice() {
            return Err(ProofVerificationFailure {
                key: raw.key(),
                error: ProofVerificationError::InvalidEvidence,
            });
        }

        Ok(match raw.key().proof_type {
            ProofType::ServerIdentity => {
                VerifiedProofArtifact::ServerIdentity(VerifiedServerIdentityProof::from_raw(raw))
            }
            ProofType::UserAuthorization => VerifiedProofArtifact::UserAuthorization(
                VerifiedUserAuthorizationProof::from_raw(raw),
            ),
            ProofType::PhoneDeviceAttestation => VerifiedProofArtifact::PhoneDeviceAttestation(
                VerifiedPhoneDeviceAttestationProof::from_raw(raw),
            ),
            ProofType::TeeAttestation => {
                VerifiedProofArtifact::TeeAttestation(VerifiedTeeAttestationProof::from_raw(raw))
            }
            ProofType::Fido2WebAuthnAssertion => {
                VerifiedProofArtifact::Fido2WebAuthn(VerifiedFido2WebAuthnProof::from_raw(raw))
            }
            ProofType::TpmQuote => {
                VerifiedProofArtifact::TpmQuote(VerifiedTpmQuoteProof::from_raw(raw))
            }
        })
    }
}

#[cfg(test)]
fn verify_common(
    raw: &RawProofEvidence,
    requirement: &ProofRequirement,
    policy: &ProofSetPolicy,
    now_secs: u64,
) -> Result<(), ProofVerificationFailure> {
    let key = raw.key();
    let context = raw.context();
    if key.subject() != requirement.key.subject() {
        return Err(ProofVerificationFailure {
            key,
            error: ProofVerificationError::WrongSubject,
        });
    }
    if context.issuer() != requirement.issuer() {
        return Err(ProofVerificationFailure {
            key,
            error: ProofVerificationError::WrongIssuer,
        });
    }
    if context.trust_identity() != requirement.trust_identity() {
        return Err(ProofVerificationFailure {
            key,
            error: ProofVerificationError::WrongTrustIdentity,
        });
    }
    if context.subject_binding() != requirement.subject_binding() {
        return Err(ProofVerificationFailure {
            key,
            error: ProofVerificationError::WrongSubjectBinding,
        });
    }
    if context.nonce() != policy.nonce() {
        return Err(ProofVerificationFailure {
            key,
            error: ProofVerificationError::WrongNonce,
        });
    }
    if context.operation_digest() != policy.operation_digest() {
        return Err(ProofVerificationFailure {
            key,
            error: ProofVerificationError::WrongOperationDigest,
        });
    }
    if context.purpose() != policy.purpose() {
        return Err(ProofVerificationFailure {
            key,
            error: ProofVerificationError::WrongPurpose,
        });
    }
    if context.policy_id() != policy.policy_id() {
        return Err(ProofVerificationFailure {
            key,
            error: ProofVerificationError::WrongPolicy,
        });
    }
    if context.replay_identity() != policy.replay_identity() {
        return Err(ProofVerificationFailure {
            key,
            error: ProofVerificationError::WrongReplayIdentity,
        });
    }
    if context.canonical_digest().is_empty() {
        return Err(ProofVerificationFailure {
            key,
            error: ProofVerificationError::CanonicalContextInvalid,
        });
    }
    if context.expires_at() <= context.issued_at()
        || context.freshness_secs() == 0
        || context.freshness_secs() > MAX_FRESHNESS_SECS
        || context.expires_at().saturating_sub(context.issued_at()) > context.freshness_secs()
        || context.freshness_secs() > policy.max_age_secs()
    {
        return Err(ProofVerificationFailure {
            key,
            error: ProofVerificationError::InvalidFreshness,
        });
    }
    if context.issued_at() > now_secs.saturating_add(policy.max_future_skew_secs()) {
        return Err(ProofVerificationFailure {
            key,
            error: ProofVerificationError::FutureDated,
        });
    }
    if context.expires_at() <= now_secs {
        return Err(ProofVerificationFailure {
            key,
            error: ProofVerificationError::Stale,
        });
    }
    if raw.evidence().is_empty() {
        return Err(ProofVerificationFailure {
            key,
            error: ProofVerificationError::MalformedEvidence,
        });
    }
    let computed_digest: [u8; 32] = Sha256::digest(raw.evidence()).into();
    if &computed_digest != context.evidence_digest() {
        return Err(ProofVerificationFailure {
            key,
            error: ProofVerificationError::CanonicalContextInvalid,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedProofData {
    context: ProofContext,
}

macro_rules! define_verified_proof {
    ($name:ident, $expected:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            data: VerifiedProofData,
        }

        impl $name {
            #[cfg(test)]
            fn from_raw(raw: &RawProofEvidence) -> Self {
                debug_assert_eq!(raw.key().proof_type(), $expected);
                Self {
                    data: VerifiedProofData {
                        context: raw.context().clone(),
                    },
                }
            }

            pub fn context(&self) -> &ProofContext {
                &self.data.context
            }

            pub fn key(&self) -> ProofKey {
                self.data.context.key()
            }

            pub fn proof_type(&self) -> ProofType {
                self.data.context.proof_type()
            }

            pub fn subject(&self) -> ProofSubject {
                self.data.context.subject()
            }

            pub fn canonical_digest(&self) -> &[u8; 32] {
                self.data.context.canonical_digest()
            }

            pub fn evidence_digest(&self) -> &[u8; 32] {
                self.data.context.evidence_digest()
            }
        }
    };
}

define_verified_proof!(VerifiedServerIdentityProof, ProofType::ServerIdentity);
define_verified_proof!(VerifiedUserAuthorizationProof, ProofType::UserAuthorization);
define_verified_proof!(
    VerifiedPhoneDeviceAttestationProof,
    ProofType::PhoneDeviceAttestation
);
define_verified_proof!(VerifiedTeeAttestationProof, ProofType::TeeAttestation);
define_verified_proof!(
    VerifiedFido2WebAuthnProof,
    ProofType::Fido2WebAuthnAssertion
);
define_verified_proof!(VerifiedTpmQuoteProof, ProofType::TpmQuote);

/// Union of exact verified proof types. Each variant is constructed only by
/// its matching verifier branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedProofArtifact {
    ServerIdentity(VerifiedServerIdentityProof),
    UserAuthorization(VerifiedUserAuthorizationProof),
    PhoneDeviceAttestation(VerifiedPhoneDeviceAttestationProof),
    TeeAttestation(VerifiedTeeAttestationProof),
    Fido2WebAuthn(VerifiedFido2WebAuthnProof),
    TpmQuote(VerifiedTpmQuoteProof),
}

impl VerifiedProofArtifact {
    pub fn key(&self) -> ProofKey {
        match self {
            Self::ServerIdentity(proof) => proof.key(),
            Self::UserAuthorization(proof) => proof.key(),
            Self::PhoneDeviceAttestation(proof) => proof.key(),
            Self::TeeAttestation(proof) => proof.key(),
            Self::Fido2WebAuthn(proof) => proof.key(),
            Self::TpmQuote(proof) => proof.key(),
        }
    }

    pub fn proof_type(&self) -> ProofType {
        self.key().proof_type()
    }

    pub fn subject(&self) -> ProofSubject {
        self.key().subject()
    }

    pub fn context(&self) -> &ProofContext {
        match self {
            Self::ServerIdentity(proof) => proof.context(),
            Self::UserAuthorization(proof) => proof.context(),
            Self::PhoneDeviceAttestation(proof) => proof.context(),
            Self::TeeAttestation(proof) => proof.context(),
            Self::Fido2WebAuthn(proof) => proof.context(),
            Self::TpmQuote(proof) => proof.context(),
        }
    }

    fn canonical_digest(&self) -> &[u8; 32] {
        match self {
            Self::ServerIdentity(proof) => proof.canonical_digest(),
            Self::UserAuthorization(proof) => proof.canonical_digest(),
            Self::PhoneDeviceAttestation(proof) => proof.canonical_digest(),
            Self::TeeAttestation(proof) => proof.canonical_digest(),
            Self::Fido2WebAuthn(proof) => proof.canonical_digest(),
            Self::TpmQuote(proof) => proof.canonical_digest(),
        }
    }
}

/// Errors raised while composing a complete exact proof set.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProofSetError {
    #[error("proof set exceeds the configured count bound")]
    ProofCountExceeded,
    #[error("proof set contains duplicate proof {key:?}")]
    DuplicateProof { key: ProofKey },
    #[error("proof set contains conflicting proof {key:?}")]
    ConflictingProof { key: ProofKey },
    #[error("proof set is missing required proof {key:?}")]
    MissingRequiredProof { key: ProofKey },
    #[error("proof set contains an unexpected proof {key:?}")]
    UnexpectedProof { key: ProofKey },
    #[error("proof set attempted type substitution for {key:?}")]
    TypeSubstitution { key: ProofKey },
    #[error("proof verification failed: {0}")]
    Verification(ProofVerificationFailure),
}

/// Read-only composer that enforces all exact requirements before producing a
/// non-forgeable verified set.
pub struct ProofSetComposer<'a> {
    policy: &'a ProofSetPolicy,
    registry: &'a ProofVerifierRegistry,
}

impl<'a> ProofSetComposer<'a> {
    pub fn compose(
        &self,
        raw_proofs: &[RawProofEvidence],
        now_secs: u64,
    ) -> Result<VerifiedProofSet, ProofSetError> {
        if raw_proofs.len() > MAX_PROOF_COUNT {
            return Err(ProofSetError::ProofCountExceeded);
        }

        let requirements: BTreeMap<ProofKey, &ProofRequirement> = self
            .policy
            .requirements
            .iter()
            .map(|requirement| (requirement.key, requirement))
            .collect();
        let mut indexed: BTreeMap<ProofKey, &RawProofEvidence> = BTreeMap::new();
        for raw in raw_proofs {
            let key = raw.key();
            if let Some(previous) = indexed.insert(key, raw) {
                if previous.context().canonical_digest() != raw.context().canonical_digest() {
                    return Err(ProofSetError::ConflictingProof { key });
                }
                return Err(ProofSetError::DuplicateProof { key });
            }
            if !requirements.contains_key(&key) {
                return Err(ProofSetError::TypeSubstitution { key });
            }
        }

        for requirement in self.policy.requirements() {
            if !indexed.contains_key(&requirement.key) {
                return Err(ProofSetError::MissingRequiredProof {
                    key: requirement.key,
                });
            }
        }

        let mut verified = Vec::with_capacity(indexed.len());
        for (key, raw) in indexed {
            let requirement = requirements
                .get(&key)
                .copied()
                .ok_or(ProofSetError::UnexpectedProof { key })?;
            verified.push(
                self.registry
                    .verify_one(raw, requirement, self.policy, now_secs)
                    .map_err(ProofSetError::Verification)?,
            );
        }

        Ok(VerifiedProofSet::from_verified(
            self.policy.clone(),
            verified,
        ))
    }
}

/// A fully composed proof set. Its fields are private and there is no public
/// constructor or unchecked conversion from raw evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProofSet {
    policy: ProofSetPolicy,
    proofs: Vec<VerifiedProofArtifact>,
    policy_digest: [u8; 32],
    canonical_digest: [u8; 32],
}

impl VerifiedProofSet {
    fn from_verified(policy: ProofSetPolicy, mut proofs: Vec<VerifiedProofArtifact>) -> Self {
        proofs.sort_by_key(VerifiedProofArtifact::key);
        let policy_digest = *policy.canonical_digest();
        let mut canonical = Vec::new();
        append_len_prefixed(&mut canonical, PROOF_SET_DOMAIN.as_bytes())
            .expect("proof-set domain is bounded");
        canonical.extend_from_slice(&policy_digest);
        canonical.extend_from_slice(
            &u32::try_from(proofs.len())
                .expect("proof set count is bounded")
                .to_be_bytes(),
        );
        for proof in &proofs {
            canonical.push(proof.key().proof_type().canonical_tag());
            canonical.push(proof.key().subject().canonical_tag());
            canonical.extend_from_slice(proof.canonical_digest());
        }
        Self {
            policy,
            proofs,
            policy_digest,
            canonical_digest: Sha256::digest(canonical).into(),
        }
    }

    pub fn policy_id(&self) -> &str {
        self.policy.policy_id()
    }

    pub fn operation_digest(&self) -> &[u8; 32] {
        self.policy.operation_digest()
    }

    pub fn purpose(&self) -> ValueBearingPurpose {
        self.policy.purpose()
    }

    pub fn nonce(&self) -> &[u8] {
        self.policy.nonce()
    }

    pub fn replay_identity(&self) -> &[u8] {
        self.policy.replay_identity()
    }

    pub fn proofs(&self) -> &[VerifiedProofArtifact] {
        &self.proofs
    }

    pub fn proof_count(&self) -> usize {
        self.proofs.len()
    }

    /// Returns the exact canonical policy digest used when this set was
    /// composed. This is a safe summary and never exposes raw evidence.
    pub fn policy_digest(&self) -> &[u8; 32] {
        &self.policy_digest
    }

    pub fn canonical_digest(&self) -> &[u8; 32] {
        &self.canonical_digest
    }

    pub fn contains(&self, key: ProofKey) -> bool {
        self.proofs.iter().any(|proof| proof.key() == key)
    }

    pub(crate) fn matches_binding(
        &self,
        expected_policy: &ProofSetPolicy,
        operation_digest: &[u8; 32],
        purpose: ValueBearingPurpose,
    ) -> bool {
        self.policy == *expected_policy
            && self.policy_digest() == expected_policy.policy_digest()
            && self.operation_digest() == operation_digest
            && self.purpose() == purpose
            && self.proof_count() == expected_policy.requirements().len()
    }
}

#[cfg(test)]
fn fixture_marker(proof_type: ProofType) -> Vec<u8> {
    [
        b"CONXIAN-TEST-PROOF/v1:".as_slice(),
        proof_type.canonical_token().as_bytes(),
    ]
    .concat()
}

#[cfg(test)]
pub(crate) fn test_fixture_set_for_request(
    request: &ValueBearingSignRequest,
) -> crate::ConclaveResult<VerifiedProofSet> {
    let policy = request.expected_proof_policy().ok_or_else(|| {
        crate::ConclaveError::Unsupported(
            "test proof composition requires an expected proof policy".to_string(),
        )
    })?;
    let now_secs = unix_time_secs();
    let raw_proofs = policy
        .requirements()
        .iter()
        .map(|requirement| {
            RawProofEvidence::test_fixture(TestProofEvidenceInput::from_policy(
                policy,
                requirement,
                now_secs,
            ))
        })
        .collect::<Vec<_>>();
    policy
        .composer(&ProofVerifierRegistry::test_fixture())
        .compose(&raw_proofs, now_secs)
        .map_err(|error| crate::ConclaveError::Unsupported(error.to_string()))
}

#[cfg(test)]
fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "proof-test-policy-v1";
    const ISSUER: &str = "test-issuer";
    const ROOT: &str = "test-root";

    fn requirement(key: ProofKey, binding: &[u8]) -> ProofRequirement {
        ProofRequirement::new(key, ISSUER, ROOT, binding.to_vec()).expect("valid requirement")
    }

    fn raw(
        key: ProofKey,
        now: u64,
        operation_digest: [u8; 32],
        nonce: Vec<u8>,
        purpose: ValueBearingPurpose,
        policy_id: &str,
        binding: &[u8],
    ) -> RawProofEvidence {
        RawProofEvidence::test_fixture(
            TestProofEvidenceInput::new(key, operation_digest, purpose)
                .with_issuer(ISSUER)
                .with_trust_identity(ROOT)
                .with_nonce(nonce)
                .with_policy_id(policy_id)
                .with_subject_binding(binding.to_vec())
                .with_times(now.saturating_sub(1), now.saturating_add(99), 100)
                .with_replay_identity(b"replay".to_vec()),
        )
    }

    fn fixture_policy(
        operation_digest: [u8; 32],
        nonce: Vec<u8>,
        requirements: Vec<ProofRequirement>,
    ) -> ProofSetPolicy {
        ProofSetPolicy::test_fixture(
            POLICY,
            operation_digest,
            ValueBearingPurpose::Transaction,
            nonce,
            b"replay".to_vec(),
            100,
            5,
            requirements,
        )
        .expect("valid fixture policy")
    }

    #[test]
    fn all_six_proof_categories_verify_independently_and_compose() {
        let now = 1_000;
        let digest = [7; 32];
        let nonce = b"challenge".to_vec();
        let keys = [
            ProofKey::new(ProofType::ServerIdentity, ProofSubject::Server),
            ProofKey::new(ProofType::UserAuthorization, ProofSubject::User),
            ProofKey::new(ProofType::PhoneDeviceAttestation, ProofSubject::PhoneDevice),
            ProofKey::new(ProofType::TeeAttestation, ProofSubject::PhoneDevice),
            ProofKey::new(ProofType::Fido2WebAuthnAssertion, ProofSubject::User),
            ProofKey::new(ProofType::TpmQuote, ProofSubject::Server),
        ];
        let requirements = keys
            .iter()
            .map(|key| requirement(*key, b"subject-binding"))
            .collect::<Vec<_>>();
        let policy = fixture_policy(digest, nonce.clone(), requirements);
        let raw = keys
            .iter()
            .map(|key| {
                raw(
                    *key,
                    now,
                    digest,
                    nonce.clone(),
                    ValueBearingPurpose::Transaction,
                    POLICY,
                    b"subject-binding",
                )
            })
            .collect::<Vec<_>>();

        let set = policy
            .composer(&ProofVerifierRegistry::test_fixture())
            .compose(&raw, now)
            .expect("all exact fixture proofs should verify");
        assert_eq!(set.proof_count(), 6);
        for key in keys {
            assert!(set.contains(key));
        }
    }

    #[test]
    fn production_verifier_and_fixture_policy_boundaries_fail_closed() {
        let now = 1_000;
        let digest = [8; 32];
        let key = ProofKey::new(ProofType::TeeAttestation, ProofSubject::Server);
        let fixture_policy =
            fixture_policy(digest, b"nonce".to_vec(), vec![requirement(key, b"b")]);
        let evidence = raw(
            key,
            now,
            digest,
            b"nonce".to_vec(),
            ValueBearingPurpose::Transaction,
            POLICY,
            b"b",
        );

        let production_error = fixture_policy
            .composer(&ProofVerifierRegistry::production())
            .compose(std::slice::from_ref(&evidence), now)
            .expect_err("production registry has no provider");
        assert!(matches!(
            production_error,
            ProofSetError::Verification(ProofVerificationFailure {
                error: ProofVerificationError::UnsupportedProductionVerifier,
                ..
            })
        ));

        let production_policy = ProofSetPolicy::new(
            POLICY,
            digest,
            ValueBearingPurpose::Transaction,
            b"nonce".to_vec(),
            b"replay".to_vec(),
            100,
            5,
            vec![requirement(key, b"b")],
        )
        .expect("valid production policy");
        let fixture_error = production_policy
            .composer(&ProofVerifierRegistry::test_fixture())
            .compose(&[evidence], now)
            .expect_err("fixtures cannot satisfy production policy");
        assert!(matches!(
            fixture_error,
            ProofSetError::Verification(ProofVerificationFailure {
                error: ProofVerificationError::FixtureNotAllowedByProductionPolicy,
                ..
            })
        ));
    }

    #[test]
    fn mismatches_and_type_substitution_are_diagnosed_without_raw_evidence() {
        let now = 1_000;
        let digest = [9; 32];
        let key = ProofKey::new(ProofType::ServerIdentity, ProofSubject::Server);
        let policy = fixture_policy(
            digest,
            b"nonce".to_vec(),
            vec![requirement(key, b"binding")],
        );
        let registry = ProofVerifierRegistry::test_fixture();

        let wrong_nonce = RawProofEvidence::test_fixture(
            TestProofEvidenceInput::new(key, digest, ValueBearingPurpose::Transaction)
                .with_issuer(ISSUER)
                .with_trust_identity(ROOT)
                .with_nonce(b"wrong-nonce".to_vec())
                .with_policy_id(POLICY)
                .with_subject_binding(b"binding".to_vec())
                .with_times(now - 1, now + 99, 100)
                .with_replay_identity(b"replay".to_vec()),
        );
        let error = policy
            .composer(&registry)
            .compose(&[wrong_nonce], now)
            .expect_err("nonce mismatch must fail");
        assert!(matches!(
            error,
            ProofSetError::Verification(ProofVerificationFailure {
                error: ProofVerificationError::WrongNonce,
                ..
            })
        ));

        let substituted = RawProofEvidence::test_fixture(
            TestProofEvidenceInput::new(key, digest, ValueBearingPurpose::Transaction)
                .with_key(ProofKey::new(
                    ProofType::Fido2WebAuthnAssertion,
                    ProofSubject::User,
                ))
                .with_issuer(ISSUER)
                .with_trust_identity(ROOT)
                .with_nonce(b"nonce".to_vec())
                .with_policy_id(POLICY)
                .with_subject_binding(b"binding".to_vec())
                .with_times(now - 1, now + 99, 100)
                .with_replay_identity(b"replay".to_vec()),
        );
        assert!(matches!(
            policy.composer(&registry).compose(&[substituted], now),
            Err(ProofSetError::TypeSubstitution { .. })
        ));
    }

    #[test]
    fn stale_future_malformed_and_bound_errors_fail_closed() {
        let digest = [10; 32];
        let key = ProofKey::new(ProofType::TpmQuote, ProofSubject::Server);
        let policy = fixture_policy(digest, b"nonce".to_vec(), vec![requirement(key, b"b")]);
        let registry = ProofVerifierRegistry::test_fixture();

        let stale = RawProofEvidence::test_fixture(
            TestProofEvidenceInput::new(key, digest, ValueBearingPurpose::Transaction)
                .with_issuer(ISSUER)
                .with_trust_identity(ROOT)
                .with_nonce(b"nonce".to_vec())
                .with_policy_id(POLICY)
                .with_subject_binding(b"b".to_vec())
                .with_times(1, 10, 100)
                .with_replay_identity(b"replay".to_vec()),
        );
        assert!(matches!(
            policy.composer(&registry).compose(&[stale], 100),
            Err(ProofSetError::Verification(ProofVerificationFailure {
                error: ProofVerificationError::Stale,
                ..
            }))
        ));

        let future = RawProofEvidence::test_fixture(
            TestProofEvidenceInput::new(key, digest, ValueBearingPurpose::Transaction)
                .with_issuer(ISSUER)
                .with_trust_identity(ROOT)
                .with_nonce(b"nonce".to_vec())
                .with_policy_id(POLICY)
                .with_subject_binding(b"b".to_vec())
                .with_times(200, 300, 100)
                .with_replay_identity(b"replay".to_vec()),
        );
        assert!(matches!(
            policy.composer(&registry).compose(&[future], 100),
            Err(ProofSetError::Verification(ProofVerificationFailure {
                error: ProofVerificationError::FutureDated,
                ..
            }))
        ));

        let malformed = RawProofEvidence::new(
            key,
            ISSUER,
            ROOT,
            b"nonce".to_vec(),
            digest,
            ValueBearingPurpose::Transaction,
            POLICY,
            b"b".to_vec(),
            90,
            110,
            100,
            b"replay".to_vec(),
            Vec::new(),
        )
        .expect("bounded malformed raw input is retained for verification");
        assert!(matches!(
            policy.composer(&registry).compose(&[malformed], 100),
            Err(ProofSetError::Verification(ProofVerificationFailure {
                error: ProofVerificationError::MalformedEvidence,
                ..
            }))
        ));

        assert!(matches!(
            RawProofEvidence::new(
                key,
                ISSUER,
                ROOT,
                vec![0; MAX_NONCE_BYTES + 1],
                digest,
                ValueBearingPurpose::Transaction,
                POLICY,
                b"b".to_vec(),
                90,
                110,
                100,
                b"replay".to_vec(),
                vec![1],
            ),
            Err(ProofInputError::ValueTooLarge)
        ));
        assert!(matches!(
            RawProofEvidence::new(
                key,
                ISSUER,
                ROOT,
                b"nonce".to_vec(),
                digest,
                ValueBearingPurpose::Transaction,
                POLICY,
                b"b".to_vec(),
                90,
                110,
                100,
                b"replay".to_vec(),
                vec![1; MAX_EVIDENCE_BYTES + 1],
            ),
            Err(ProofInputError::ValueTooLarge)
        ));

        let too_many = vec![
            RawProofEvidence::test_fixture(
                TestProofEvidenceInput::new(key, digest, ValueBearingPurpose::Transaction)
                    .with_issuer(ISSUER)
                    .with_trust_identity(ROOT)
                    .with_nonce(b"nonce".to_vec())
                    .with_policy_id(POLICY)
                    .with_subject_binding(b"b".to_vec())
                    .with_times(90, 110, 100)
                    .with_replay_identity(b"replay".to_vec()),
            );
            MAX_PROOF_COUNT + 1
        ];
        assert!(matches!(
            policy.composer(&registry).compose(&too_many, 100),
            Err(ProofSetError::ProofCountExceeded)
        ));
    }

    #[test]
    fn independent_context_mismatches_are_typed_and_fail_closed() {
        let now = 1_000;
        let digest = [13; 32];
        let key = ProofKey::new(ProofType::TeeAttestation, ProofSubject::Server);
        let policy = fixture_policy(
            digest,
            b"nonce".to_vec(),
            vec![requirement(key, b"binding")],
        );
        let registry = ProofVerifierRegistry::test_fixture();

        let compose_error = |raw: RawProofEvidence| {
            policy
                .composer(&registry)
                .compose(&[raw], now)
                .expect_err("context mismatch must fail")
        };

        let wrong_operation = RawProofEvidence::test_fixture(
            TestProofEvidenceInput::new(key, digest, ValueBearingPurpose::Transaction)
                .with_issuer(ISSUER)
                .with_trust_identity(ROOT)
                .with_nonce(b"nonce".to_vec())
                .with_operation_digest([14; 32])
                .with_policy_id(POLICY)
                .with_subject_binding(b"binding".to_vec())
                .with_times(now - 1, now + 99, 100)
                .with_replay_identity(b"replay".to_vec()),
        );
        assert!(matches!(
            compose_error(wrong_operation),
            ProofSetError::Verification(ProofVerificationFailure {
                error: ProofVerificationError::WrongOperationDigest,
                ..
            })
        ));

        let wrong_purpose = RawProofEvidence::test_fixture(
            TestProofEvidenceInput::new(key, digest, ValueBearingPurpose::Transaction)
                .with_issuer(ISSUER)
                .with_trust_identity(ROOT)
                .with_nonce(b"nonce".to_vec())
                .with_purpose(ValueBearingPurpose::Authorization)
                .with_policy_id(POLICY)
                .with_subject_binding(b"binding".to_vec())
                .with_times(now - 1, now + 99, 100)
                .with_replay_identity(b"replay".to_vec()),
        );
        assert!(matches!(
            compose_error(wrong_purpose),
            ProofSetError::Verification(ProofVerificationFailure {
                error: ProofVerificationError::WrongPurpose,
                ..
            })
        ));

        let wrong_policy = RawProofEvidence::test_fixture(
            TestProofEvidenceInput::new(key, digest, ValueBearingPurpose::Transaction)
                .with_issuer(ISSUER)
                .with_trust_identity(ROOT)
                .with_nonce(b"nonce".to_vec())
                .with_policy_id("different-policy")
                .with_subject_binding(b"binding".to_vec())
                .with_times(now - 1, now + 99, 100)
                .with_replay_identity(b"replay".to_vec()),
        );
        assert!(matches!(
            compose_error(wrong_policy),
            ProofSetError::Verification(ProofVerificationFailure {
                error: ProofVerificationError::WrongPolicy,
                ..
            })
        ));

        let wrong_issuer = RawProofEvidence::test_fixture(
            TestProofEvidenceInput::new(key, digest, ValueBearingPurpose::Transaction)
                .with_issuer("different-issuer")
                .with_trust_identity(ROOT)
                .with_nonce(b"nonce".to_vec())
                .with_policy_id(POLICY)
                .with_subject_binding(b"binding".to_vec())
                .with_times(now - 1, now + 99, 100)
                .with_replay_identity(b"replay".to_vec()),
        );
        assert!(matches!(
            compose_error(wrong_issuer),
            ProofSetError::Verification(ProofVerificationFailure {
                error: ProofVerificationError::WrongIssuer,
                ..
            })
        ));

        let wrong_root = RawProofEvidence::test_fixture(
            TestProofEvidenceInput::new(key, digest, ValueBearingPurpose::Transaction)
                .with_issuer(ISSUER)
                .with_trust_identity("different-root")
                .with_nonce(b"nonce".to_vec())
                .with_policy_id(POLICY)
                .with_subject_binding(b"binding".to_vec())
                .with_times(now - 1, now + 99, 100)
                .with_replay_identity(b"replay".to_vec()),
        );
        assert!(matches!(
            compose_error(wrong_root),
            ProofSetError::Verification(ProofVerificationFailure {
                error: ProofVerificationError::WrongTrustIdentity,
                ..
            })
        ));

        let wrong_binding = RawProofEvidence::test_fixture(
            TestProofEvidenceInput::new(key, digest, ValueBearingPurpose::Transaction)
                .with_issuer(ISSUER)
                .with_trust_identity(ROOT)
                .with_nonce(b"nonce".to_vec())
                .with_policy_id(POLICY)
                .with_subject_binding(b"different-binding".to_vec())
                .with_times(now - 1, now + 99, 100)
                .with_replay_identity(b"replay".to_vec()),
        );
        assert!(matches!(
            compose_error(wrong_binding),
            ProofSetError::Verification(ProofVerificationFailure {
                error: ProofVerificationError::WrongSubjectBinding,
                ..
            })
        ));

        let wrong_replay = RawProofEvidence::test_fixture(
            TestProofEvidenceInput::new(key, digest, ValueBearingPurpose::Transaction)
                .with_issuer(ISSUER)
                .with_trust_identity(ROOT)
                .with_nonce(b"nonce".to_vec())
                .with_policy_id(POLICY)
                .with_subject_binding(b"binding".to_vec())
                .with_times(now - 1, now + 99, 100)
                .with_replay_identity(b"different-replay".to_vec()),
        );
        assert!(matches!(
            compose_error(wrong_replay),
            ProofSetError::Verification(ProofVerificationFailure {
                error: ProofVerificationError::WrongReplayIdentity,
                ..
            })
        ));

        let wrong_subject = RawProofEvidence::test_fixture(
            TestProofEvidenceInput::new(
                ProofKey::new(ProofType::TeeAttestation, ProofSubject::PhoneDevice),
                digest,
                ValueBearingPurpose::Transaction,
            )
            .with_issuer(ISSUER)
            .with_trust_identity(ROOT)
            .with_nonce(b"nonce".to_vec())
            .with_policy_id(POLICY)
            .with_subject_binding(b"binding".to_vec())
            .with_times(now - 1, now + 99, 100)
            .with_replay_identity(b"replay".to_vec()),
        );
        let wrong_subject_failure = registry
            .verify_one(
                &wrong_subject,
                policy.requirements().first().expect("requirement"),
                &policy,
                now,
            )
            .expect_err("wrong subject must be diagnosed independently");
        assert_eq!(
            wrong_subject_failure.error,
            ProofVerificationError::WrongSubject
        );
    }

    #[test]
    fn canonical_context_and_proof_set_are_domain_separated_and_order_independent() {
        let now = 1_000;
        let digest = [11; 32];
        let key_a = ProofKey::new(ProofType::ServerIdentity, ProofSubject::Server);
        let key_b = ProofKey::new(ProofType::UserAuthorization, ProofSubject::User);
        let policy_a = fixture_policy(
            digest,
            b"nonce".to_vec(),
            vec![requirement(key_a, b"a"), requirement(key_b, b"b")],
        );
        let policy_b = fixture_policy(
            digest,
            b"different".to_vec(),
            vec![requirement(key_a, b"a"), requirement(key_b, b"b")],
        );
        let raw_a = raw(
            key_a,
            now,
            digest,
            b"nonce".to_vec(),
            ValueBearingPurpose::Transaction,
            POLICY,
            b"a",
        );
        let raw_b = raw(
            key_b,
            now,
            digest,
            b"nonce".to_vec(),
            ValueBearingPurpose::Transaction,
            POLICY,
            b"b",
        );
        assert_ne!(
            raw_a.context().canonical_digest(),
            RawProofEvidence::test_fixture(
                TestProofEvidenceInput::new(key_a, digest, ValueBearingPurpose::Authorization,)
                    .with_issuer(ISSUER)
                    .with_trust_identity(ROOT)
                    .with_nonce(b"nonce".to_vec())
                    .with_policy_id(POLICY)
                    .with_subject_binding(b"a".to_vec())
                    .with_times(now - 1, now + 99, 100)
                    .with_replay_identity(b"replay".to_vec()),
            )
            .context()
            .canonical_digest()
        );
        let registry = ProofVerifierRegistry::test_fixture();
        let set_one = policy_a
            .composer(&registry)
            .compose(&[raw_a.clone(), raw_b.clone()], now)
            .expect("ordered set should verify");
        let set_two = policy_a
            .composer(&registry)
            .compose(&[raw_b, raw_a], now)
            .expect("reordered set should verify");
        assert_eq!(set_one.canonical_digest(), set_two.canonical_digest());
        assert_ne!(policy_a.nonce(), policy_b.nonce());
    }

    #[test]
    fn policy_digest_binds_exact_fields_and_requirement_order_is_canonical() {
        let key_a = ProofKey::new(ProofType::ServerIdentity, ProofSubject::Server);
        let key_b = ProofKey::new(ProofType::UserAuthorization, ProofSubject::User);
        let requirement_a = requirement(key_a, b"a");
        let requirement_b = requirement(key_b, b"b");
        let policy = |operation_digest,
                      purpose,
                      nonce,
                      replay_identity,
                      max_age_secs,
                      max_future_skew_secs,
                      requirements| {
            ProofSetPolicy::test_fixture(
                POLICY,
                operation_digest,
                purpose,
                nonce,
                replay_identity,
                max_age_secs,
                max_future_skew_secs,
                requirements,
            )
            .expect("valid fixture policy")
        };

        let base = policy(
            [21; 32],
            ValueBearingPurpose::Transaction,
            b"nonce".to_vec(),
            b"replay".to_vec(),
            100,
            5,
            vec![requirement_a.clone(), requirement_b.clone()],
        );
        let reordered = policy(
            [21; 32],
            ValueBearingPurpose::Transaction,
            b"nonce".to_vec(),
            b"replay".to_vec(),
            100,
            5,
            vec![requirement_b.clone(), requirement_a.clone()],
        );
        assert_eq!(base.canonical_digest(), reordered.canonical_digest());

        assert_ne!(
            base.canonical_digest(),
            policy(
                [21; 32],
                ValueBearingPurpose::Transaction,
                b"nonce".to_vec(),
                b"replay".to_vec(),
                100,
                5,
                vec![requirement_a.clone()],
            )
            .canonical_digest()
        );
        assert_ne!(
            base.canonical_digest(),
            policy(
                [21; 32],
                ValueBearingPurpose::Transaction,
                b"nonce".to_vec(),
                b"replay".to_vec(),
                100,
                5,
                vec![
                    ProofRequirement::new(key_a, "different-issuer", ROOT, b"a".to_vec())
                        .expect("valid issuer variant"),
                    requirement_b.clone(),
                ],
            )
            .canonical_digest()
        );
        assert_ne!(
            base.canonical_digest(),
            policy(
                [21; 32],
                ValueBearingPurpose::Transaction,
                b"nonce".to_vec(),
                b"replay".to_vec(),
                100,
                5,
                vec![
                    ProofRequirement::new(key_a, ISSUER, "different-root", b"a".to_vec())
                        .expect("valid root variant"),
                    requirement_b.clone(),
                ],
            )
            .canonical_digest()
        );
        assert_ne!(
            base.canonical_digest(),
            policy(
                [21; 32],
                ValueBearingPurpose::Transaction,
                b"nonce".to_vec(),
                b"replay".to_vec(),
                100,
                5,
                vec![
                    ProofRequirement::new(key_a, ISSUER, ROOT, b"different-binding".to_vec())
                        .expect("valid subject-binding variant"),
                    requirement_b.clone(),
                ],
            )
            .canonical_digest()
        );

        for variant in [
            policy(
                [22; 32],
                ValueBearingPurpose::Transaction,
                b"nonce".to_vec(),
                b"replay".to_vec(),
                100,
                5,
                vec![requirement_a.clone(), requirement_b.clone()],
            ),
            policy(
                [21; 32],
                ValueBearingPurpose::Authorization,
                b"nonce".to_vec(),
                b"replay".to_vec(),
                100,
                5,
                vec![requirement_a.clone(), requirement_b.clone()],
            ),
            policy(
                [21; 32],
                ValueBearingPurpose::Transaction,
                b"different-nonce".to_vec(),
                b"replay".to_vec(),
                100,
                5,
                vec![requirement_a.clone(), requirement_b.clone()],
            ),
            policy(
                [21; 32],
                ValueBearingPurpose::Transaction,
                b"nonce".to_vec(),
                b"different-replay".to_vec(),
                100,
                5,
                vec![requirement_a.clone(), requirement_b.clone()],
            ),
            policy(
                [21; 32],
                ValueBearingPurpose::Transaction,
                b"nonce".to_vec(),
                b"replay".to_vec(),
                99,
                5,
                vec![requirement_a.clone(), requirement_b.clone()],
            ),
            policy(
                [21; 32],
                ValueBearingPurpose::Transaction,
                b"nonce".to_vec(),
                b"replay".to_vec(),
                100,
                6,
                vec![requirement_a, requirement_b],
            ),
        ] {
            assert_ne!(base.canonical_digest(), variant.canonical_digest());
        }
    }

    #[test]
    fn duplicate_conflicting_and_partial_sets_are_rejected() {
        let now = 1_000;
        let digest = [12; 32];
        let key_a = ProofKey::new(ProofType::ServerIdentity, ProofSubject::Server);
        let key_b = ProofKey::new(ProofType::TpmQuote, ProofSubject::Server);
        assert!(matches!(
            ProofSetPolicy::test_fixture(
                POLICY,
                digest,
                ValueBearingPurpose::Transaction,
                b"nonce".to_vec(),
                b"replay".to_vec(),
                100,
                5,
                Vec::new(),
            ),
            Err(ProofInputError::EmptyRequirementSet)
        ));
        let policy = fixture_policy(
            digest,
            b"nonce".to_vec(),
            vec![requirement(key_a, b"a"), requirement(key_b, b"b")],
        );
        let first = raw(
            key_a,
            now,
            digest,
            b"nonce".to_vec(),
            ValueBearingPurpose::Transaction,
            POLICY,
            b"a",
        );
        let duplicate = first.clone();
        assert!(matches!(
            policy
                .composer(&ProofVerifierRegistry::test_fixture())
                .compose(&[first.clone(), duplicate], now),
            Err(ProofSetError::DuplicateProof { .. })
        ));

        let conflicting = RawProofEvidence::test_fixture(
            TestProofEvidenceInput::new(key_a, digest, ValueBearingPurpose::Transaction)
                .with_issuer(ISSUER)
                .with_trust_identity(ROOT)
                .with_nonce(b"nonce".to_vec())
                .with_policy_id(POLICY)
                .with_subject_binding(b"different-binding".to_vec())
                .with_times(now - 1, now + 99, 100)
                .with_replay_identity(b"replay".to_vec()),
        );
        assert!(matches!(
            policy
                .composer(&ProofVerifierRegistry::test_fixture())
                .compose(&[first.clone(), conflicting], now),
            Err(ProofSetError::ConflictingProof { .. })
        ));

        assert!(matches!(
            policy
                .composer(&ProofVerifierRegistry::test_fixture())
                .compose(&[first], now),
            Err(ProofSetError::MissingRequiredProof { key }) if key == key_b
        ));
    }

    #[test]
    fn raw_evidence_debug_does_not_expose_evidence_bytes() {
        let raw = RawProofEvidence::test_fixture(
            TestProofEvidenceInput::new(
                ProofKey::new(ProofType::ServerIdentity, ProofSubject::Server),
                [15; 32],
                ValueBearingPurpose::Transaction,
            )
            .with_issuer(ISSUER)
            .with_trust_identity(ROOT)
            .with_nonce(b"nonce".to_vec())
            .with_policy_id(POLICY)
            .with_subject_binding(b"binding".to_vec())
            .with_times(999, 1_099, 100)
            .with_replay_identity(b"replay".to_vec()),
        );
        let diagnostic = format!("{raw:?}");
        assert!(!diagnostic.contains("CONXIAN-TEST-PROOF/v1:"));
        assert!(diagnostic.contains("evidence_len"));
        assert!(diagnostic.contains("evidence_digest"));
    }
}
