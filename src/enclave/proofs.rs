//! Bounded, fail-closed verification for independent external proofs.
//!
//! This module is an evidence framework, not a provider implementation. The
//! production registry contains one explicit unavailable verifier for each
//! semantic proof kind. No structural, simulated, or software verifier can
//! satisfy the production registry.

use crate::enclave::replay_guard::{ReplayGuard, ReplayGuardError};
use crate::enclave::{EnclaveManager, ValueBearingSignRequest, ValueBearingSignResponse};
use crate::protocol::intent::SwapIntent;
use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

/// Current version of the independent proof envelope.
pub const PROOF_ENVELOPE_VERSION: u16 = 1;

/// Domain used by canonical proof-envelope encodings.
pub const PROOF_ENVELOPE_DOMAIN: &str = "CONXIAN-INDEPENDENT-PROOF/v1";

/// Domain used by canonical proof-context bindings.
pub const PROOF_CONTEXT_DOMAIN: &str = "CONXIAN-PROOF-CONTEXT/v1";

/// Domain used by replay keys generated for proof envelopes.
pub const PROOF_REPLAY_DOMAIN: &str = "CONXIAN-PROOF-REPLAY/v1";

/// Settlement purpose and audience used by the additive enclave-side helper.
pub const SETTLEMENT_PROOF_PURPOSE: &str = "SETTLEMENT";
pub const SETTLEMENT_PROOF_AUDIENCE: &str = "conxian/settlement/v1";

pub const SERVER_PROOF_VERIFIER_ID: &str = "conxian.proof.server.unavailable.v1";
pub const USER_PROOF_VERIFIER_ID: &str = "conxian.proof.user.unavailable.v1";
pub const PHONE_PROOF_VERIFIER_ID: &str = "conxian.proof.phone.unavailable.v1";
pub const TEE_PROOF_VERIFIER_ID: &str = "conxian.proof.tee.unavailable.v1";
pub const FIDO_PROOF_VERIFIER_ID: &str = "conxian.proof.fido.unavailable.v1";
pub const TPM_PROOF_VERIFIER_ID: &str = "conxian.proof.tpm.unavailable.v1";

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_NONCE_BYTES: usize = 128;
const MAX_EVIDENCE_BYTES: usize = 16 * 1024;
const MAX_PROOF_LIFETIME_SECS: u64 = 24 * 60 * 60;
const MAX_PROOF_BUNDLE_SIZE: usize = 6;
const DEFAULT_MAX_PROOF_AGE_SECS: u64 = 5 * 60;
const DEFAULT_MAX_PROOF_FUTURE_SKEW_SECS: u64 = 30;
const MAX_CONTEXT_AGE_SECS: u64 = 24 * 60 * 60;
const MAX_CONTEXT_FUTURE_SKEW_SECS: u64 = 15 * 60;

fn invalid_payload() -> ConclaveError {
    ConclaveError::InvalidPayload
}

fn proof_verification_failed() -> ConclaveError {
    ConclaveError::EnclaveFailure("independent proof verification failed".to_string())
}

fn proof_verifier_unavailable() -> ConclaveError {
    ConclaveError::Unsupported("independent proof verifier is unavailable".to_string())
}

fn validate_identifier(value: &str) -> ConclaveResult<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(invalid_payload());
    }

    Ok(())
}

fn validate_non_empty_bounded(value: &[u8], maximum: usize) -> ConclaveResult<()> {
    if value.is_empty() || value.len() > maximum {
        return Err(invalid_payload());
    }

    Ok(())
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) -> ConclaveResult<()> {
    let length = u32::try_from(value.len()).map_err(|_| invalid_payload())?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn append_identifier(output: &mut Vec<u8>, value: &str) -> ConclaveResult<()> {
    append_len_prefixed(output, value.as_bytes())
}

/// Semantic proof kinds are intentionally non-substitutable.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProofKind {
    Server,
    User,
    Phone,
    Tee,
    Fido,
    Tpm,
}

impl ProofKind {
    pub const fn all() -> [Self; 6] {
        [
            Self::Server,
            Self::User,
            Self::Phone,
            Self::Tee,
            Self::Fido,
            Self::Tpm,
        ]
    }

    pub const fn canonical_tag(self) -> u8 {
        match self {
            Self::Server => 1,
            Self::User => 2,
            Self::Phone => 3,
            Self::Tee => 4,
            Self::Fido => 5,
            Self::Tpm => 6,
        }
    }

    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::User => "user",
            Self::Phone => "phone",
            Self::Tee => "tee",
            Self::Fido => "fido",
            Self::Tpm => "tpm",
        }
    }

    pub const fn production_verifier_id(self) -> &'static str {
        match self {
            Self::Server => SERVER_PROOF_VERIFIER_ID,
            Self::User => USER_PROOF_VERIFIER_ID,
            Self::Phone => PHONE_PROOF_VERIFIER_ID,
            Self::Tee => TEE_PROOF_VERIFIER_ID,
            Self::Fido => FIDO_PROOF_VERIFIER_ID,
            Self::Tpm => TPM_PROOF_VERIFIER_ID,
        }
    }
}

/// A versioned proof envelope received from an external provider.
///
/// The fields are public for transport ergonomics, but callers must pass the
/// envelope through [`ProofVerifierRegistry::verify_bundle`] before treating
/// it as evidence. Deserialization rejects unknown object fields and
/// verification rechecks every bound and version because public fields may be
/// mutated after construction.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProofEnvelope {
    pub version: u16,
    pub kind: ProofKind,
    pub proof_id: String,
    pub verifier_id: String,
    pub operation_digest: [u8; 32],
    pub purpose: String,
    pub audience: String,
    pub nonce: Vec<u8>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub evidence: Vec<u8>,
}

impl fmt::Debug for ProofEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofEnvelope")
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("proof_id", &self.proof_id)
            .field("verifier_id", &self.verifier_id)
            .field("operation_digest", &self.operation_digest)
            .field("purpose", &self.purpose)
            .field("audience", &self.audience)
            .field("nonce_len", &self.nonce.len())
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("evidence_len", &self.evidence.len())
            .finish()
    }
}

impl ProofEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: ProofKind,
        proof_id: impl Into<String>,
        verifier_id: impl Into<String>,
        operation_digest: [u8; 32],
        purpose: impl Into<String>,
        audience: impl Into<String>,
        nonce: Vec<u8>,
        issued_at: u64,
        expires_at: u64,
        evidence: Vec<u8>,
    ) -> ConclaveResult<Self> {
        Self::new_with_version(
            PROOF_ENVELOPE_VERSION,
            kind,
            proof_id,
            verifier_id,
            operation_digest,
            purpose,
            audience,
            nonce,
            issued_at,
            expires_at,
            evidence,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_version(
        version: u16,
        kind: ProofKind,
        proof_id: impl Into<String>,
        verifier_id: impl Into<String>,
        operation_digest: [u8; 32],
        purpose: impl Into<String>,
        audience: impl Into<String>,
        nonce: Vec<u8>,
        issued_at: u64,
        expires_at: u64,
        evidence: Vec<u8>,
    ) -> ConclaveResult<Self> {
        let envelope = Self {
            version,
            kind,
            proof_id: proof_id.into(),
            verifier_id: verifier_id.into(),
            operation_digest,
            purpose: purpose.into(),
            audience: audience.into(),
            nonce,
            issued_at,
            expires_at,
            evidence,
        };
        envelope.validate_shape()?;
        Ok(envelope)
    }

    pub fn validate_shape(&self) -> ConclaveResult<()> {
        if self.version != PROOF_ENVELOPE_VERSION {
            return Err(invalid_payload());
        }
        validate_identifier(&self.proof_id)?;
        validate_identifier(&self.verifier_id)?;
        validate_identifier(&self.purpose)?;
        validate_identifier(&self.audience)?;
        validate_non_empty_bounded(&self.nonce, MAX_NONCE_BYTES)?;
        validate_non_empty_bounded(&self.evidence, MAX_EVIDENCE_BYTES)?;

        let lifetime = self
            .expires_at
            .checked_sub(self.issued_at)
            .ok_or_else(invalid_payload)?;
        if lifetime > MAX_PROOF_LIFETIME_SECS {
            return Err(invalid_payload());
        }

        Ok(())
    }

    pub fn canonical_bytes(&self) -> ConclaveResult<Vec<u8>> {
        self.validate_shape()?;

        let mut output = Vec::new();
        append_len_prefixed(&mut output, PROOF_ENVELOPE_DOMAIN.as_bytes())?;
        output.extend_from_slice(&self.version.to_be_bytes());
        output.push(self.kind.canonical_tag());
        append_identifier(&mut output, &self.proof_id)?;
        append_identifier(&mut output, &self.verifier_id)?;
        output.extend_from_slice(&self.operation_digest);
        append_identifier(&mut output, &self.purpose)?;
        append_identifier(&mut output, &self.audience)?;
        append_len_prefixed(&mut output, &self.nonce)?;
        output.extend_from_slice(&self.issued_at.to_be_bytes());
        output.extend_from_slice(&self.expires_at.to_be_bytes());
        append_len_prefixed(&mut output, &self.evidence)?;
        Ok(output)
    }

    pub fn digest(&self) -> ConclaveResult<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }

    pub fn replay_key(&self) -> ConclaveResult<ProofReplayKey> {
        ProofReplayKey::from_envelope(self)
    }
}

/// Exact operation/purpose/audience/nonce binding and freshness context.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProofVerificationContext {
    pub operation_digest: [u8; 32],
    pub purpose: String,
    pub audience: String,
    pub nonce: Vec<u8>,
    pub now_secs: u64,
    pub max_age_secs: u64,
    pub max_future_skew_secs: u64,
}

impl fmt::Debug for ProofVerificationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofVerificationContext")
            .field("operation_digest", &self.operation_digest)
            .field("purpose", &self.purpose)
            .field("audience", &self.audience)
            .field("nonce_len", &self.nonce.len())
            .field("now_secs", &self.now_secs)
            .field("max_age_secs", &self.max_age_secs)
            .field("max_future_skew_secs", &self.max_future_skew_secs)
            .finish()
    }
}

impl ProofVerificationContext {
    pub fn new(
        operation_digest: [u8; 32],
        purpose: impl Into<String>,
        audience: impl Into<String>,
        nonce: Vec<u8>,
        now_secs: u64,
    ) -> ConclaveResult<Self> {
        Self {
            operation_digest,
            purpose: purpose.into(),
            audience: audience.into(),
            nonce,
            now_secs,
            max_age_secs: DEFAULT_MAX_PROOF_AGE_SECS,
            max_future_skew_secs: DEFAULT_MAX_PROOF_FUTURE_SKEW_SECS,
        }
        .validate()
    }

    pub fn for_settlement(
        intent: &SwapIntent,
        nonce: Vec<u8>,
        now_secs: u64,
    ) -> ConclaveResult<Self> {
        let canonical_hash = intent.canonical_hash();
        if intent.signable_hash != canonical_hash {
            return Err(ConclaveError::EnclaveFailure(
                "settlement proof context requires the canonical swap intent hash".to_string(),
            ));
        }
        let operation_digest: [u8; 32] = intent
            .canonical_hash()
            .try_into()
            .map_err(|_| invalid_payload())?;
        Self::new(
            operation_digest,
            SETTLEMENT_PROOF_PURPOSE,
            SETTLEMENT_PROOF_AUDIENCE,
            nonce,
            now_secs,
        )
    }

    pub fn with_freshness_window(
        mut self,
        max_age_secs: u64,
        max_future_skew_secs: u64,
    ) -> ConclaveResult<Self> {
        if max_age_secs > MAX_CONTEXT_AGE_SECS
            || max_future_skew_secs > MAX_CONTEXT_FUTURE_SKEW_SECS
        {
            return Err(ConclaveError::Unsupported(
                "proof freshness window exceeds the bounded verification policy".to_string(),
            ));
        }
        self.max_age_secs = max_age_secs;
        self.max_future_skew_secs = max_future_skew_secs;
        self.validate()
    }

    pub fn validate(&self) -> ConclaveResult<Self> {
        validate_identifier(&self.purpose)?;
        validate_identifier(&self.audience)?;
        validate_non_empty_bounded(&self.nonce, MAX_NONCE_BYTES)?;
        if self.max_age_secs > MAX_CONTEXT_AGE_SECS
            || self.max_future_skew_secs > MAX_CONTEXT_FUTURE_SKEW_SECS
        {
            return Err(invalid_payload());
        }
        Ok(self.clone())
    }

    pub fn binding_digest(&self) -> ConclaveResult<[u8; 32]> {
        self.validate()?;
        let mut output = Vec::new();
        append_len_prefixed(&mut output, PROOF_CONTEXT_DOMAIN.as_bytes())?;
        output.extend_from_slice(&self.operation_digest);
        append_identifier(&mut output, &self.purpose)?;
        append_identifier(&mut output, &self.audience)?;
        append_len_prefixed(&mut output, &self.nonce)?;
        Ok(Sha256::digest(output).into())
    }

    fn verify_envelope_binding(&self, envelope: &ProofEnvelope) -> ConclaveResult<()> {
        self.validate()?;
        envelope.validate_shape()?;

        if envelope.operation_digest != self.operation_digest
            || envelope.purpose != self.purpose
            || envelope.audience != self.audience
            || envelope.nonce != self.nonce
        {
            return Err(proof_verification_failed());
        }

        let future_limit = self
            .now_secs
            .checked_add(self.max_future_skew_secs)
            .ok_or_else(invalid_payload)?;
        if envelope.issued_at > future_limit {
            return Err(proof_verification_failed());
        }

        if envelope.issued_at <= self.now_secs {
            let age = self
                .now_secs
                .checked_sub(envelope.issued_at)
                .ok_or_else(proof_verification_failed)?;
            if age > self.max_age_secs {
                return Err(proof_verification_failed());
            }
        }
        if envelope.expires_at < self.now_secs {
            return Err(proof_verification_failed());
        }

        let freshness_limit = envelope
            .issued_at
            .checked_add(self.max_age_secs)
            .ok_or_else(invalid_payload)?;
        if self.now_secs > freshness_limit {
            return Err(proof_verification_failed());
        }

        Ok(())
    }
}

/// A required semantic kind and its exact verifier identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProofRequirement {
    pub kind: ProofKind,
    pub verifier_id: String,
}

impl ProofRequirement {
    pub fn new(kind: ProofKind, verifier_id: impl Into<String>) -> ConclaveResult<Self> {
        let requirement = Self {
            kind,
            verifier_id: verifier_id.into(),
        };
        requirement.validate()?;
        Ok(requirement)
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        validate_identifier(&self.verifier_id)
    }
}

/// Explicit policy for required and unlisted proof kinds.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum UnlistedProofPolicy {
    Reject,
    Allow,
}

impl From<bool> for UnlistedProofPolicy {
    fn from(allow_unlisted: bool) -> Self {
        if allow_unlisted {
            Self::Allow
        } else {
            Self::Reject
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProofPolicy {
    pub required: Vec<ProofRequirement>,
    pub unlisted: UnlistedProofPolicy,
}

impl ProofPolicy {
    pub fn new<U>(required: Vec<ProofRequirement>, unlisted: U) -> ConclaveResult<Self>
    where
        U: Into<UnlistedProofPolicy>,
    {
        let policy = Self {
            required,
            unlisted: unlisted.into(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn production() -> Self {
        Self {
            required: ProofKind::all()
                .into_iter()
                .map(|kind| ProofRequirement {
                    kind,
                    verifier_id: kind.production_verifier_id().to_string(),
                })
                .collect(),
            unlisted: UnlistedProofPolicy::Reject,
        }
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        if self.required.len() > MAX_PROOF_BUNDLE_SIZE {
            return Err(invalid_payload());
        }
        let mut kinds = HashSet::with_capacity(self.required.len());
        for requirement in &self.required {
            requirement.validate()?;
            if !kinds.insert(requirement.kind) {
                return Err(invalid_payload());
            }
        }
        Ok(())
    }

    pub fn requires(&self, kind: ProofKind) -> Option<&ProofRequirement> {
        self.required
            .iter()
            .find(|requirement| requirement.kind == kind)
    }

    pub fn allows_unlisted(&self) -> bool {
        self.unlisted == UnlistedProofPolicy::Allow
    }
}

impl Default for ProofPolicy {
    fn default() -> Self {
        Self::production()
    }
}

/// A collection of envelopes. Construction and verification both reject
/// duplicate semantic kinds and duplicate proof IDs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProofBundle {
    pub proofs: Vec<ProofEnvelope>,
}

impl ProofBundle {
    pub fn new(proofs: Vec<ProofEnvelope>) -> ConclaveResult<Self> {
        let bundle = Self { proofs };
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        if self.proofs.len() > MAX_PROOF_BUNDLE_SIZE {
            return Err(invalid_payload());
        }
        let mut kinds = HashSet::with_capacity(self.proofs.len());
        let mut proof_ids = HashSet::with_capacity(self.proofs.len());
        for proof in &self.proofs {
            proof.validate_shape()?;
            if !kinds.insert(proof.kind) || !proof_ids.insert(proof.proof_id.clone()) {
                return Err(invalid_payload());
            }
        }
        Ok(())
    }

    pub fn push(&mut self, proof: ProofEnvelope) -> ConclaveResult<()> {
        self.proofs.push(proof);
        if let Err(error) = self.validate() {
            let _ = self.proofs.pop();
            return Err(error);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> ConclaveResult<Vec<u8>> {
        self.validate()?;
        let mut proofs = self.proofs.iter().collect::<Vec<_>>();
        proofs.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.proof_id.cmp(&right.proof_id))
                .then_with(|| left.verifier_id.cmp(&right.verifier_id))
        });

        let mut output = Vec::new();
        append_len_prefixed(&mut output, PROOF_ENVELOPE_DOMAIN.as_bytes())?;
        let count = u32::try_from(proofs.len()).map_err(|_| invalid_payload())?;
        output.extend_from_slice(&count.to_be_bytes());
        for proof in proofs {
            append_len_prefixed(&mut output, &proof.canonical_bytes()?)?;
        }
        Ok(output)
    }

    pub fn digest(&self) -> ConclaveResult<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }

    pub fn verify(
        &self,
        registry: &ProofVerifierRegistry,
        policy: &ProofPolicy,
        context: &ProofVerificationContext,
        replay_guard: &ReplayGuard,
    ) -> ConclaveResult<VerifiedProofSet> {
        registry.verify_bundle(self, policy, context, replay_guard)
    }
}

impl TryFrom<Vec<ProofEnvelope>> for ProofBundle {
    type Error = ConclaveError;

    fn try_from(proofs: Vec<ProofEnvelope>) -> Result<Self, Self::Error> {
        Self::new(proofs)
    }
}

/// Status of a verifier entry. Test-only positive status never exists in a
/// production build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofVerifierStatus {
    Unavailable,
    #[cfg(test)]
    TestOnly,
}

/// A verifier for one exact `(ProofKind, verifier_id)` route.
///
/// The production registry is fixed to unavailable entries. This trait is
/// public so a future provider implementation can be added without changing
/// proof envelope or receipt shapes; the current public constructors do not
/// install provider implementations into the production registry.
pub trait ProofVerifier: Send + Sync {
    fn kind(&self) -> ProofKind;
    fn verifier_id(&self) -> &str;
    fn status(&self) -> ProofVerifierStatus;
    fn verify(
        &self,
        envelope: &ProofEnvelope,
        context: &ProofVerificationContext,
    ) -> ConclaveResult<VerifiedProofReceipt>;
}

struct UnavailableProofVerifier {
    kind: ProofKind,
    verifier_id: &'static str,
}

impl ProofVerifier for UnavailableProofVerifier {
    fn kind(&self) -> ProofKind {
        self.kind
    }

    fn verifier_id(&self) -> &str {
        self.verifier_id
    }

    fn status(&self) -> ProofVerifierStatus {
        ProofVerifierStatus::Unavailable
    }

    fn verify(
        &self,
        _envelope: &ProofEnvelope,
        _context: &ProofVerificationContext,
    ) -> ConclaveResult<VerifiedProofReceipt> {
        Err(proof_verifier_unavailable())
    }
}

/// Exact-route production registry. There is no kind-only fallback and no
/// structural verifier path.
pub struct ProofVerifierRegistry {
    verifiers: HashMap<(ProofKind, String), Arc<dyn ProofVerifier>>,
}

impl std::fmt::Debug for ProofVerifierRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProofVerifierRegistry")
            .field("route_count", &self.verifiers.len())
            .finish()
    }
}

impl ProofVerifierRegistry {
    /// Builds the only production registry currently supported. Every real
    /// provider verifier is explicit and unavailable.
    pub fn production() -> Self {
        let mut verifiers: HashMap<(ProofKind, String), Arc<dyn ProofVerifier>> = HashMap::new();
        for kind in ProofKind::all() {
            let verifier_id = kind.production_verifier_id();
            let verifier = UnavailableProofVerifier { kind, verifier_id };
            verifiers.insert((kind, verifier_id.to_string()), Arc::new(verifier));
        }
        Self { verifiers }
    }

    pub fn verifier_status(&self, kind: ProofKind, verifier_id: &str) -> ProofVerifierStatus {
        self.verifiers
            .get(&(kind, verifier_id.to_string()))
            .map_or(ProofVerifierStatus::Unavailable, |verifier| {
                verifier.status()
            })
    }

    pub fn route_count(&self) -> usize {
        self.verifiers.len()
    }

    /// Verifies every supplied proof independently, applies the explicit
    /// required/unlisted policy, and atomically consumes all proof replay keys
    /// only after the complete bundle passes.
    pub fn verify_bundle(
        &self,
        bundle: &ProofBundle,
        policy: &ProofPolicy,
        context: &ProofVerificationContext,
        replay_guard: &ReplayGuard,
    ) -> ConclaveResult<VerifiedProofSet> {
        bundle.validate()?;
        policy.validate()?;
        context.validate()?;

        let mut receipts = Vec::with_capacity(bundle.proofs.len());
        let mut first_error = None;

        for proof in &bundle.proofs {
            let result = self.verify_one(proof, context);
            match result {
                Ok(receipt) => receipts.push(receipt),
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        if let Some(error) = first_error {
            return Err(error);
        }

        self.validate_policy_composition(bundle, policy)?;

        let replay_keys = bundle
            .proofs
            .iter()
            .map(ProofEnvelope::replay_key)
            .collect::<ConclaveResult<Vec<_>>>()?;
        let replay_key_strings = replay_keys
            .iter()
            .map(|key| key.as_str().to_string())
            .collect::<Vec<_>>();
        replay_guard
            .try_check_and_record_batch(replay_key_strings, context.now_secs)
            .map_err(map_replay_error)?;

        VerifiedProofSet::from_verified(context, receipts)
    }

    fn verify_one(
        &self,
        proof: &ProofEnvelope,
        context: &ProofVerificationContext,
    ) -> ConclaveResult<VerifiedProofReceipt> {
        context.verify_envelope_binding(proof)?;
        let key = (proof.kind, proof.verifier_id.clone());
        let verifier = self
            .verifiers
            .get(&key)
            .ok_or_else(proof_verifier_unavailable)?;
        if verifier.kind() != proof.kind || verifier.verifier_id() != proof.verifier_id {
            return Err(proof_verification_failed());
        }
        if verifier.status() == ProofVerifierStatus::Unavailable {
            return Err(proof_verifier_unavailable());
        }

        let receipt = verifier.verify(proof, context)?;
        if !receipt.matches_envelope(proof, context)? {
            return Err(proof_verification_failed());
        }
        Ok(receipt)
    }

    fn validate_policy_composition(
        &self,
        bundle: &ProofBundle,
        policy: &ProofPolicy,
    ) -> ConclaveResult<()> {
        for requirement in &policy.required {
            if !bundle.proofs.iter().any(|proof| {
                proof.kind == requirement.kind && proof.verifier_id == requirement.verifier_id
            }) {
                return Err(ConclaveError::Unsupported(
                    "required independent proof is missing".to_string(),
                ));
            }
        }

        if !policy.allows_unlisted()
            && bundle.proofs.iter().any(|proof| {
                !policy.required.iter().any(|requirement| {
                    proof.kind == requirement.kind && proof.verifier_id == requirement.verifier_id
                })
            })
        {
            return Err(ConclaveError::Unsupported(
                "unlisted independent proof is not permitted by policy".to_string(),
            ));
        }

        Ok(())
    }

    #[cfg(test)]
    fn test_fixture_all_six() -> Self {
        let mut verifiers: HashMap<(ProofKind, String), Arc<dyn ProofVerifier>> = HashMap::new();
        for kind in ProofKind::all() {
            let verifier_id = format!("conxian.test.proof.{}.v1", kind.canonical_name());
            let verifier = FixtureProofVerifier {
                kind,
                verifier_id: verifier_id.clone(),
                expected_evidence: format!("fixture:{}", kind.canonical_name()).into_bytes(),
            };
            verifiers.insert((kind, verifier_id), Arc::new(verifier));
        }
        Self { verifiers }
    }
}

impl Default for ProofVerifierRegistry {
    fn default() -> Self {
        Self::production()
    }
}

fn map_replay_error(error: ReplayGuardError) -> ConclaveError {
    match error {
        ReplayGuardError::Duplicate => {
            ConclaveError::EnclaveFailure("independent proof replay detected".to_string())
        }
        ReplayGuardError::CapacitySaturated => ConclaveError::EnclaveFailure(
            "independent proof replay guard capacity is saturated".to_string(),
        ),
        ReplayGuardError::LockPoisoned => ConclaveError::EnclaveFailure(
            "independent proof replay guard is unavailable".to_string(),
        ),
    }
}

/// Replay key generated from the proof kind, proof ID, operation digest, and
/// nonce under a dedicated domain separator. Raw evidence is never included.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProofReplayKey {
    encoded: String,
    digest: [u8; 32],
}

impl ProofReplayKey {
    pub fn from_envelope(envelope: &ProofEnvelope) -> ConclaveResult<Self> {
        envelope.validate_shape()?;

        let mut canonical = Vec::new();
        append_len_prefixed(&mut canonical, PROOF_REPLAY_DOMAIN.as_bytes())?;
        canonical.push(envelope.kind.canonical_tag());
        append_identifier(&mut canonical, &envelope.proof_id)?;
        append_identifier(&mut canonical, &envelope.verifier_id)?;
        canonical.extend_from_slice(&envelope.operation_digest);
        append_len_prefixed(&mut canonical, &envelope.nonce)?;

        let digest: [u8; 32] = Sha256::digest(canonical).into();
        Ok(Self {
            encoded: format!("{}:{}", PROOF_REPLAY_DOMAIN, hex::encode(digest)),
            digest,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// A verified receipt intentionally retains no raw evidence bytes.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VerifiedProofReceipt {
    kind: ProofKind,
    proof_id: String,
    verifier_id: String,
    operation_digest: [u8; 32],
    purpose: String,
    audience: String,
    nonce_digest: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    verified_at: u64,
    proof_digest: [u8; 32],
    evidence_digest: [u8; 32],
}

impl VerifiedProofReceipt {
    pub fn kind(&self) -> ProofKind {
        self.kind
    }

    pub fn proof_id(&self) -> &str {
        &self.proof_id
    }

    pub fn verifier_id(&self) -> &str {
        &self.verifier_id
    }

    pub fn operation_digest(&self) -> &[u8; 32] {
        &self.operation_digest
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn nonce_digest(&self) -> &[u8; 32] {
        &self.nonce_digest
    }

    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn verified_at(&self) -> u64 {
        self.verified_at
    }

    pub fn proof_digest(&self) -> &[u8; 32] {
        &self.proof_digest
    }

    pub fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence_digest
    }

    #[cfg(test)]
    fn from_fixture(
        envelope: &ProofEnvelope,
        context: &ProofVerificationContext,
    ) -> ConclaveResult<Self> {
        Self::from_verified_envelope(envelope, context)
    }

    #[allow(dead_code)]
    fn from_verified_envelope(
        envelope: &ProofEnvelope,
        context: &ProofVerificationContext,
    ) -> ConclaveResult<Self> {
        context.verify_envelope_binding(envelope)?;
        Ok(Self {
            kind: envelope.kind,
            proof_id: envelope.proof_id.clone(),
            verifier_id: envelope.verifier_id.clone(),
            operation_digest: envelope.operation_digest,
            purpose: envelope.purpose.clone(),
            audience: envelope.audience.clone(),
            nonce_digest: Sha256::digest(&context.nonce).into(),
            issued_at: envelope.issued_at,
            expires_at: envelope.expires_at,
            verified_at: context.now_secs,
            proof_digest: envelope.digest()?,
            evidence_digest: Sha256::digest(&envelope.evidence).into(),
        })
    }

    fn matches_envelope(
        &self,
        envelope: &ProofEnvelope,
        context: &ProofVerificationContext,
    ) -> ConclaveResult<bool> {
        let nonce_digest: [u8; 32] = Sha256::digest(&context.nonce).into();
        let evidence_digest: [u8; 32] = Sha256::digest(&envelope.evidence).into();
        Ok(self.kind == envelope.kind
            && self.proof_id == envelope.proof_id
            && self.verifier_id == envelope.verifier_id
            && self.operation_digest == envelope.operation_digest
            && self.purpose == envelope.purpose
            && self.audience == envelope.audience
            && self.nonce_digest == nonce_digest
            && self.issued_at == envelope.issued_at
            && self.expires_at == envelope.expires_at
            && self.verified_at == context.now_secs
            && self.proof_digest == envelope.digest()?
            && self.evidence_digest == evidence_digest)
    }

    fn canonical_bytes(&self) -> ConclaveResult<Vec<u8>> {
        let mut output = Vec::new();
        append_len_prefixed(&mut output, PROOF_CONTEXT_DOMAIN.as_bytes())?;
        output.push(self.kind.canonical_tag());
        append_identifier(&mut output, &self.proof_id)?;
        append_identifier(&mut output, &self.verifier_id)?;
        output.extend_from_slice(&self.operation_digest);
        append_identifier(&mut output, &self.purpose)?;
        append_identifier(&mut output, &self.audience)?;
        output.extend_from_slice(&self.nonce_digest);
        output.extend_from_slice(&self.issued_at.to_be_bytes());
        output.extend_from_slice(&self.expires_at.to_be_bytes());
        output.extend_from_slice(&self.verified_at.to_be_bytes());
        output.extend_from_slice(&self.proof_digest);
        output.extend_from_slice(&self.evidence_digest);
        Ok(output)
    }
}

/// Verified receipts bound to one exact operation context. It contains no raw
/// proof envelope or evidence payload.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VerifiedProofSet {
    context_binding: [u8; 32],
    operation_digest: [u8; 32],
    purpose: String,
    audience: String,
    nonce_digest: [u8; 32],
    receipts: Vec<VerifiedProofReceipt>,
}

impl VerifiedProofSet {
    fn from_verified(
        context: &ProofVerificationContext,
        mut receipts: Vec<VerifiedProofReceipt>,
    ) -> ConclaveResult<Self> {
        receipts.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.proof_id.cmp(&right.proof_id))
        });
        Ok(Self {
            context_binding: context.binding_digest()?,
            operation_digest: context.operation_digest,
            purpose: context.purpose.clone(),
            audience: context.audience.clone(),
            nonce_digest: Sha256::digest(&context.nonce).into(),
            receipts,
        })
    }

    pub fn context_binding(&self) -> &[u8; 32] {
        &self.context_binding
    }

    pub fn operation_digest(&self) -> &[u8; 32] {
        &self.operation_digest
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn nonce_digest(&self) -> &[u8; 32] {
        &self.nonce_digest
    }

    pub fn receipts(&self) -> &[VerifiedProofReceipt] {
        &self.receipts
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    pub fn contains_kind(&self, kind: ProofKind) -> bool {
        self.receipts.iter().any(|receipt| receipt.kind == kind)
    }

    pub fn receipt_for_kind(&self, kind: ProofKind) -> Option<&VerifiedProofReceipt> {
        self.receipts.iter().find(|receipt| receipt.kind == kind)
    }

    pub fn is_bound_to(&self, context: &ProofVerificationContext) -> ConclaveResult<bool> {
        Ok(self.context_binding == context.binding_digest()?)
    }

    pub fn digest(&self) -> ConclaveResult<[u8; 32]> {
        let mut output = Vec::new();
        append_len_prefixed(&mut output, PROOF_CONTEXT_DOMAIN.as_bytes())?;
        output.extend_from_slice(&self.context_binding);
        output.extend_from_slice(&self.operation_digest);
        append_identifier(&mut output, &self.purpose)?;
        append_identifier(&mut output, &self.audience)?;
        output.extend_from_slice(&self.nonce_digest);
        let count = u32::try_from(self.receipts.len()).map_err(|_| invalid_payload())?;
        output.extend_from_slice(&count.to_be_bytes());
        for receipt in &self.receipts {
            append_len_prefixed(&mut output, &receipt.canonical_bytes()?)?;
        }
        Ok(Sha256::digest(output).into())
    }
}

/// Private, constructor-controlled carrier for proof-complete value-bearing
/// authorization. It stores only verified receipts and binding digests.
#[derive(Debug, Clone)]
pub struct ProofBoundValueBearingAuthorization {
    verified_proofs: VerifiedProofSet,
}

impl ProofBoundValueBearingAuthorization {
    pub fn verified_proofs(&self) -> &VerifiedProofSet {
        &self.verified_proofs
    }

    pub fn context_binding(&self) -> &[u8; 32] {
        self.verified_proofs.context_binding()
    }

    fn matches_request(&self, request: &ValueBearingSignRequest) -> bool {
        self.verified_proofs.operation_digest() == request.message_digest()
            && self.verified_proofs.purpose()
                == request.operation_context().purpose().canonical_token()
            && self.verified_proofs.audience() == request.operation_context().domain()
            && request.operation_context().context() == request.message_digest()
    }
}

/// Verifies a bundle and creates the additive proof-aware value-bearing
/// authorization carrier. Existing serialized request/response shapes remain
/// unchanged.
pub fn authorize_value_bearing_with_proofs(
    registry: &ProofVerifierRegistry,
    bundle: &ProofBundle,
    policy: &ProofPolicy,
    context: &ProofVerificationContext,
    replay_guard: &ReplayGuard,
) -> ConclaveResult<ProofBoundValueBearingAuthorization> {
    let verified_proofs = registry.verify_bundle(bundle, policy, context, replay_guard)?;
    Ok(ProofBoundValueBearingAuthorization { verified_proofs })
}

/// Builds proof authorization for a canonical settlement intent. The rail
/// entry point is intentionally deferred: `RailProxy`'s legacy containment
/// path cannot consume this carrier, and no existing serialized request or
/// response shape is widened here.
pub fn authorize_settlement_with_proofs(
    registry: &ProofVerifierRegistry,
    bundle: &ProofBundle,
    policy: &ProofPolicy,
    intent: &SwapIntent,
    nonce: Vec<u8>,
    now_secs: u64,
    replay_guard: &ReplayGuard,
) -> ConclaveResult<ProofBoundValueBearingAuthorization> {
    let context = ProofVerificationContext::for_settlement(intent, nonce, now_secs)?;
    authorize_value_bearing_with_proofs(registry, bundle, policy, &context, replay_guard)
}

/// Additive proof-aware signing helper. It checks that the typed signing
/// request is bound to the verified proof context before invoking the existing
/// provider-only value-bearing path. It never calls legacy raw signing.
pub fn sign_value_bearing_with_proof_authorization(
    enclave: &dyn EnclaveManager,
    request: ValueBearingSignRequest,
    authorization: &ProofBoundValueBearingAuthorization,
) -> ConclaveResult<ValueBearingSignResponse> {
    if !authorization.matches_request(&request) {
        return Err(ConclaveError::Unsupported(
            "proof authorization does not match value-bearing operation context".to_string(),
        ));
    }
    enclave.sign_value_bearing(request)
}

#[cfg(test)]
struct FixtureProofVerifier {
    kind: ProofKind,
    verifier_id: String,
    expected_evidence: Vec<u8>,
}

#[cfg(test)]
impl ProofVerifier for FixtureProofVerifier {
    fn kind(&self) -> ProofKind {
        self.kind
    }

    fn verifier_id(&self) -> &str {
        &self.verifier_id
    }

    fn status(&self) -> ProofVerifierStatus {
        ProofVerifierStatus::TestOnly
    }

    fn verify(
        &self,
        envelope: &ProofEnvelope,
        context: &ProofVerificationContext,
    ) -> ConclaveResult<VerifiedProofReceipt> {
        if envelope.kind != self.kind
            || envelope.verifier_id != self.verifier_id
            || envelope.evidence != self.expected_evidence
        {
            return Err(proof_verification_failed());
        }
        VerifiedProofReceipt::from_fixture(envelope, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::replay_guard::ReplayGuard;

    const NOW: u64 = 1_000_000;

    fn fixture_verifier_id(kind: ProofKind) -> String {
        format!("conxian.test.proof.{}.v1", kind.canonical_name())
    }

    fn context() -> ProofVerificationContext {
        ProofVerificationContext::new(
            [7; 32],
            "SETTLEMENT",
            "conxian/settlement/v1",
            vec![9; 16],
            NOW,
        )
        .expect("fixture context")
    }

    fn fixture_proof(kind: ProofKind, proof_id: &str) -> ProofEnvelope {
        let context = context();
        ProofEnvelope::new(
            kind,
            proof_id,
            fixture_verifier_id(kind),
            context.operation_digest,
            context.purpose.clone(),
            context.audience.clone(),
            context.nonce.clone(),
            NOW.saturating_sub(10),
            NOW.saturating_add(60),
            format!("fixture:{}", kind.canonical_name()).into_bytes(),
        )
        .expect("fixture proof")
    }

    fn fixture_bundle() -> ProofBundle {
        ProofBundle::new(
            ProofKind::all()
                .into_iter()
                .enumerate()
                .map(|(index, kind)| fixture_proof(kind, &format!("proof-{index}")))
                .collect(),
        )
        .expect("fixture bundle")
    }

    fn fixture_policy() -> ProofPolicy {
        ProofPolicy::new(
            ProofKind::all()
                .into_iter()
                .map(|kind| {
                    ProofRequirement::new(kind, fixture_verifier_id(kind)).expect("requirement")
                })
                .collect(),
            UnlistedProofPolicy::Reject,
        )
        .expect("fixture policy")
    }

    #[test]
    fn production_registry_has_six_explicit_unavailable_routes() {
        let registry = ProofVerifierRegistry::production();
        assert_eq!(registry.route_count(), 6);
        for kind in ProofKind::all() {
            assert_eq!(
                registry.verifier_status(kind, kind.production_verifier_id()),
                ProofVerifierStatus::Unavailable
            );
        }
    }

    #[test]
    fn positive_test_only_all_six_composition_verifies_independently() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let bundle = fixture_bundle();
        let guard = ReplayGuard::new(300, 32);
        let verified = registry
            .verify_bundle(&bundle, &fixture_policy(), &context(), &guard)
            .expect("all fixtures verify");

        assert_eq!(verified.len(), 6);
        for kind in ProofKind::all() {
            assert!(verified.contains_kind(kind));
        }
        let serialized = serde_json::to_string(&verified).expect("receipt serialization");
        assert!(!serialized.contains("fixture:server"));
        assert!(!serialized.contains("\"evidence\":"));
    }

    #[test]
    fn production_registry_rejects_a_well_shaped_all_six_bundle() {
        let registry = ProofVerifierRegistry::production();
        let context = context();
        let bundle = ProofBundle::new(
            ProofKind::all()
                .into_iter()
                .enumerate()
                .map(|(index, kind)| {
                    ProofEnvelope::new(
                        kind,
                        format!("production-proof-{index}"),
                        kind.production_verifier_id(),
                        context.operation_digest,
                        context.purpose.clone(),
                        context.audience.clone(),
                        context.nonce.clone(),
                        NOW.saturating_sub(1),
                        NOW.saturating_add(30),
                        vec![1, 2, 3],
                    )
                    .expect("well-shaped proof")
                })
                .collect(),
        )
        .expect("well-shaped bundle");

        assert!(matches!(
            registry.verify_bundle(
                &bundle,
                &ProofPolicy::production(),
                &context,
                &ReplayGuard::new(300, 32),
            ),
            Err(ConclaveError::Unsupported(_))
        ));
    }

    #[test]
    fn rejects_missing_required_kind() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let bundle = ProofBundle::new(
            ProofKind::all()
                .into_iter()
                .filter(|kind| *kind != ProofKind::Tpm)
                .enumerate()
                .map(|(index, kind)| fixture_proof(kind, &format!("proof-{index}")))
                .collect(),
        )
        .expect("bundle without tpm");
        assert!(registry
            .verify_bundle(
                &bundle,
                &fixture_policy(),
                &context(),
                &ReplayGuard::new(300, 32)
            )
            .is_err());
    }

    #[test]
    fn rejects_duplicate_kind_and_duplicate_proof_id() {
        let first = fixture_proof(ProofKind::Server, "same-id");
        let second_kind = fixture_proof(ProofKind::Server, "different-id");
        assert!(ProofBundle::new(vec![first.clone(), second_kind]).is_err());

        let second_id = fixture_proof(ProofKind::User, "same-id");
        assert!(ProofBundle::new(vec![first, second_id]).is_err());
    }

    #[test]
    fn rejects_unsupported_version_and_malformed_bounds() {
        assert!(ProofEnvelope::new_with_version(
            PROOF_ENVELOPE_VERSION + 1,
            ProofKind::Server,
            "proof",
            fixture_verifier_id(ProofKind::Server),
            [7; 32],
            "SETTLEMENT",
            "audience",
            vec![1],
            NOW,
            NOW + 1,
            vec![1],
        )
        .is_err());
        assert!(ProofEnvelope::new(
            ProofKind::Server,
            "",
            fixture_verifier_id(ProofKind::Server),
            [7; 32],
            "SETTLEMENT",
            "audience",
            vec![1],
            NOW,
            NOW + 1,
            vec![1],
        )
        .is_err());
        assert!(ProofEnvelope::new(
            ProofKind::Server,
            "proof",
            fixture_verifier_id(ProofKind::Server),
            [7; 32],
            "SETTLEMENT",
            "audience",
            Vec::new(),
            NOW,
            NOW + 1,
            vec![1],
        )
        .is_err());
        assert!(ProofEnvelope::new(
            ProofKind::Server,
            "proof",
            fixture_verifier_id(ProofKind::Server),
            [7; 32],
            "SETTLEMENT",
            "audience",
            vec![1],
            NOW,
            NOW + 1,
            vec![0; MAX_EVIDENCE_BYTES + 1],
        )
        .is_err());
    }

    #[test]
    fn rejects_unknown_serialized_fields() {
        let serialized = serde_json::json!({
            "version": PROOF_ENVELOPE_VERSION,
            "kind": "Server",
            "proof_id": "proof",
            "verifier_id": fixture_verifier_id(ProofKind::Server),
            "operation_digest": vec![7; 32],
            "purpose": "SETTLEMENT",
            "audience": "audience",
            "nonce": [1],
            "issued_at": NOW,
            "expires_at": NOW + 1,
            "evidence": [1],
            "unexpected": true,
        });
        assert!(serde_json::from_value::<ProofEnvelope>(serialized).is_err());
    }

    #[test]
    fn rejects_wrong_digest_purpose_audience_and_nonce() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let policy = ProofPolicy::new(
            vec![
                ProofRequirement::new(ProofKind::Server, fixture_verifier_id(ProofKind::Server))
                    .expect("requirement"),
            ],
            false,
        )
        .expect("policy");
        let mutations = [
            |proof: &mut ProofEnvelope| proof.operation_digest = [8; 32],
            |proof: &mut ProofEnvelope| proof.purpose = "AUTHORIZATION".to_string(),
            |proof: &mut ProofEnvelope| proof.audience = "other-audience".to_string(),
            |proof: &mut ProofEnvelope| proof.nonce = vec![8; 16],
        ];
        for mutate in mutations {
            let mut proof = fixture_proof(ProofKind::Server, "binding-proof");
            mutate(&mut proof);
            let bundle = ProofBundle {
                proofs: vec![proof],
            };
            assert!(registry
                .verify_bundle(&bundle, &policy, &context(), &ReplayGuard::new(300, 32))
                .is_err());
        }
    }

    #[test]
    fn rejects_stale_future_and_expired_proofs() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let policy = ProofPolicy::new(
            vec![
                ProofRequirement::new(ProofKind::Server, fixture_verifier_id(ProofKind::Server))
                    .expect("requirement"),
            ],
            false,
        )
        .expect("policy");
        let mut stale = fixture_proof(ProofKind::Server, "stale");
        stale.issued_at = NOW - DEFAULT_MAX_PROOF_AGE_SECS - 1;
        stale.expires_at = NOW - 1;
        assert!(registry
            .verify_bundle(
                &ProofBundle {
                    proofs: vec![stale]
                },
                &policy,
                &context(),
                &ReplayGuard::new(300, 32),
            )
            .is_err());

        let mut future = fixture_proof(ProofKind::Server, "future");
        future.issued_at = NOW + DEFAULT_MAX_PROOF_FUTURE_SKEW_SECS + 1;
        future.expires_at = future.issued_at + 1;
        assert!(registry
            .verify_bundle(
                &ProofBundle {
                    proofs: vec![future]
                },
                &policy,
                &context(),
                &ReplayGuard::new(300, 32),
            )
            .is_err());

        let mut expired = fixture_proof(ProofKind::Server, "expired");
        expired.expires_at = NOW - 1;
        assert!(registry
            .verify_bundle(
                &ProofBundle {
                    proofs: vec![expired]
                },
                &policy,
                &context(),
                &ReplayGuard::new(300, 32),
            )
            .is_err());
    }

    #[test]
    fn accepts_a_proof_within_the_configured_future_skew() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let policy = ProofPolicy::new(
            vec![
                ProofRequirement::new(ProofKind::Server, fixture_verifier_id(ProofKind::Server))
                    .expect("requirement"),
            ],
            false,
        )
        .expect("policy");
        let mut future = fixture_proof(ProofKind::Server, "future-within-skew");
        future.issued_at = NOW + DEFAULT_MAX_PROOF_FUTURE_SKEW_SECS;
        future.expires_at = future.issued_at + 1;
        assert!(registry
            .verify_bundle(
                &ProofBundle {
                    proofs: vec![future]
                },
                &policy,
                &context(),
                &ReplayGuard::new(300, 32),
            )
            .is_ok());
    }

    #[test]
    fn rejects_invalid_evidence_and_cross_kind_substitution() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let policy = ProofPolicy::new(
            vec![
                ProofRequirement::new(ProofKind::Server, fixture_verifier_id(ProofKind::Server))
                    .expect("requirement"),
            ],
            false,
        )
        .expect("policy");
        let mut invalid = fixture_proof(ProofKind::Server, "invalid");
        invalid.evidence = b"fixture:user".to_vec();
        assert!(registry
            .verify_bundle(
                &ProofBundle {
                    proofs: vec![invalid]
                },
                &policy,
                &context(),
                &ReplayGuard::new(300, 32),
            )
            .is_err());

        let mut substituted = fixture_proof(ProofKind::User, "substituted");
        substituted.verifier_id = fixture_verifier_id(ProofKind::Server);
        substituted.evidence = b"fixture:server".to_vec();
        assert!(registry
            .verify_bundle(
                &ProofBundle {
                    proofs: vec![substituted]
                },
                &policy,
                &context(),
                &ReplayGuard::new(300, 32),
            )
            .is_err());
    }

    #[test]
    fn rejects_unlisted_kinds_when_policy_is_explicitly_closed() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let policy = ProofPolicy::new(
            vec![
                ProofRequirement::new(ProofKind::Server, fixture_verifier_id(ProofKind::Server))
                    .expect("requirement"),
            ],
            UnlistedProofPolicy::Reject,
        )
        .expect("policy");
        let bundle = ProofBundle::new(vec![
            fixture_proof(ProofKind::Server, "server"),
            fixture_proof(ProofKind::User, "user"),
        ])
        .expect("bundle");
        assert!(registry
            .verify_bundle(&bundle, &policy, &context(), &ReplayGuard::new(300, 32))
            .is_err());
    }

    #[test]
    fn replay_is_atomic_for_a_bundle() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let policy = fixture_policy();
        let bundle = fixture_bundle();
        let guard = ReplayGuard::new(300, 6);
        registry
            .verify_bundle(&bundle, &policy, &context(), &guard)
            .expect("first bundle");
        assert!(registry
            .verify_bundle(&bundle, &policy, &context(), &guard)
            .is_err());
    }

    #[test]
    fn capacity_failure_does_not_partially_insert_bundle_replay_keys() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let policy = fixture_policy();
        let bundle = fixture_bundle();
        let guard = ReplayGuard::new(300, 5);
        assert!(registry
            .verify_bundle(&bundle, &policy, &context(), &guard)
            .is_err());

        let one = ProofBundle::new(vec![fixture_proof(ProofKind::Server, "single")])
            .expect("single bundle");
        let one_policy = ProofPolicy::new(
            vec![
                ProofRequirement::new(ProofKind::Server, fixture_verifier_id(ProofKind::Server))
                    .expect("requirement"),
            ],
            false,
        )
        .expect("policy");
        assert!(registry
            .verify_bundle(&one, &one_policy, &context(), &guard)
            .is_ok());
    }

    #[test]
    fn replay_key_changes_for_each_security_relevant_component() {
        let base = fixture_proof(ProofKind::Server, "base");
        let base_key = base.replay_key().expect("base key");

        let mut kind = base.clone();
        kind.kind = ProofKind::User;
        let mut proof_id = base.clone();
        proof_id.proof_id = "other".to_string();
        let mut digest = base.clone();
        digest.operation_digest = [8; 32];
        let mut nonce = base;
        nonce.nonce = vec![4; 16];

        assert_ne!(base_key, kind.replay_key().expect("kind key"));
        assert_ne!(base_key, proof_id.replay_key().expect("id key"));
        assert_ne!(base_key, digest.replay_key().expect("digest key"));
        assert_ne!(base_key, nonce.replay_key().expect("nonce key"));
        assert!(base_key.as_str().starts_with(PROOF_REPLAY_DOMAIN));
    }

    #[test]
    fn settlement_helper_binds_to_canonical_intent_and_domain() {
        let mut intent = SwapIntent {
            request: crate::protocol::intent::SwapRequest {
                from_asset: crate::protocol::asset::AssetIdentifier {
                    chain: crate::protocol::asset::Chain::BITCOIN,
                    symbol: "BTC".to_string(),
                },
                to_asset: crate::protocol::asset::AssetIdentifier {
                    chain: crate::protocol::asset::Chain::STACKS,
                    symbol: "STX".to_string(),
                },
                amount: 1,
                recipient_address: "recipient".to_string(),
                attribution: None,
            },
            signable_hash: Vec::new(),
            rail_type: "x402".to_string(),
            chain_context: None,
            fdc3_context: None,
        };
        intent.signable_hash = intent.canonical_hash();
        let context = ProofVerificationContext::for_settlement(&intent, vec![1; 16], NOW)
            .expect("settlement context");
        assert_eq!(context.purpose, SETTLEMENT_PROOF_PURPOSE);
        assert_eq!(context.audience, SETTLEMENT_PROOF_AUDIENCE);
        assert_eq!(context.operation_digest.as_slice(), intent.canonical_hash());
    }

    #[test]
    fn exact_route_does_not_fallback_to_kind_only() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let mut proof = fixture_proof(ProofKind::Server, "route");
        proof.verifier_id = "some-other-server-verifier".to_string();
        let policy = ProofPolicy::new(
            vec![
                ProofRequirement::new(ProofKind::Server, proof.verifier_id.clone())
                    .expect("requirement"),
            ],
            false,
        )
        .expect("policy");
        assert!(registry
            .verify_bundle(
                &ProofBundle {
                    proofs: vec![proof]
                },
                &policy,
                &context(),
                &ReplayGuard::new(300, 32),
            )
            .is_err());
    }

    #[test]
    fn proof_policy_rejects_duplicate_required_kinds() {
        let policy = ProofPolicy {
            required: vec![
                ProofRequirement::new(ProofKind::Server, "server-a").expect("requirement"),
                ProofRequirement::new(ProofKind::Server, "server-b").expect("requirement"),
            ],
            unlisted: UnlistedProofPolicy::Reject,
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn proof_bundle_digest_is_order_independent() {
        let first = fixture_bundle();
        let mut reversed = first.proofs.clone();
        reversed.reverse();
        let second = ProofBundle::new(reversed).expect("reversed bundle");
        assert_eq!(
            first.digest().expect("digest"),
            second.digest().expect("digest")
        );
    }

    #[test]
    fn receipt_set_contains_only_digests_and_binding_metadata() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let verified = registry
            .verify_bundle(
                &fixture_bundle(),
                &fixture_policy(),
                &context(),
                &ReplayGuard::new(300, 32),
            )
            .expect("verified set");
        let json = serde_json::to_value(&verified).expect("json");
        let object = json.as_object().expect("receipt set object");
        assert!(object.get("receipts").is_some());
        assert!(serde_json::to_string(&verified)
            .expect("json string")
            .contains("evidence_digest"));
        assert!(!serde_json::to_string(&verified)
            .expect("json string")
            .contains("fixture:server"));
    }
}
