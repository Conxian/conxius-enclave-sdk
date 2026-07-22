//! Bounded, fail-closed verification for independent external proofs.
//!
//! This module is an evidence framework, not a provider implementation. The
//! production registry contains one explicit unavailable verifier for each
//! semantic proof kind. No structural, simulated, or software verifier can
//! satisfy the production registry.

use crate::enclave::replay_guard::{
    ReplayBinding, ReplayConsumeOutcome, ReplayGuard, ReplayGuardError, ReplayReservation,
    ReplayStore, ReplayStoreDurability, ReplayStoreError,
};
use crate::enclave::{
    EnclaveManager, SignerKeyBinding, ValueBearingSignRequest, ValueBearingSignResponse,
};
use crate::protocol::intent::SwapIntent;
use crate::{ConclaveError, ConclaveResult};
use serde::de::{self, Deserializer, Error as DeError, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Current version of the independent proof envelope.
pub const PROOF_ENVELOPE_VERSION: u16 = 1;

/// Domain used by canonical proof-envelope encodings.
pub const PROOF_ENVELOPE_DOMAIN: &str = "CONXIAN-INDEPENDENT-PROOF/v1";

/// Domain used by canonical proof-context bindings.
pub const PROOF_CONTEXT_DOMAIN: &str = "CONXIAN-PROOF-CONTEXT/v1";

/// Domain used by canonical proof-policy identities.
pub const PROOF_POLICY_DOMAIN: &str = "CONXIAN-PROOF-POLICY/v1";

/// Domain used by replay keys generated for proof envelopes.
pub const PROOF_REPLAY_DOMAIN: &str = "CONXIAN-PROOF-REPLAY/v1";

/// Distinct replay domain consumed at the final durable value-bearing signing
/// boundary. Proof reservations and operation reservations must never share a
/// key space.
pub const VALUE_BEARING_OPERATION_REPLAY_DOMAIN: &str = "CONXIAN-VALUE-BEARING-OPERATION-REPLAY/v1";

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

/// Maximum serialized JSON or bincode-style transport accepted by the
/// bounded proof-bundle entry point. Field and sequence visitors enforce the
/// stricter per-value limits below; this outer limit also caps parser work for
/// unknown fields and framing overhead that generic serde cannot avoid before
/// dispatching a field visitor.
pub const MAX_PROOF_TRANSPORT_BYTES: usize = 256 * 1024;

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

fn validate_deserialized_identifier<E: DeError>(value: &str) -> Result<String, E> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(E::custom("bounded proof identifier is invalid"));
    }
    Ok(value.to_string())
}

struct BoundedIdentifierVisitor;

impl<'de> Visitor<'de> for BoundedIdentifierVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded non-empty proof identifier")
    }

    fn visit_str<E: DeError>(self, value: &str) -> Result<Self::Value, E> {
        validate_deserialized_identifier(value)
    }

    fn visit_borrowed_str<E: DeError>(self, value: &'de str) -> Result<Self::Value, E> {
        validate_deserialized_identifier(value)
    }

    fn visit_string<E: DeError>(self, value: String) -> Result<Self::Value, E> {
        validate_deserialized_identifier(&value)
    }
}

fn deserialize_bounded_identifier<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_string(BoundedIdentifierVisitor)
}

struct BoundedBytesVisitor {
    maximum: usize,
}

impl<'de> Visitor<'de> for BoundedBytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {} proof bytes", self.maximum)
    }

    fn visit_bytes<E: DeError>(self, value: &[u8]) -> Result<Self::Value, E> {
        if value.len() > self.maximum {
            return Err(E::custom("proof byte field exceeds its bound"));
        }
        Ok(value.to_vec())
    }

    fn visit_borrowed_bytes<E: DeError>(self, value: &'de [u8]) -> Result<Self::Value, E> {
        self.visit_bytes(value)
    }

    fn visit_byte_buf<E: DeError>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        if value.len() > self.maximum {
            return Err(E::custom("proof byte field exceeds its bound"));
        }
        Ok(value)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        if sequence.size_hint().is_some_and(|size| size > self.maximum) {
            return Err(A::Error::custom("proof byte sequence exceeds its bound"));
        }

        let capacity = sequence.size_hint().unwrap_or_default().min(self.maximum);
        let mut bytes = Vec::with_capacity(capacity);
        while bytes.len() < self.maximum {
            match sequence.next_element::<u8>()? {
                Some(byte) => bytes.push(byte),
                None => return Ok(bytes),
            }
        }

        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("proof byte sequence exceeds its bound"));
        }
        Ok(bytes)
    }
}

fn deserialize_bounded_bytes<'de, D, const MAXIMUM: usize>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_byte_buf(BoundedBytesVisitor { maximum: MAXIMUM })
}

fn deserialize_bounded_nonce<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes::<D, MAX_NONCE_BYTES>(deserializer)
}

fn deserialize_bounded_evidence<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes::<D, MAX_EVIDENCE_BYTES>(deserializer)
}

struct BoundedVecVisitor<T> {
    maximum: usize,
    marker: PhantomData<fn() -> T>,
}

impl<'de, T> Visitor<'de> for BoundedVecVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {} bounded proof entries", self.maximum)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        if sequence.size_hint().is_some_and(|size| size > self.maximum) {
            return Err(A::Error::custom("proof sequence exceeds its bound"));
        }

        let capacity = sequence.size_hint().unwrap_or_default().min(self.maximum);
        let mut values = Vec::with_capacity(capacity);
        while values.len() < self.maximum {
            match sequence.next_element::<T>()? {
                Some(value) => values.push(value),
                None => return Ok(values),
            }
        }

        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("proof sequence exceeds its bound"));
        }
        Ok(values)
    }
}

fn deserialize_bounded_vec<'de, D, T, const MAXIMUM: usize>(
    deserializer: D,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(BoundedVecVisitor {
        maximum: MAXIMUM,
        marker: PhantomData,
    })
}

fn deserialize_bounded_requirements<'de, D>(
    deserializer: D,
) -> Result<Vec<ProofRequirement>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, ProofRequirement, MAX_PROOF_BUNDLE_SIZE>(deserializer)
}

fn deserialize_bounded_proofs<'de, D>(deserializer: D) -> Result<Vec<ProofEnvelope>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, ProofEnvelope, MAX_PROOF_BUNDLE_SIZE>(deserializer)
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
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub proof_id: String,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub verifier_id: String,
    pub operation_digest: [u8; 32],
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub purpose: String,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub audience: String,
    #[serde(deserialize_with = "deserialize_bounded_nonce")]
    pub nonce: Vec<u8>,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(deserialize_with = "deserialize_bounded_evidence")]
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
        if lifetime == 0 || lifetime > MAX_PROOF_LIFETIME_SECS {
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
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub purpose: String,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub audience: String,
    #[serde(deserialize_with = "deserialize_bounded_nonce")]
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

    fn with_now_secs(&self, now_secs: u64) -> ConclaveResult<Self> {
        let mut context = self.clone();
        context.now_secs = now_secs;
        context.validate()
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

    fn effective_valid_until(&self, envelope: &ProofEnvelope) -> ConclaveResult<u64> {
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
        if envelope.expires_at <= self.now_secs {
            return Err(proof_verification_failed());
        }

        let freshness_limit = envelope
            .issued_at
            .checked_add(self.max_age_secs)
            .ok_or_else(invalid_payload)?;
        if self.now_secs >= freshness_limit {
            return Err(proof_verification_failed());
        }

        let effective_valid_until = envelope.expires_at.min(freshness_limit);
        if self.now_secs >= effective_valid_until {
            return Err(proof_verification_failed());
        }
        Ok(effective_valid_until)
    }

    fn verify_envelope_binding(&self, envelope: &ProofEnvelope) -> ConclaveResult<()> {
        self.effective_valid_until(envelope).map(|_| ())
    }
}

/// A required semantic kind and its exact verifier identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProofRequirement {
    pub kind: ProofKind,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
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
    #[serde(deserialize_with = "deserialize_bounded_requirements")]
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

    /// Canonical policy encoding used for security-sensitive policy binding.
    /// Required entries are sorted by semantic kind and exact verifier identity
    /// so equivalent construction order cannot produce different identities.
    pub fn canonical_bytes(&self) -> ConclaveResult<Vec<u8>> {
        self.validate()?;
        let mut required = self.required.iter().collect::<Vec<_>>();
        required.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.verifier_id.cmp(&right.verifier_id))
        });

        let mut output = Vec::new();
        append_len_prefixed(&mut output, PROOF_POLICY_DOMAIN.as_bytes())?;
        output.push(match self.unlisted {
            UnlistedProofPolicy::Reject => 0,
            UnlistedProofPolicy::Allow => 1,
        });
        let count = u32::try_from(required.len()).map_err(|_| invalid_payload())?;
        output.extend_from_slice(&count.to_be_bytes());
        for requirement in required {
            output.push(requirement.kind.canonical_tag());
            append_identifier(&mut output, &requirement.verifier_id)?;
        }
        Ok(output)
    }

    pub fn digest(&self) -> ConclaveResult<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }

    /// Returns true only for the constructor-controlled six-kind production
    /// policy. Generic proof verification intentionally remains configurable.
    pub fn is_exact_production(&self) -> bool {
        self.validate().is_ok() && self.digest().ok() == ProofPolicy::production().digest().ok()
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
///
/// `ProofBundle` is serializable for transport, but deliberately does not
/// implement generic `Deserialize`. Untrusted JSON must enter through
/// [`deserialize_proof_bundle_json`], which enforces the outer transport bound
/// before the private wire representation invokes the bounded field visitors.
/// Serialized raw evidence is transport-only and must not be used for
/// diagnostics; `Debug` implementations redact evidence contents.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofBundleWire {
    #[serde(deserialize_with = "deserialize_bounded_proofs")]
    proofs: Vec<ProofEnvelope>,
}

/// The only public untrusted JSON construction path for [`ProofBundle`]. It
/// checks the complete outer payload before invoking the private wire
/// representation and its bounded field and sequence visitors. Serialized raw
/// evidence remains transport-only, not diagnostics.
pub fn deserialize_proof_bundle_json(input: &[u8]) -> ConclaveResult<ProofBundle> {
    if input.len() > MAX_PROOF_TRANSPORT_BYTES {
        return Err(invalid_payload());
    }
    let wire: ProofBundleWire = serde_json::from_slice(input).map_err(|_| invalid_payload())?;
    ProofBundle::new(wire.proofs)
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

/// Provider and key identity context required by the complete replay binding.
/// The key identity is reduced to a digest before this context is retained.
#[derive(Clone, PartialEq, Eq)]
pub struct ProofReplayBindingContext {
    provider: String,
    key_identity_digest: [u8; 32],
}

impl std::fmt::Debug for ProofReplayBindingContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProofReplayBindingContext")
            .field("provider", &self.provider)
            .field("key_identity_digest", &self.key_identity_digest)
            .finish()
    }
}

impl ProofReplayBindingContext {
    pub fn new(provider: impl Into<String>, key_identity: &[u8]) -> ConclaveResult<Self> {
        let provider = provider.into();
        let probe = ReplayBinding::new(
            provider.clone(),
            "proof-subject",
            "proof-mechanism",
            b"proof-nonce",
            [0; 32],
            "PROOF",
            [1; 32],
            key_identity,
            [2; 32],
            Option::<String>::None,
            Option::<String>::None,
        )
        .map_err(|_| invalid_payload())?;
        Ok(Self {
            provider,
            key_identity_digest: *probe.key_identity_digest(),
        })
    }

    pub fn for_signer_key(
        provider: impl Into<String>,
        key_binding: &SignerKeyBinding,
    ) -> ConclaveResult<Self> {
        let provider = provider.into();
        Ok(Self {
            provider,
            key_identity_digest: key_binding.replay_identity_digest()?,
        })
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn key_identity_digest(&self) -> &[u8; 32] {
        &self.key_identity_digest
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
        let receipts = self.verify_bundle_evidence(bundle, policy, context)?;

        let replay_reservations = bundle
            .proofs
            .iter()
            .map(|proof| {
                context
                    .effective_valid_until(proof)
                    .and_then(|valid_until| {
                        proof
                            .replay_key()
                            .map(|key| (key.as_str().to_string(), valid_until))
                    })
            })
            .collect::<ConclaveResult<Vec<_>>>()?;
        replay_guard
            .try_check_and_record_batch_with_horizons(replay_reservations, context.now_secs)
            .map_err(map_replay_error)?;

        VerifiedProofSet::from_verified(context, policy, receipts)
    }

    /// Verifies a proof bundle and consumes complete provider-neutral replay
    /// reservations through the additive store contract. The process-local
    /// `ReplayGuard` path above remains an explicit containment-only API.
    pub fn verify_bundle_with_store(
        &self,
        bundle: &ProofBundle,
        policy: &ProofPolicy,
        context: &ProofVerificationContext,
        binding_context: &ProofReplayBindingContext,
        replay_store: &dyn ReplayStore,
    ) -> ConclaveResult<VerifiedProofSet> {
        let receipts = self.verify_bundle_evidence(bundle, policy, context)?;
        let policy_digest = policy.digest()?;
        let reservations = bundle
            .proofs
            .iter()
            .zip(receipts.iter())
            .map(|(proof, receipt)| {
                let binding = ReplayBinding::from_component_digests(
                    binding_context.provider().to_string(),
                    proof.proof_id.clone(),
                    proof.verifier_id.clone(),
                    *receipt.nonce_digest(),
                    proof.operation_digest,
                    proof.purpose.clone(),
                    policy_digest,
                    *binding_context.key_identity_digest(),
                    *receipt.evidence_digest(),
                    Some(proof.proof_id.clone()),
                    Some(proof.audience.clone()),
                )
                .map_err(|_| invalid_payload())?;
                let valid_until = context.effective_valid_until(proof)?;
                ReplayReservation::new(&binding, valid_until).map_err(|_| invalid_payload())
            })
            .collect::<ConclaveResult<Vec<_>>>()?;
        replay_store
            .consume_once_batch(&reservations, context.now_secs)
            .map_err(map_replay_store_error)?;

        VerifiedProofSet::from_verified(context, policy, receipts)
    }

    /// Production-facing additive boundary. A process-local or unavailable
    /// store is rejected before proof authorization can be issued.
    pub fn verify_bundle_with_durable_store(
        &self,
        bundle: &ProofBundle,
        policy: &ProofPolicy,
        context: &ProofVerificationContext,
        binding_context: &ProofReplayBindingContext,
        replay_store: &dyn ReplayStore,
    ) -> ConclaveResult<VerifiedProofSet> {
        ensure_exact_production_policy(policy)?;
        if replay_store.durability() != ReplayStoreDurability::DurableProvider {
            return Err(ConclaveError::Unsupported(
                "durable replay store is required for production proof authorization".to_string(),
            ));
        }
        self.verify_bundle_with_store(bundle, policy, context, binding_context, replay_store)
    }

    fn verify_bundle_evidence(
        &self,
        bundle: &ProofBundle,
        policy: &ProofPolicy,
        context: &ProofVerificationContext,
    ) -> ConclaveResult<Vec<VerifiedProofReceipt>> {
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
        Ok(receipts)
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
            // Test-only positive routes deliberately reuse the exact
            // production policy identities. The production registry remains
            // unavailable, so these fixtures cannot be used as production
            // verifier implementations.
            let verifier_id = kind.production_verifier_id().to_string();
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
        ReplayGuardError::ClockRollback => ConclaveError::ClockRollback,
        ReplayGuardError::InvalidInput => ConclaveError::InvalidPayload,
        ReplayGuardError::LockPoisoned => ConclaveError::EnclaveFailure(
            "independent proof replay guard is unavailable".to_string(),
        ),
    }
}

fn map_replay_store_error(error: ReplayStoreError) -> ConclaveError {
    match error {
        ReplayStoreError::ClockRollback => ConclaveError::ClockRollback,
        ReplayStoreError::InvalidKey | ReplayStoreError::InvalidRetention => {
            ConclaveError::InvalidPayload
        }
        ReplayStoreError::AtomicBatchFailure(_) => ConclaveError::EnclaveFailure(
            "independent proof replay batch failed atomically".to_string(),
        ),
        ReplayStoreError::BackendUnavailable
        | ReplayStoreError::TransactionIndeterminate
        | ReplayStoreError::LockPoisoned => ConclaveError::Unsupported(
            "independent proof replay store is unavailable or indeterminate".to_string(),
        ),
        ReplayStoreError::CapacitySaturated => ConclaveError::EnclaveFailure(
            "independent proof replay store capacity is saturated".to_string(),
        ),
    }
}

fn ensure_exact_production_policy(policy: &ProofPolicy) -> ConclaveResult<()> {
    let expected_policy_digest = ProofPolicy::production().digest()?;
    if !policy.is_exact_production() || policy.digest()? != expected_policy_digest {
        return Err(ConclaveError::Unsupported(
            "value-bearing proof authorization requires the exact production proof policy"
                .to_string(),
        ));
    }
    Ok(())
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
    effective_expires_at: u64,
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

    pub fn effective_expires_at(&self) -> u64 {
        self.effective_expires_at
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
            effective_expires_at: context.effective_valid_until(envelope)?,
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
        let effective_expires_at = context.effective_valid_until(envelope)?;
        Ok(self.kind == envelope.kind
            && self.proof_id == envelope.proof_id
            && self.verifier_id == envelope.verifier_id
            && self.operation_digest == envelope.operation_digest
            && self.purpose == envelope.purpose
            && self.audience == envelope.audience
            && self.nonce_digest == nonce_digest
            && self.issued_at == envelope.issued_at
            && self.expires_at == envelope.expires_at
            && self.effective_expires_at == effective_expires_at
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
        output.extend_from_slice(&self.effective_expires_at.to_be_bytes());
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
    policy_digest: [u8; 32],
    operation_digest: [u8; 32],
    purpose: String,
    audience: String,
    nonce_digest: [u8; 32],
    effective_expires_at: Option<u64>,
    receipts: Vec<VerifiedProofReceipt>,
}

impl VerifiedProofSet {
    fn from_verified(
        context: &ProofVerificationContext,
        policy: &ProofPolicy,
        mut receipts: Vec<VerifiedProofReceipt>,
    ) -> ConclaveResult<Self> {
        receipts.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.proof_id.cmp(&right.proof_id))
        });
        Ok(Self {
            context_binding: context.binding_digest()?,
            policy_digest: policy.digest()?,
            operation_digest: context.operation_digest,
            purpose: context.purpose.clone(),
            audience: context.audience.clone(),
            nonce_digest: Sha256::digest(&context.nonce).into(),
            effective_expires_at: receipts
                .iter()
                .map(VerifiedProofReceipt::effective_expires_at)
                .min(),
            receipts,
        })
    }

    pub fn context_binding(&self) -> &[u8; 32] {
        &self.context_binding
    }

    pub fn policy_digest(&self) -> &[u8; 32] {
        &self.policy_digest
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

    pub fn effective_expires_at(&self) -> Option<u64> {
        self.effective_expires_at
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
        output.extend_from_slice(&self.policy_digest);
        output.extend_from_slice(&self.operation_digest);
        append_identifier(&mut output, &self.purpose)?;
        append_identifier(&mut output, &self.audience)?;
        output.extend_from_slice(&self.nonce_digest);
        match self.effective_expires_at {
            Some(expires_at) => {
                output.push(1);
                output.extend_from_slice(&expires_at.to_be_bytes());
            }
            None => output.push(0),
        }
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
///
/// This carrier is not cloneable and retains an atomic authorization-time
/// high-water mark. Durable carriers are signer-bound and one-shot at final
/// signing: proof replay keys are reserved atomically while the bundle is
/// verified, then a distinct operation replay key is consumed immediately
/// before provider signing.
#[derive(Debug)]
pub struct ProofBoundValueBearingAuthorization {
    verified_proofs: VerifiedProofSet,
    policy_digest: [u8; 32],
    authorization_expires_at: u64,
    last_observed_secs: AtomicU64,
    durable_binding: Option<DurableAuthorizationBinding>,
    final_signing_consumed: AtomicBool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DurableAuthorizationBinding {
    provider: String,
    key_identity_digest: [u8; 32],
}

impl ProofBoundValueBearingAuthorization {
    fn from_verified(verified_proofs: VerifiedProofSet) -> ConclaveResult<Self> {
        let authorization_expires_at = verified_proofs
            .effective_expires_at()
            .ok_or_else(proof_verification_failed)?;
        let last_observed_secs = verified_proofs
            .receipts()
            .iter()
            .fold(0, |high_water, receipt| {
                high_water.max(receipt.verified_at())
            });
        Ok(Self {
            policy_digest: *verified_proofs.policy_digest(),
            verified_proofs,
            authorization_expires_at,
            last_observed_secs: AtomicU64::new(last_observed_secs),
            durable_binding: None,
            final_signing_consumed: AtomicBool::new(false),
        })
    }

    fn from_verified_with_durable_binding(
        verified_proofs: VerifiedProofSet,
        binding_context: &ProofReplayBindingContext,
    ) -> ConclaveResult<Self> {
        let mut authorization = Self::from_verified(verified_proofs)?;
        authorization.durable_binding = Some(DurableAuthorizationBinding {
            provider: binding_context.provider().to_string(),
            key_identity_digest: *binding_context.key_identity_digest(),
        });
        Ok(authorization)
    }

    pub fn verified_proofs(&self) -> &VerifiedProofSet {
        &self.verified_proofs
    }

    pub fn context_binding(&self) -> &[u8; 32] {
        self.verified_proofs.context_binding()
    }

    pub fn policy_digest(&self) -> &[u8; 32] {
        &self.policy_digest
    }

    pub fn authorization_expires_at(&self) -> u64 {
        self.authorization_expires_at
    }

    fn observe_and_validate_at(&self, now_secs: u64) -> ConclaveResult<()> {
        let mut last_observed_secs = self.last_observed_secs.load(Ordering::Acquire);
        loop {
            if now_secs < last_observed_secs {
                return Err(ConclaveError::ClockRollback);
            }
            if now_secs == last_observed_secs {
                break;
            }

            match self.last_observed_secs.compare_exchange_weak(
                last_observed_secs,
                now_secs,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed_secs) => last_observed_secs = observed_secs,
            }
        }

        if now_secs >= self.authorization_expires_at {
            return Err(ConclaveError::Unsupported(
                "proof authorization has expired".to_string(),
            ));
        }

        Ok(())
    }

    fn matches_request(&self, request: &ValueBearingSignRequest) -> ConclaveResult<bool> {
        let expected_policy_digest = ProofPolicy::production().digest().ok();
        let key_matches = self.durable_binding.as_ref().is_none_or(|binding| {
            request
                .key_binding()
                .replay_identity_digest()
                .is_ok_and(|digest| digest == binding.key_identity_digest)
        });
        Ok(self.policy_digest == *self.verified_proofs.policy_digest()
            && expected_policy_digest.as_ref() == Some(&self.policy_digest)
            && request.trust_requirement().policy_id() == crate::enclave::VALUE_BEARING_POLICY_ID
            && !self.verified_proofs.is_empty()
            && self.verified_proofs.operation_digest() == request.message_digest()
            && self.verified_proofs.purpose()
                == request.operation_context().purpose().canonical_token()
            && self.verified_proofs.audience() == request.operation_context().domain()
            && request.operation_context().context() == request.message_digest()
            && key_matches)
    }
}

/// Test-only containment helper for verifying a bundle and creating a
/// proof-aware value-bearing authorization carrier. The supplied context's
/// freshness timestamp is replaced with the SDK trusted process clock before
/// verification. It is not exported by the production library.
#[cfg(test)]
pub(crate) fn authorize_value_bearing_with_proofs(
    registry: &ProofVerifierRegistry,
    bundle: &ProofBundle,
    policy: &ProofPolicy,
    context: &ProofVerificationContext,
    replay_guard: &ReplayGuard,
) -> ConclaveResult<ProofBoundValueBearingAuthorization> {
    authorize_value_bearing_with_proofs_with_trusted_clock(
        registry,
        bundle,
        policy,
        context,
        replay_guard,
        crate::enclave::trusted_unix_time_secs(),
    )
}

/// Additive production-gated authorization path. It requires both the exact
/// production proof policy and a durable replay store; process-local replay
/// cannot silently satisfy this boundary.
pub fn authorize_value_bearing_with_durable_store(
    registry: &ProofVerifierRegistry,
    bundle: &ProofBundle,
    policy: &ProofPolicy,
    context: &ProofVerificationContext,
    binding_context: &ProofReplayBindingContext,
    replay_store: &dyn ReplayStore,
) -> ConclaveResult<ProofBoundValueBearingAuthorization> {
    ensure_exact_production_policy(policy)?;
    let trusted_context = context.with_now_secs(crate::enclave::trusted_unix_time_secs()?)?;
    let verified_proofs = registry.verify_bundle_with_durable_store(
        bundle,
        policy,
        &trusted_context,
        binding_context,
        replay_store,
    )?;
    ProofBoundValueBearingAuthorization::from_verified_with_durable_binding(
        verified_proofs,
        binding_context,
    )
}

#[cfg(test)]
fn authorize_value_bearing_with_proofs_with_trusted_clock(
    registry: &ProofVerifierRegistry,
    bundle: &ProofBundle,
    policy: &ProofPolicy,
    context: &ProofVerificationContext,
    replay_guard: &ReplayGuard,
    trusted_now_secs: ConclaveResult<u64>,
) -> ConclaveResult<ProofBoundValueBearingAuthorization> {
    let trusted_context = context.with_now_secs(trusted_now_secs?)?;
    authorize_value_bearing_with_proofs_at(registry, bundle, policy, &trusted_context, replay_guard)
}

#[cfg(test)]
fn authorize_value_bearing_with_proofs_at(
    registry: &ProofVerifierRegistry,
    bundle: &ProofBundle,
    policy: &ProofPolicy,
    context: &ProofVerificationContext,
    replay_guard: &ReplayGuard,
) -> ConclaveResult<ProofBoundValueBearingAuthorization> {
    ensure_exact_production_policy(policy)?;
    let verified_proofs = registry.verify_bundle(bundle, policy, context, replay_guard)?;
    ProofBoundValueBearingAuthorization::from_verified(verified_proofs)
}

/// Builds proof authorization for a canonical settlement intent. The legacy
/// timestamp argument is retained for source compatibility but ignored; the
/// SDK trusted process clock controls proof freshness. The rail entry point is
/// intentionally deferred: `RailProxy`'s legacy containment path cannot consume
/// this carrier, and no existing serialized request or response shape is
/// widened here.
#[cfg(test)]
pub(crate) fn authorize_settlement_with_proofs(
    registry: &ProofVerifierRegistry,
    bundle: &ProofBundle,
    policy: &ProofPolicy,
    intent: &SwapIntent,
    nonce: Vec<u8>,
    _caller_supplied_now_secs: u64,
    replay_guard: &ReplayGuard,
) -> ConclaveResult<ProofBoundValueBearingAuthorization> {
    authorize_settlement_with_proofs_with_trusted_clock(
        registry,
        bundle,
        policy,
        intent,
        nonce,
        replay_guard,
        crate::enclave::trusted_unix_time_secs(),
    )
}

/// Settlement-specific durable replay entry point. The SDK trusted clock
/// controls freshness; no caller-supplied timestamp is accepted.
pub fn authorize_settlement_with_durable_store(
    registry: &ProofVerifierRegistry,
    bundle: &ProofBundle,
    policy: &ProofPolicy,
    intent: &SwapIntent,
    nonce: Vec<u8>,
    binding_context: &ProofReplayBindingContext,
    replay_store: &dyn ReplayStore,
) -> ConclaveResult<ProofBoundValueBearingAuthorization> {
    ensure_exact_production_policy(policy)?;
    let context = ProofVerificationContext::for_settlement(
        intent,
        nonce,
        crate::enclave::trusted_unix_time_secs()?,
    )?;
    let verified_proofs = registry.verify_bundle_with_durable_store(
        bundle,
        policy,
        &context,
        binding_context,
        replay_store,
    )?;
    ProofBoundValueBearingAuthorization::from_verified_with_durable_binding(
        verified_proofs,
        binding_context,
    )
}

#[cfg(test)]
fn authorize_settlement_with_proofs_with_trusted_clock(
    registry: &ProofVerifierRegistry,
    bundle: &ProofBundle,
    policy: &ProofPolicy,
    intent: &SwapIntent,
    nonce: Vec<u8>,
    replay_guard: &ReplayGuard,
    trusted_now_secs: ConclaveResult<u64>,
) -> ConclaveResult<ProofBoundValueBearingAuthorization> {
    authorize_settlement_with_proofs_at(
        registry,
        bundle,
        policy,
        intent,
        nonce,
        trusted_now_secs?,
        replay_guard,
    )
}

#[cfg(test)]
fn authorize_settlement_with_proofs_at(
    registry: &ProofVerifierRegistry,
    bundle: &ProofBundle,
    policy: &ProofPolicy,
    intent: &SwapIntent,
    nonce: Vec<u8>,
    now_secs: u64,
    replay_guard: &ReplayGuard,
) -> ConclaveResult<ProofBoundValueBearingAuthorization> {
    let context = ProofVerificationContext::for_settlement(intent, nonce, now_secs)?;
    authorize_value_bearing_with_proofs_at(registry, bundle, policy, &context, replay_guard)
}

/// Additive proof-aware signing helper. It checks that the typed signing
/// request is bound to the verified proof context before invoking the existing
/// provider-only value-bearing path. It never calls legacy raw signing.
#[cfg(test)]
pub(crate) fn sign_value_bearing_with_proof_authorization(
    enclave: &dyn EnclaveManager,
    request: ValueBearingSignRequest,
    authorization: &ProofBoundValueBearingAuthorization,
) -> ConclaveResult<ValueBearingSignResponse> {
    sign_value_bearing_with_proof_authorization_with_trusted_clock(
        enclave,
        request,
        authorization,
        crate::enclave::trusted_unix_time_secs(),
    )
}

#[cfg(test)]
fn sign_value_bearing_with_proof_authorization_with_trusted_clock(
    enclave: &dyn EnclaveManager,
    request: ValueBearingSignRequest,
    authorization: &ProofBoundValueBearingAuthorization,
    trusted_now_secs: ConclaveResult<u64>,
) -> ConclaveResult<ValueBearingSignResponse> {
    sign_value_bearing_with_proof_authorization_at(
        enclave,
        request,
        authorization,
        trusted_now_secs?,
    )
}

#[cfg(test)]
fn sign_value_bearing_with_proof_authorization_at(
    enclave: &dyn EnclaveManager,
    request: ValueBearingSignRequest,
    authorization: &ProofBoundValueBearingAuthorization,
    now_secs: u64,
) -> ConclaveResult<ValueBearingSignResponse> {
    authorization.observe_and_validate_at(now_secs)?;
    if !authorization.matches_request(&request)? {
        return Err(ConclaveError::Unsupported(
            "proof authorization does not match value-bearing operation context".to_string(),
        ));
    }
    enclave.sign_value_bearing(request)
}

/// Signs a proof-authorized value-bearing operation only after consuming a
/// distinct complete operation replay binding from the caller-supplied durable
/// store. Duplicate, unavailable, indeterminate, rollback, and non-durable
/// outcomes fail closed before provider code is invoked. The authorization
/// carrier is one-shot and key-bound, so reuse across manager instances cannot
/// produce a second signature.
pub fn sign_value_bearing_with_proof_authorization_and_durable_store(
    enclave: &dyn EnclaveManager,
    request: ValueBearingSignRequest,
    authorization: &ProofBoundValueBearingAuthorization,
    replay_store: &dyn ReplayStore,
) -> ConclaveResult<ValueBearingSignResponse> {
    let now_secs = crate::enclave::trusted_unix_time_secs()?;
    sign_value_bearing_with_proof_authorization_and_durable_store_at(
        enclave,
        request,
        authorization,
        replay_store,
        now_secs,
    )
}

fn sign_value_bearing_with_proof_authorization_and_durable_store_at(
    enclave: &dyn EnclaveManager,
    request: ValueBearingSignRequest,
    authorization: &ProofBoundValueBearingAuthorization,
    replay_store: &dyn ReplayStore,
    now_secs: u64,
) -> ConclaveResult<ValueBearingSignResponse> {
    if replay_store.durability() != ReplayStoreDurability::DurableProvider {
        return Err(ConclaveError::Unsupported(
            "durable replay store is required for proof-authorized final signing".to_string(),
        ));
    }
    authorization.observe_and_validate_at(now_secs)?;
    if !authorization.matches_request(&request)? {
        return Err(ConclaveError::Unsupported(
            "proof authorization does not match value-bearing operation context".to_string(),
        ));
    }

    let durable_binding = authorization.durable_binding.as_ref().ok_or_else(|| {
        ConclaveError::Unsupported(
            "proof authorization is not bound to a durable replay provider".to_string(),
        )
    })?;
    let operation_digest = request.operation_binding()?;
    let evidence_digest = authorization.verified_proofs.digest()?;
    let binding = ReplayBinding::from_component_digests_with_domain(
        VALUE_BEARING_OPERATION_REPLAY_DOMAIN,
        durable_binding.provider.clone(),
        "value-bearing-operation",
        request.algorithm().canonical_token(),
        *authorization.verified_proofs.nonce_digest(),
        operation_digest,
        request.operation_context().purpose().canonical_token(),
        authorization.policy_digest,
        durable_binding.key_identity_digest,
        evidence_digest,
        Some(hex::encode(evidence_digest)),
        Some(request.operation_context().domain().to_string()),
    )
    .map_err(|_| invalid_payload())?;
    let reservation = ReplayReservation::new(&binding, authorization.authorization_expires_at)
        .map_err(|_| invalid_payload())?;

    match replay_store
        .consume_once(&reservation, now_secs)
        .map_err(map_replay_store_error)?
    {
        ReplayConsumeOutcome::Accepted => {}
        ReplayConsumeOutcome::Duplicate => {
            return Err(ConclaveError::EnclaveFailure(
                "value-bearing operation replay detected".to_string(),
            ));
        }
    }

    if authorization
        .final_signing_consumed
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(ConclaveError::EnclaveFailure(
            "proof authorization has already been consumed for final signing".to_string(),
        ));
    }

    let response = enclave.sign_value_bearing_provider(&request)?;
    ValueBearingSignResponse::from_provider_at_time(
        &request,
        response,
        enclave.signer_capability(),
        now_secs,
    )
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
    use crate::enclave::attestation::{
        parse_extension_data, AttestationLevel, AttestationPurpose, AttestationReportType,
        DeviceIntegrityReport, SignerKeyBindingEvidence, ATTESTATION_ENVELOPE_VERSION,
    };
    use crate::enclave::replay_guard::{ReplayBatchOutcome, ReplayGuard};
    use crate::enclave::{
        EnclaveManager, OperationContext, SignResponse, SignerCapability, SignerKeyBinding,
        SigningAlgorithm, TrustRequirement, UnavailableReplayStore, ValueBearingPurpose,
        ValueBearingSignRequest, VALUE_BEARING_POLICY_ID,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    const NOW: u64 = 1_000_000;

    fn fixture_verifier_id(kind: ProofKind) -> String {
        kind.production_verifier_id().to_string()
    }

    fn context() -> ProofVerificationContext {
        context_at(NOW)
    }

    fn context_at(now_secs: u64) -> ProofVerificationContext {
        ProofVerificationContext::new(
            [7; 32],
            "SETTLEMENT",
            "conxian/settlement/v1",
            vec![9; 16],
            now_secs,
        )
        .expect("fixture context")
    }

    fn fixture_proof(kind: ProofKind, proof_id: &str) -> ProofEnvelope {
        fixture_proof_at(kind, proof_id, NOW)
    }

    fn fixture_proof_at(kind: ProofKind, proof_id: &str, now_secs: u64) -> ProofEnvelope {
        let context = context_at(now_secs);
        ProofEnvelope::new(
            kind,
            proof_id,
            fixture_verifier_id(kind),
            context.operation_digest,
            context.purpose.clone(),
            context.audience.clone(),
            context.nonce.clone(),
            now_secs.saturating_sub(10),
            now_secs.saturating_add(60),
            format!("fixture:{}", kind.canonical_name()).into_bytes(),
        )
        .expect("fixture proof")
    }

    fn fixture_bundle() -> ProofBundle {
        fixture_bundle_at(NOW)
    }

    fn fixture_bundle_at(now_secs: u64) -> ProofBundle {
        ProofBundle::new(
            ProofKind::all()
                .into_iter()
                .enumerate()
                .map(|(index, kind)| fixture_proof_at(kind, &format!("proof-{index}"), now_secs))
                .collect(),
        )
        .expect("fixture bundle")
    }

    fn fixture_bundle_for_context(
        context: &ProofVerificationContext,
        now_secs: u64,
    ) -> ProofBundle {
        ProofBundle::new(
            ProofKind::all()
                .into_iter()
                .enumerate()
                .map(|(index, kind)| {
                    ProofEnvelope::new(
                        kind,
                        format!("proof-{index}"),
                        fixture_verifier_id(kind),
                        context.operation_digest,
                        context.purpose.clone(),
                        context.audience.clone(),
                        context.nonce.clone(),
                        now_secs.saturating_sub(10),
                        now_secs.saturating_add(60),
                        format!("fixture:{}", kind.canonical_name()).into_bytes(),
                    )
                    .expect("fixture proof")
                })
                .collect(),
        )
        .expect("fixture bundle")
    }

    fn fixture_policy() -> ProofPolicy {
        ProofPolicy::production()
    }

    fn value_request(context: &ProofVerificationContext) -> ValueBearingSignRequest {
        ValueBearingSignRequest::new(
            OperationContext::new(
                context.audience.clone(),
                ValueBearingPurpose::Settlement,
                context.operation_digest.to_vec(),
            )
            .expect("operation context"),
            SigningAlgorithm::Ed25519,
            TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID).expect("trust requirement"),
            context.operation_digest,
            SignerKeyBinding::new("proof-test-key", "m/44'/0'/0'", vec![3; 32])
                .expect("key binding"),
            None,
        )
        .expect("value-bearing request")
    }

    fn fixture_settlement_intent() -> SwapIntent {
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
        intent
    }

    struct CountingProofVerifier {
        kind: ProofKind,
        verifier_id: String,
        expected_evidence: Vec<u8>,
        calls: Arc<AtomicUsize>,
    }

    impl ProofVerifier for CountingProofVerifier {
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
            self.calls.fetch_add(1, AtomicOrdering::Relaxed);
            if envelope.kind != self.kind
                || envelope.verifier_id != self.verifier_id
                || envelope.evidence != self.expected_evidence
            {
                return Err(proof_verification_failed());
            }
            VerifiedProofReceipt::from_fixture(envelope, context)
        }
    }

    fn counting_registry(calls: Arc<AtomicUsize>) -> ProofVerifierRegistry {
        let kind = ProofKind::Server;
        let verifier_id = fixture_verifier_id(kind);
        let verifier = CountingProofVerifier {
            kind,
            verifier_id: verifier_id.clone(),
            expected_evidence: format!("fixture:{}", kind.canonical_name()).into_bytes(),
            calls,
        };
        let mut verifiers = HashMap::new();
        verifiers.insert(
            (kind, verifier_id),
            Arc::new(verifier) as Arc<dyn ProofVerifier>,
        );
        ProofVerifierRegistry { verifiers }
    }

    struct DurableFixtureReplayStore {
        guard: ReplayGuard,
    }

    impl DurableFixtureReplayStore {
        fn new(max_entries: usize) -> Self {
            Self {
                guard: ReplayGuard::new(300, max_entries),
            }
        }
    }

    impl ReplayStore for DurableFixtureReplayStore {
        fn durability(&self) -> ReplayStoreDurability {
            ReplayStoreDurability::DurableProvider
        }

        fn consume_once(
            &self,
            reservation: &ReplayReservation,
            now_secs: u64,
        ) -> Result<ReplayConsumeOutcome, ReplayStoreError> {
            self.guard.consume_once(reservation, now_secs)
        }

        fn consume_once_batch(
            &self,
            reservations: &[ReplayReservation],
            now_secs: u64,
        ) -> Result<ReplayBatchOutcome, ReplayStoreError> {
            self.guard.consume_once_batch(reservations, now_secs)
        }
    }

    struct DurableFixtureProvider {
        operation_key: SigningKey,
        provider_calls: AtomicUsize,
    }

    impl DurableFixtureProvider {
        fn new() -> Self {
            Self {
                operation_key: SigningKey::from_bytes(&[7; 32]),
                provider_calls: AtomicUsize::new(0),
            }
        }

        fn request(&self, context: &ProofVerificationContext) -> ValueBearingSignRequest {
            ValueBearingSignRequest::new(
                OperationContext::new(
                    context.audience.clone(),
                    ValueBearingPurpose::Settlement,
                    context.operation_digest.to_vec(),
                )
                .expect("operation context"),
                SigningAlgorithm::Ed25519,
                TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID)
                    .expect("trust requirement"),
                context.operation_digest,
                SignerKeyBinding::new(
                    "durable-test-key",
                    "m/44'/0'/0'",
                    self.operation_key.verifying_key().to_bytes().to_vec(),
                )
                .expect("key binding"),
                None,
            )
            .expect("value-bearing request")
        }

        fn response_for(&self, request: &ValueBearingSignRequest) -> SignResponse {
            let attestation_key = crate::enclave::attestation::test_signing_key();
            let operation_public_key = self.operation_key.verifying_key().to_bytes();
            let extension_data =
                "PURPOSE_SIGN|ALGORITHM_ED25519|TEE_ENABLED|HARDWARE_ROOT_OF_TRUST|OS_VERSION_14"
                    .to_string();
            let extensions = parse_extension_data(&extension_data).expect("extensions");
            let mut report = DeviceIntegrityReport {
                report_version: ATTESTATION_ENVELOPE_VERSION,
                report_type: AttestationReportType::DeviceIntegrity,
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
                        crate::enclave::attestation::AttestationAlgorithm::Ed25519,
                    )
                    .expect("key binding evidence"),
                ),
                certificate_chain: vec![
                    hex::encode(attestation_key.verifying_key().to_bytes()),
                    "CONCLAVE_ROOT_CA_V1".to_string(),
                ],
                timestamp: crate::enclave::trusted_unix_time_secs()
                    .expect("test host clock should be available"),
                extension_data,
                extensions,
            };
            report
                .sign_with_ed25519_key(&attestation_key)
                .expect("attestation report");
            SignResponse {
                signature_hex: hex::encode(
                    self.operation_key.sign(request.message_digest()).to_bytes(),
                ),
                public_key_hex: hex::encode(operation_public_key),
                device_attestation: Some(serde_json::to_string(&report).expect("attestation json")),
            }
        }
    }

    impl EnclaveManager for DurableFixtureProvider {
        fn initialize(&self) -> ConclaveResult<()> {
            Ok(())
        }

        fn generate_key(&self, key_id: &str) -> ConclaveResult<String> {
            Ok(key_id.to_string())
        }

        fn get_public_key(&self, _derivation_path: &str) -> ConclaveResult<String> {
            Ok(hex::encode(self.operation_key.verifying_key().to_bytes()))
        }

        fn sign(&self, _request: crate::enclave::SignRequest) -> ConclaveResult<SignResponse> {
            Err(ConclaveError::EnclaveFailure(
                "durable fixture raw sign must not be called".to_string(),
            ))
        }

        fn signer_capability(&self) -> SignerCapability {
            SignerCapability::provider_verified(VALUE_BEARING_POLICY_ID)
                .expect("provider capability")
        }

        fn sign_value_bearing_provider(
            &self,
            request: &ValueBearingSignRequest,
        ) -> ConclaveResult<SignResponse> {
            self.provider_calls.fetch_add(1, AtomicOrdering::Relaxed);
            Ok(self.response_for(request))
        }
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
        let zero_lifetime = ProofEnvelope::new(
            ProofKind::Server,
            "zero-lifetime",
            fixture_verifier_id(ProofKind::Server),
            [7; 32],
            "SETTLEMENT",
            "audience",
            vec![1],
            NOW,
            NOW,
            vec![1],
        );
        assert!(zero_lifetime.is_err());
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

    #[test]
    fn policy_digest_is_canonical_and_bound_to_verified_receipts() {
        let policy = fixture_policy();
        let mut reversed_required = policy.required.clone();
        reversed_required.reverse();
        let reordered = ProofPolicy::new(reversed_required, policy.unlisted).expect("policy");
        assert_eq!(
            policy.digest().expect("policy digest"),
            reordered.digest().expect("digest")
        );

        let mut changed = policy.clone();
        changed.required[0].verifier_id = "different-production-route".to_string();
        assert_ne!(
            policy.digest().expect("policy digest"),
            changed.digest().expect("digest")
        );

        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let verified = registry
            .verify_bundle(
                &fixture_bundle(),
                &policy,
                &context(),
                &ReplayGuard::new(300, 32),
            )
            .expect("verified set");
        assert_eq!(
            verified.policy_digest(),
            &policy.digest().expect("policy digest")
        );
        assert_eq!(verified.effective_expires_at(), Some(NOW + 60));
    }

    #[test]
    fn effective_expiry_uses_the_first_proof_validity_boundary() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let policy = ProofPolicy::new(
            vec![
                ProofRequirement::new(ProofKind::Server, fixture_verifier_id(ProofKind::Server))
                    .expect("requirement"),
            ],
            UnlistedProofPolicy::Reject,
        )
        .expect("policy");
        let mut proof = fixture_proof(ProofKind::Server, "effective-expiry");
        proof.issued_at = NOW - 4;
        proof.expires_at = NOW + 100;
        let context = context()
            .with_freshness_window(5, DEFAULT_MAX_PROOF_FUTURE_SKEW_SECS)
            .expect("freshness window");
        let verified = registry
            .verify_bundle(
                &ProofBundle::new(vec![proof]).expect("bundle"),
                &policy,
                &context,
                &ReplayGuard::new(300, 32),
            )
            .expect("proof verifies");

        assert_eq!(verified.effective_expires_at(), Some(NOW + 1));
        assert_eq!(
            verified
                .receipt_for_kind(ProofKind::Server)
                .expect("receipt")
                .effective_expires_at(),
            NOW + 1
        );
    }

    #[test]
    fn replay_is_rejected_after_legacy_ttl_before_proof_expiry() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let bundle = fixture_bundle();
        let policy = fixture_policy();
        let guard = ReplayGuard::new(1, 32);

        registry
            .verify_bundle(&bundle, &policy, &context_at(NOW), &guard)
            .expect("first proof bundle");
        assert!(matches!(
            registry.verify_bundle(&bundle, &policy, &context_at(NOW + 2), &guard),
            Err(ConclaveError::EnclaveFailure(message))
                if message.contains("replay detected")
        ));
    }

    #[test]
    fn weak_policy_cannot_authorize_value_bearing_operations() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let one_proof = ProofBundle::new(vec![fixture_proof(ProofKind::Server, "weak")])
            .expect("one-proof bundle");
        let weak_policy = ProofPolicy::new(
            vec![
                ProofRequirement::new(ProofKind::Server, fixture_verifier_id(ProofKind::Server))
                    .expect("weak requirement"),
            ],
            UnlistedProofPolicy::Reject,
        )
        .expect("weak policy");

        registry
            .verify_bundle(
                &one_proof,
                &weak_policy,
                &context(),
                &ReplayGuard::new(300, 32),
            )
            .expect("generic independent verification remains configurable");
        assert!(matches!(
            authorize_value_bearing_with_proofs(
                &registry,
                &one_proof,
                &weak_policy,
                &context(),
                &ReplayGuard::new(300, 32),
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("exact production proof policy")
        ));
    }

    #[test]
    fn reduced_policy_cannot_authorize_settlement_helper() {
        let weak_policy = ProofPolicy::new(
            vec![
                ProofRequirement::new(ProofKind::Server, fixture_verifier_id(ProofKind::Server))
                    .expect("weak requirement"),
            ],
            UnlistedProofPolicy::Reject,
        )
        .expect("weak policy");

        assert!(matches!(
            authorize_settlement_with_proofs(
                &ProofVerifierRegistry::test_fixture_all_six(),
                &fixture_bundle(),
                &weak_policy,
                &fixture_settlement_intent(),
                vec![1; 16],
                NOW,
                &ReplayGuard::new(300, 32),
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("exact production proof policy")
        ));
    }

    #[test]
    fn empty_policy_and_bundle_cannot_create_value_bearing_authorization() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let empty_bundle = ProofBundle::new(Vec::new()).expect("empty bundle shape");
        let empty_policy =
            ProofPolicy::new(Vec::new(), UnlistedProofPolicy::Reject).expect("empty policy shape");

        assert!(matches!(
            authorize_value_bearing_with_proofs(
                &registry,
                &empty_bundle,
                &empty_policy,
                &context(),
                &ReplayGuard::new(300, 32),
            ),
            Err(ConclaveError::Unsupported(_))
        ));
    }

    #[test]
    fn proof_authorization_rechecks_expiry_before_hardware_signing_gate() {
        let authorization = authorize_value_bearing_with_proofs_at(
            &ProofVerifierRegistry::test_fixture_all_six(),
            &fixture_bundle(),
            &ProofPolicy::production(),
            &context(),
            &ReplayGuard::new(300, 32),
        )
        .expect("test-only production-shaped authorization");
        let request = value_request(&context());
        let enclave = crate::enclave::UnavailableEnclave;

        assert!(matches!(
            sign_value_bearing_with_proof_authorization_at(
                &enclave,
                request.clone(),
                &authorization,
                NOW + 59,
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("provider-verified hardware enclave")
        ));
        assert!(matches!(
            sign_value_bearing_with_proof_authorization_at(
                &enclave,
                request,
                &authorization,
                NOW + 60,
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("proof authorization has expired")
        ));
    }

    #[test]
    fn public_proof_authorization_ignores_caller_supplied_future_time() {
        let trusted_now =
            crate::enclave::trusted_unix_time_secs().expect("test host clock should be available");
        let future_now = trusted_now
            .checked_add(DEFAULT_MAX_PROOF_FUTURE_SKEW_SECS + 60)
            .expect("future test timestamp");
        let future_context = context_at(future_now);
        let future_bundle = fixture_bundle_at(future_now);

        assert!(matches!(
            authorize_value_bearing_with_proofs(
                &ProofVerifierRegistry::test_fixture_all_six(),
                &future_bundle,
                &ProofPolicy::production(),
                &future_context,
                &ReplayGuard::new(300, 32),
            ),
            Err(ConclaveError::EnclaveFailure(message))
                if message.contains("independent proof verification failed")
        ));
    }

    #[test]
    fn proof_authorization_clock_failure_precedes_verification_and_replay_recording() {
        let context = context();
        let bundle = fixture_bundle();
        let replay_guard = ReplayGuard::new(300, 32);
        let pre_epoch = SystemTime::UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .expect("pre-epoch fixture should be representable");

        assert!(matches!(
            authorize_value_bearing_with_proofs_with_trusted_clock(
                &ProofVerifierRegistry::test_fixture_all_six(),
                &bundle,
                &ProofPolicy::production(),
                &context,
                &replay_guard,
                crate::enclave::trusted_unix_time_secs_at(pre_epoch),
            ),
            Err(ConclaveError::ClockUnavailable)
        ));

        // The failed clock acquisition did not reserve any proof replay keys.
        assert!(authorize_value_bearing_with_proofs_at(
            &ProofVerifierRegistry::test_fixture_all_six(),
            &bundle,
            &ProofPolicy::production(),
            &context,
            &replay_guard,
        )
        .is_ok());
    }

    #[test]
    fn public_settlement_authorization_ignores_caller_supplied_future_time() {
        let intent = fixture_settlement_intent();
        let trusted_now =
            crate::enclave::trusted_unix_time_secs().expect("test host clock should be available");
        let future_now = trusted_now
            .checked_add(DEFAULT_MAX_PROOF_FUTURE_SKEW_SECS + 60)
            .expect("future test timestamp");
        let future_context =
            ProofVerificationContext::for_settlement(&intent, vec![1; 16], future_now)
                .expect("future settlement context");
        let future_bundle = fixture_bundle_for_context(&future_context, future_now);

        assert!(matches!(
            authorize_settlement_with_proofs(
                &ProofVerifierRegistry::test_fixture_all_six(),
                &future_bundle,
                &ProofPolicy::production(),
                &intent,
                vec![1; 16],
                future_now,
                &ReplayGuard::new(300, 32),
            ),
            Err(ConclaveError::EnclaveFailure(message))
                if message.contains("independent proof verification failed")
        ));
    }

    #[test]
    fn settlement_authorization_clock_failure_precedes_verification_and_replay_recording() {
        let intent = fixture_settlement_intent();
        let nonce = vec![1; 16];
        let bundle_context = ProofVerificationContext::for_settlement(&intent, nonce.clone(), NOW)
            .expect("settlement fixture context");
        let bundle = fixture_bundle_for_context(&bundle_context, NOW);
        let replay_guard = ReplayGuard::new(300, 32);
        let pre_epoch = SystemTime::UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .expect("pre-epoch fixture should be representable");

        assert!(matches!(
            authorize_settlement_with_proofs_with_trusted_clock(
                &ProofVerifierRegistry::test_fixture_all_six(),
                &bundle,
                &ProofPolicy::production(),
                &intent,
                nonce.clone(),
                &replay_guard,
                crate::enclave::trusted_unix_time_secs_at(pre_epoch),
            ),
            Err(ConclaveError::ClockUnavailable)
        ));

        // The failed clock acquisition did not reserve any settlement proof
        // replay keys.
        assert!(authorize_settlement_with_proofs_at(
            &ProofVerifierRegistry::test_fixture_all_six(),
            &bundle,
            &ProofPolicy::production(),
            &intent,
            nonce,
            NOW,
            &replay_guard,
        )
        .is_ok());
    }

    #[test]
    fn proof_authorization_rejects_clock_rollback_after_expiry() {
        let base = 100;
        let context = context_at(base);
        let mut bundle = fixture_bundle_at(base);
        for proof in &mut bundle.proofs {
            proof.expires_at = 110;
        }
        let authorization = authorize_value_bearing_with_proofs_at(
            &ProofVerifierRegistry::test_fixture_all_six(),
            &bundle,
            &ProofPolicy::production(),
            &context,
            &ReplayGuard::new(300, 32),
        )
        .expect("test-only production-shaped authorization");
        let request = value_request(&context);
        let enclave = crate::enclave::UnavailableEnclave;

        assert!(matches!(
            sign_value_bearing_with_proof_authorization_at(
                &enclave,
                request.clone(),
                &authorization,
                109,
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("provider-verified hardware enclave")
        ));
        assert!(matches!(
            sign_value_bearing_with_proof_authorization_at(
                &enclave,
                request.clone(),
                &authorization,
                111,
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("proof authorization has expired")
        ));
        assert!(matches!(
            sign_value_bearing_with_proof_authorization_at(&enclave, request, &authorization, 105,),
            Err(ConclaveError::ClockRollback)
        ));
    }

    #[test]
    fn proof_signing_clock_failure_precedes_authorization_consumption() {
        let context = context();
        let authorization = authorize_value_bearing_with_proofs_at(
            &ProofVerifierRegistry::test_fixture_all_six(),
            &fixture_bundle(),
            &ProofPolicy::production(),
            &context,
            &ReplayGuard::new(300, 32),
        )
        .expect("test-only production-shaped authorization");
        let request = value_request(&context);
        let pre_epoch = SystemTime::UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .expect("pre-epoch fixture should be representable");

        assert!(matches!(
            sign_value_bearing_with_proof_authorization_with_trusted_clock(
                &crate::enclave::UnavailableEnclave,
                request.clone(),
                &authorization,
                crate::enclave::trusted_unix_time_secs_at(pre_epoch),
            ),
            Err(ConclaveError::ClockUnavailable)
        ));

        assert!(matches!(
            sign_value_bearing_with_proof_authorization_at(
                &crate::enclave::UnavailableEnclave,
                request,
                &authorization,
                NOW,
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("provider-verified hardware enclave")
        ));
    }

    #[test]
    fn public_proof_signing_path_uses_trusted_clock_and_hardware_gate() {
        let now_secs =
            crate::enclave::trusted_unix_time_secs().expect("test host clock should be available");
        let context = context_at(now_secs);
        let authorization = authorize_value_bearing_with_proofs(
            &ProofVerifierRegistry::test_fixture_all_six(),
            &fixture_bundle_at(now_secs),
            &ProofPolicy::production(),
            &context,
            &ReplayGuard::new(300, 32),
        )
        .expect("test-only production-shaped authorization");

        assert!(matches!(
            sign_value_bearing_with_proof_authorization(
                &crate::enclave::UnavailableEnclave,
                value_request(&context),
                &authorization,
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("provider-verified hardware enclave")
        ));
    }

    #[test]
    fn proof_authorization_rejects_context_mismatch_before_signing() {
        let authorization = authorize_value_bearing_with_proofs_at(
            &ProofVerifierRegistry::test_fixture_all_six(),
            &fixture_bundle(),
            &ProofPolicy::production(),
            &context(),
            &ReplayGuard::new(300, 32),
        )
        .expect("test-only production-shaped authorization");
        let mut wrong_context = context();
        wrong_context.operation_digest = [8; 32];
        let request = value_request(&wrong_context);

        assert!(matches!(
            sign_value_bearing_with_proof_authorization_at(
                &crate::enclave::UnavailableEnclave,
                request,
                &authorization,
                NOW + 1,
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("does not match value-bearing operation context")
        ));
    }

    #[test]
    fn bounded_deserialization_rejects_oversized_security_fields_and_sequences() {
        let mut oversized_evidence = fixture_proof(ProofKind::Server, "oversized-evidence");
        oversized_evidence.evidence = vec![1; MAX_EVIDENCE_BYTES + 1];
        let evidence_bytes = serde_json::to_vec(&oversized_evidence).expect("serialize evidence");
        assert!(serde_json::from_slice::<ProofEnvelope>(&evidence_bytes).is_err());

        let mut oversized_nonce = fixture_proof(ProofKind::Server, "oversized-nonce");
        oversized_nonce.nonce = vec![1; MAX_NONCE_BYTES + 1];
        let nonce_bytes = serde_json::to_vec(&oversized_nonce).expect("serialize nonce");
        assert!(serde_json::from_slice::<ProofEnvelope>(&nonce_bytes).is_err());

        let mut oversized_identifier = fixture_proof(ProofKind::Server, "oversized-id");
        oversized_identifier.proof_id = "x".repeat(MAX_IDENTIFIER_BYTES + 1);
        let identifier_bytes = serde_json::to_vec(&oversized_identifier).expect("serialize id");
        assert!(serde_json::from_slice::<ProofEnvelope>(&identifier_bytes).is_err());

        let oversized_bundle = ProofBundle {
            proofs: vec![fixture_proof(ProofKind::Server, "repeated"); MAX_PROOF_BUNDLE_SIZE + 1],
        };
        let bundle_bytes = serde_json::to_vec(&oversized_bundle).expect("serialize bundle");
        assert!(deserialize_proof_bundle_json(&bundle_bytes).is_err());

        let oversized_policy = ProofPolicy {
            required: vec![
                ProofRequirement::new(
                    ProofKind::Server,
                    fixture_verifier_id(ProofKind::Server)
                )
                .expect("requirement");
                MAX_PROOF_BUNDLE_SIZE + 1
            ],
            unlisted: UnlistedProofPolicy::Reject,
        };
        let policy_bytes = serde_json::to_vec(&oversized_policy).expect("serialize policy");
        assert!(serde_json::from_slice::<ProofPolicy>(&policy_bytes).is_err());
    }

    #[test]
    fn bounded_transport_entry_point_rejects_oversized_input() {
        let oversized = vec![b' '; MAX_PROOF_TRANSPORT_BYTES + 1];
        assert!(deserialize_proof_bundle_json(&oversized).is_err());
    }

    #[test]
    fn bounded_transport_rejects_unknown_fields_before_provider_verification() {
        let bundle = ProofBundle::new(vec![fixture_proof(ProofKind::Server, "transport")])
            .expect("transport bundle");
        let policy = ProofPolicy::new(
            vec![
                ProofRequirement::new(ProofKind::Server, fixture_verifier_id(ProofKind::Server))
                    .expect("requirement"),
            ],
            UnlistedProofPolicy::Reject,
        )
        .expect("policy");
        let context = context();
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = counting_registry(Arc::clone(&calls));

        let mut unknown = serde_json::to_value(&bundle).expect("serialize bundle");
        unknown["unexpected"] = serde_json::Value::String("x".repeat(1024));
        let unknown_bytes = serde_json::to_vec(&unknown).expect("serialize unknown field");
        let unknown_result = deserialize_proof_bundle_json(&unknown_bytes).and_then(|parsed| {
            registry.verify_bundle(&parsed, &policy, &context, &ReplayGuard::new(300, 32))
        });
        assert!(unknown_result.is_err());
        assert_eq!(calls.load(AtomicOrdering::Relaxed), 0);

        unknown["unexpected"] = serde_json::Value::String("x".repeat(MAX_PROOF_TRANSPORT_BYTES));
        let oversized_unknown_bytes = serde_json::to_vec(&unknown).expect("serialize oversized");
        let oversized_result =
            deserialize_proof_bundle_json(&oversized_unknown_bytes).and_then(|parsed| {
                registry.verify_bundle(&parsed, &policy, &context, &ReplayGuard::new(300, 32))
            });
        assert!(oversized_result.is_err());
        assert_eq!(calls.load(AtomicOrdering::Relaxed), 0);
    }

    #[test]
    fn complete_replay_binding_store_path_is_atomic_and_ordered() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let policy = ProofPolicy::production();
        let context = context();
        let binding_context = ProofReplayBindingContext::new("aws.nitro", b"key-id|public-key")
            .expect("binding context");
        let store = ReplayGuard::new(300, 32);

        let verified = registry
            .verify_bundle_with_store(
                &fixture_bundle(),
                &policy,
                &context,
                &binding_context,
                &store,
            )
            .expect("fixture store path should verify");
        assert_eq!(verified.len(), ProofKind::all().len());
        assert!(matches!(
            registry.verify_bundle_with_store(
                &fixture_bundle(),
                &policy,
                &context,
                &binding_context,
                &store,
            ),
            Err(ConclaveError::EnclaveFailure(message))
                if message.contains("replay batch")
        ));
    }

    #[test]
    fn durable_store_gate_rejects_process_local_replay() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let binding_context =
            ProofReplayBindingContext::new("aws.nitro", b"key-id").expect("binding context");
        assert!(matches!(
            registry.verify_bundle_with_durable_store(
                &fixture_bundle(),
                &ProofPolicy::production(),
                &context(),
                &binding_context,
                &ReplayGuard::new(300, 32),
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("durable replay store")
        ));
    }

    #[test]
    fn durable_authorization_requires_exact_canonical_production_policy() {
        let now_secs =
            crate::enclave::trusted_unix_time_secs().expect("test host clock should be available");
        let context = context_at(now_secs);
        let bundle = fixture_bundle_at(now_secs);
        let provider = DurableFixtureProvider::new();
        let request = provider.request(&context);
        let binding_context =
            ProofReplayBindingContext::for_signer_key("fixture-provider", request.key_binding())
                .expect("binding context");

        let mut reordered = ProofPolicy::production();
        reordered.required.reverse();
        assert!(reordered.is_exact_production());
        assert!(authorize_value_bearing_with_durable_store(
            &ProofVerifierRegistry::test_fixture_all_six(),
            &bundle,
            &reordered,
            &context,
            &binding_context,
            &DurableFixtureReplayStore::new(32),
        )
        .is_ok());

        let reduced = ProofPolicy::new(
            vec![
                ProofRequirement::new(ProofKind::Server, fixture_verifier_id(ProofKind::Server))
                    .expect("reduced requirement"),
            ],
            UnlistedProofPolicy::Reject,
        )
        .expect("reduced policy");
        assert!(matches!(
            authorize_value_bearing_with_durable_store(
                &ProofVerifierRegistry::test_fixture_all_six(),
                &bundle,
                &reduced,
                &context,
                &binding_context,
                &DurableFixtureReplayStore::new(32),
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("exact production proof policy")
        ));

        let empty = ProofPolicy {
            required: Vec::new(),
            unlisted: UnlistedProofPolicy::Reject,
        };
        assert!(matches!(
            authorize_value_bearing_with_durable_store(
                &ProofVerifierRegistry::test_fixture_all_six(),
                &ProofBundle::new(Vec::new()).expect("empty bundle"),
                &empty,
                &context,
                &binding_context,
                &DurableFixtureReplayStore::new(32),
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("exact production proof policy")
        ));

        let mut changed = ProofPolicy::production();
        changed.required[0].verifier_id = "changed-production-route".to_string();
        assert!(!changed.is_exact_production());
        assert!(matches!(
            authorize_value_bearing_with_durable_store(
                &ProofVerifierRegistry::test_fixture_all_six(),
                &bundle,
                &changed,
                &context,
                &binding_context,
                &DurableFixtureReplayStore::new(32),
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("exact production proof policy")
        ));
    }

    #[test]
    fn process_local_replay_cannot_authorize_public_durable_value_path() {
        let now_secs =
            crate::enclave::trusted_unix_time_secs().expect("test host clock should be available");
        let context = context_at(now_secs);
        let provider = DurableFixtureProvider::new();
        let request = provider.request(&context);
        let binding_context =
            ProofReplayBindingContext::for_signer_key("fixture-provider", request.key_binding())
                .expect("binding context");

        assert!(matches!(
            authorize_value_bearing_with_durable_store(
                &ProofVerifierRegistry::test_fixture_all_six(),
                &fixture_bundle_at(now_secs),
                &ProofPolicy::production(),
                &context,
                &binding_context,
                &ReplayGuard::new(300, 32),
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("durable replay store")
        ));
    }

    #[test]
    fn durable_final_signing_consumes_operation_replay_once_across_managers() {
        let now_secs =
            crate::enclave::trusted_unix_time_secs().expect("test host clock should be available");
        let context = context_at(now_secs);
        let provider_one = DurableFixtureProvider::new();
        let provider_two = DurableFixtureProvider::new();
        let request = provider_one.request(&context);
        let binding_context =
            ProofReplayBindingContext::for_signer_key("fixture-provider", request.key_binding())
                .expect("binding context");
        let store = DurableFixtureReplayStore::new(64);
        let authorization = authorize_value_bearing_with_durable_store(
            &ProofVerifierRegistry::test_fixture_all_six(),
            &fixture_bundle_at(now_secs),
            &ProofPolicy::production(),
            &context,
            &binding_context,
            &store,
        )
        .expect("durable authorization");

        assert!(
            sign_value_bearing_with_proof_authorization_and_durable_store(
                &provider_one,
                request.clone(),
                &authorization,
                &store,
            )
            .is_ok()
        );
        assert_eq!(provider_one.provider_calls.load(AtomicOrdering::Relaxed), 1);

        assert!(matches!(
            sign_value_bearing_with_proof_authorization_and_durable_store(
                &provider_two,
                request,
                &authorization,
                &store,
            ),
            Err(ConclaveError::EnclaveFailure(message))
                if message.contains("replay detected")
        ));
        assert_eq!(provider_two.provider_calls.load(AtomicOrdering::Relaxed), 0);
    }

    #[test]
    fn durable_final_signing_fails_closed_before_provider_on_uncertain_store() {
        let now_secs =
            crate::enclave::trusted_unix_time_secs().expect("test host clock should be available");
        let context = context_at(now_secs);
        let provider = DurableFixtureProvider::new();
        let request = provider.request(&context);
        let binding_context =
            ProofReplayBindingContext::for_signer_key("fixture-provider", request.key_binding())
                .expect("binding context");
        let store = DurableFixtureReplayStore::new(64);
        let authorization = authorize_value_bearing_with_durable_store(
            &ProofVerifierRegistry::test_fixture_all_six(),
            &fixture_bundle_at(now_secs),
            &ProofPolicy::production(),
            &context,
            &binding_context,
            &store,
        )
        .expect("durable authorization");

        assert!(matches!(
            sign_value_bearing_with_proof_authorization_and_durable_store(
                &provider,
                request.clone(),
                &authorization,
                &IndeterminateReplayStore,
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("unavailable or indeterminate")
        ));
        assert_eq!(provider.provider_calls.load(AtomicOrdering::Relaxed), 0);

        assert!(matches!(
            sign_value_bearing_with_proof_authorization_and_durable_store(
                &provider,
                request,
                &authorization,
                &UnavailableReplayStore,
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("durable replay store")
        ));
        assert_eq!(provider.provider_calls.load(AtomicOrdering::Relaxed), 0);
    }

    #[test]
    fn durable_final_signing_rejects_policy_digest_mutation() {
        let now_secs =
            crate::enclave::trusted_unix_time_secs().expect("test host clock should be available");
        let context = context_at(now_secs);
        let provider = DurableFixtureProvider::new();
        let request = provider.request(&context);
        let binding_context =
            ProofReplayBindingContext::for_signer_key("fixture-provider", request.key_binding())
                .expect("binding context");
        let store = DurableFixtureReplayStore::new(64);
        let mut authorization = authorize_value_bearing_with_durable_store(
            &ProofVerifierRegistry::test_fixture_all_six(),
            &fixture_bundle_at(now_secs),
            &ProofPolicy::production(),
            &context,
            &binding_context,
            &store,
        )
        .expect("durable authorization");
        authorization.policy_digest[0] ^= 1;

        assert!(matches!(
            sign_value_bearing_with_proof_authorization_and_durable_store(
                &provider,
                request,
                &authorization,
                &store,
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("does not match")
        ));
        assert_eq!(provider.provider_calls.load(AtomicOrdering::Relaxed), 0);
    }

    struct IndeterminateReplayStore;

    impl ReplayStore for IndeterminateReplayStore {
        fn durability(&self) -> crate::enclave::ReplayStoreDurability {
            crate::enclave::ReplayStoreDurability::DurableProvider
        }

        fn consume_once(
            &self,
            _reservation: &crate::enclave::ReplayReservation,
            _now_secs: u64,
        ) -> Result<crate::enclave::ReplayConsumeOutcome, crate::enclave::ReplayStoreError>
        {
            Err(crate::enclave::ReplayStoreError::TransactionIndeterminate)
        }

        fn consume_once_batch(
            &self,
            _reservations: &[crate::enclave::ReplayReservation],
            _now_secs: u64,
        ) -> Result<crate::enclave::ReplayBatchOutcome, crate::enclave::ReplayStoreError> {
            Err(crate::enclave::ReplayStoreError::TransactionIndeterminate)
        }
    }

    #[test]
    fn indeterminate_replay_store_outcome_fails_closed() {
        let registry = ProofVerifierRegistry::test_fixture_all_six();
        let binding_context =
            ProofReplayBindingContext::new("aws.nitro", b"key-id").expect("binding context");
        assert!(matches!(
            registry.verify_bundle_with_store(
                &fixture_bundle(),
                &ProofPolicy::production(),
                &context(),
                &binding_context,
                &IndeterminateReplayStore,
            ),
            Err(ConclaveError::Unsupported(message))
                if message.contains("unavailable or indeterminate")
        ));
    }
}
