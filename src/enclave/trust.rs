//! Provider-neutral trust, collateral, and normalized attestation contracts.
//!
//! This module deliberately stops at a contract boundary. The production
//! authenticator and verifier are explicit unavailable routes; provider
//! implementations, roots, collateral services, and hardware/runtime
//! integrations belong in later provider-specific work. JSON is transport
//! only. All security-sensitive digests and signatures use the deterministic
//! canonical encodings below.

use crate::enclave::proofs::{ProofKind, ProofPolicy, ProofVerificationContext};
#[cfg(test)]
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
#[cfg(test)]
use ed25519_dalek::{Signer, SigningKey};
use serde::de::{self, Deserializer, Error as DeError, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Current version of all Phase A transport and canonical contracts.
pub const TRUST_CONTRACT_VERSION: u16 = 1;

/// Domain separators are public so provider adapters can pin the exact
/// contract they implement without copying an undocumented string.
pub const TRUST_ANCHOR_DOMAIN: &str = "CONXIAN-TRUST-ANCHOR/v1";
pub const TRUST_BUNDLE_DOMAIN: &str = "CONXIAN-TRUST-BUNDLE/v1";
pub const COLLATERAL_SNAPSHOT_DOMAIN: &str = "CONXIAN-COLLATERAL-SNAPSHOT/v1";
pub const ATTESTATION_EVIDENCE_DOMAIN: &str = "CONXIAN-ATTESTATION-EVIDENCE/v1";
pub const ATTESTATION_RESULT_DOMAIN: &str = "CONXIAN-ATTESTATION-RESULT/v1";
pub const TRUST_AUDIT_DOMAIN: &str = "CONXIAN-TRUST-AUDIT/v1";

pub const MAX_TRUST_TRANSPORT_BYTES: usize = 256 * 1024;
pub const MAX_TRUST_IDENTIFIER_BYTES: usize = 256;
pub const MAX_TRUST_ANCHORS: usize = 32;
pub const MAX_TRUST_PUBLIC_KEY_BYTES: usize = 512;
pub const MAX_TRUST_CONSTRAINT_BYTES: usize = 8 * 1024;
pub const MAX_TRUST_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_TRUST_SIGNATURE_BYTES: usize = 512;

/// Secret-safe trust contract failures. No variant contains caller-controlled
/// identifiers, evidence, signatures, or payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    #[error("trust contract input is invalid")]
    InvalidPayload,
    #[error("trust contract version is unsupported")]
    UnsupportedVersion,
    #[error("trust contract signature is invalid")]
    InvalidSignature,
    #[error("trust contract digest does not match")]
    DigestMismatch,
    #[error("trust provider or profile does not match")]
    ProviderProfileMismatch,
    #[error("trust mechanism does not match")]
    MechanismMismatch,
    #[error("trust validity window is invalid")]
    InvalidValidityWindow,
    #[error("trust revision or rollback floor is invalid")]
    InvalidRevision,
    #[error("trust revision is below the rollback floor")]
    RollbackRejected,
    #[error("trust status is not authorizable")]
    StatusNotAuthorizable,
    #[error("trusted clock is unavailable")]
    ClockUnavailable,
    #[error("trusted clock moved backwards")]
    ClockRollback,
    #[error("trust authenticator is unavailable")]
    AuthenticatorUnavailable,
    #[error("trust verifier is unavailable")]
    VerifierUnavailable,
    #[error("trust route is unsupported")]
    Unsupported,
}

pub type TrustResult<T> = Result<T, TrustError>;

/// Revocation state is explicit. Only `Good` is authorizable.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RevocationStatus {
    Good,
    Revoked,
    Unknown,
    Unavailable,
    Expired,
    NotYetValid,
    Unsupported,
}

impl RevocationStatus {
    pub const fn canonical_tag(self) -> u8 {
        match self {
            Self::Good => 1,
            Self::Revoked => 2,
            Self::Unknown => 3,
            Self::Unavailable => 4,
            Self::Expired => 5,
            Self::NotYetValid => 6,
            Self::Unsupported => 7,
        }
    }

    pub const fn is_authorizable(self) -> bool {
        matches!(self, Self::Good)
    }
}

/// TCB state is explicit. Only `Good` is authorizable.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TcbStatus {
    Good,
    Revoked,
    Unknown,
    Unavailable,
    Expired,
    NotYetValid,
    Unsupported,
}

impl TcbStatus {
    pub const fn canonical_tag(self) -> u8 {
        match self {
            Self::Good => 1,
            Self::Revoked => 2,
            Self::Unknown => 3,
            Self::Unavailable => 4,
            Self::Expired => 5,
            Self::NotYetValid => 6,
            Self::Unsupported => 7,
        }
    }

    pub const fn is_authorizable(self) -> bool {
        matches!(self, Self::Good)
    }
}

/// Phase A has one testable signature encoding. Provider-specific algorithms
/// remain a separate gate and cannot be silently substituted.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TrustSignatureAlgorithm {
    Ed25519,
}

impl TrustSignatureAlgorithm {
    pub const fn canonical_tag(self) -> u8 {
        match self {
            Self::Ed25519 => 1,
        }
    }

    const fn public_key_len(self) -> usize {
        match self {
            Self::Ed25519 => 32,
        }
    }

    const fn signature_len(self) -> usize {
        match self {
            Self::Ed25519 => 64,
        }
    }
}

/// A trusted clock is an internal dependency of verification and replay
/// authorization. Callers pass a clock object, not a timestamp, to the public
/// orchestration helpers.
pub trait TrustedClock: Send + Sync {
    fn now_secs(&self) -> TrustResult<u64>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTrustedClock;

impl TrustedClock for SystemTrustedClock {
    fn now_secs(&self) -> TrustResult<u64> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TrustError::ClockUnavailable)?;
        Ok(duration.as_secs())
    }
}

fn validate_identifier(value: &str) -> TrustResult<()> {
    if value.is_empty()
        || value.len() > MAX_TRUST_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(TrustError::InvalidPayload);
    }
    Ok(())
}

fn validate_bytes(value: &[u8], maximum: usize, require_non_empty: bool) -> TrustResult<()> {
    if value.len() > maximum || (require_non_empty && value.is_empty()) {
        return Err(TrustError::InvalidPayload);
    }
    Ok(())
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) -> TrustResult<()> {
    let length = u32::try_from(value.len()).map_err(|_| TrustError::InvalidPayload)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn append_identifier(output: &mut Vec<u8>, value: &str) -> TrustResult<()> {
    validate_identifier(value)?;
    append_len_prefixed(output, value.as_bytes())
}

fn append_digest(output: &mut Vec<u8>, value: &[u8; 32]) -> TrustResult<()> {
    append_len_prefixed(output, value)
}

fn digest_identifier(value: &str) -> [u8; 32] {
    let mut canonical = Vec::new();
    canonical.extend_from_slice(&(TRUST_AUDIT_DOMAIN.len() as u32).to_be_bytes());
    canonical.extend_from_slice(TRUST_AUDIT_DOMAIN.as_bytes());
    canonical.extend_from_slice(&TRUST_CONTRACT_VERSION.to_be_bytes());
    canonical.extend_from_slice(&(value.len() as u32).to_be_bytes());
    canonical.extend_from_slice(value.as_bytes());
    Sha256::digest(canonical).into()
}

#[cfg(test)]
fn validate_window(issued_at: u64, expires_at: u64, now_secs: u64) -> TrustResult<()> {
    if issued_at > expires_at {
        return Err(TrustError::InvalidValidityWindow);
    }
    if now_secs < issued_at {
        return Err(TrustError::InvalidValidityWindow);
    }
    if now_secs > expires_at {
        return Err(TrustError::InvalidValidityWindow);
    }
    Ok(())
}

struct BoundedIdentifierVisitor;

impl<'de> Visitor<'de> for BoundedIdentifierVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded non-empty trust identifier")
    }

    fn visit_str<E: DeError>(self, value: &str) -> Result<Self::Value, E> {
        validate_identifier(value).map_err(|_| E::custom("bounded trust identifier is invalid"))?;
        Ok(value.to_owned())
    }

    fn visit_borrowed_str<E: DeError>(self, value: &'de str) -> Result<Self::Value, E> {
        self.visit_str(value)
    }

    fn visit_string<E: DeError>(self, value: String) -> Result<Self::Value, E> {
        self.visit_str(&value)
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
    require_non_empty: bool,
}

impl<'de> Visitor<'de> for BoundedBytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {} bounded bytes", self.maximum)
    }

    fn visit_bytes<E: DeError>(self, value: &[u8]) -> Result<Self::Value, E> {
        validate_bytes(value, self.maximum, self.require_non_empty)
            .map_err(|_| E::custom("bounded trust byte field is invalid"))?;
        Ok(value.to_vec())
    }

    fn visit_borrowed_bytes<E: DeError>(self, value: &'de [u8]) -> Result<Self::Value, E> {
        self.visit_bytes(value)
    }

    fn visit_byte_buf<E: DeError>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        self.visit_bytes(&value)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        if sequence.size_hint().is_some_and(|size| size > self.maximum) {
            return Err(A::Error::custom("trust byte field exceeds its bound"));
        }

        let capacity = sequence.size_hint().unwrap_or_default().min(self.maximum);
        let mut bytes = Vec::with_capacity(capacity);
        while bytes.len() < self.maximum {
            match sequence.next_element::<u8>()? {
                Some(byte) => bytes.push(byte),
                None => {
                    validate_bytes(&bytes, self.maximum, self.require_non_empty)
                        .map_err(|_| A::Error::custom("bounded trust byte field is invalid"))?;
                    return Ok(bytes);
                }
            }
        }

        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("trust byte field exceeds its bound"));
        }
        validate_bytes(&bytes, self.maximum, self.require_non_empty)
            .map_err(|_| A::Error::custom("bounded trust byte field is invalid"))?;
        Ok(bytes)
    }
}

fn deserialize_bounded_bytes<'de, D, const MAXIMUM: usize>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_byte_buf(BoundedBytesVisitor {
        maximum: MAXIMUM,
        require_non_empty: true,
    })
}

fn deserialize_bounded_optional_bytes<'de, D, const MAXIMUM: usize>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_byte_buf(BoundedBytesVisitor {
        maximum: MAXIMUM,
        require_non_empty: false,
    })
}

struct BoundedVecVisitor<T, const MAXIMUM: usize> {
    marker: std::marker::PhantomData<T>,
}

impl<'de, T, const MAXIMUM: usize> Visitor<'de> for BoundedVecVisitor<T, MAXIMUM>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {} bounded trust entries", MAXIMUM)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        if sequence.size_hint().is_some_and(|size| size > MAXIMUM) {
            return Err(A::Error::custom("trust sequence exceeds its bound"));
        }

        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or_default().min(MAXIMUM));
        while values.len() < MAXIMUM {
            match sequence.next_element::<T>()? {
                Some(value) => values.push(value),
                None => return Ok(values),
            }
        }
        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("trust sequence exceeds its bound"));
        }
        Ok(values)
    }
}

fn deserialize_bounded_anchors<'de, D>(deserializer: D) -> Result<Vec<TrustAnchor>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedVecVisitor::<TrustAnchor, MAX_TRUST_ANCHORS> {
        marker: std::marker::PhantomData,
    })
}

/// An untrusted provider/profile-scoped trust anchor.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchor {
    pub version: u16,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub anchor_id: String,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub provider: String,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub profile: String,
    pub signature_algorithm: TrustSignatureAlgorithm,
    #[serde(deserialize_with = "deserialize_bounded_public_key")]
    pub public_key: Vec<u8>,
    #[serde(deserialize_with = "deserialize_bounded_constraints")]
    pub constraints: Vec<u8>,
    pub not_before: u64,
    pub not_after: u64,
    pub revision: u64,
    pub revocation_status: RevocationStatus,
    pub tcb_status: TcbStatus,
}

fn deserialize_bounded_public_key<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes::<D, MAX_TRUST_PUBLIC_KEY_BYTES>(deserializer)
}

fn deserialize_bounded_constraints<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_optional_bytes::<D, MAX_TRUST_CONSTRAINT_BYTES>(deserializer)
}

impl fmt::Debug for TrustAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustAnchor")
            .field("version", &self.version)
            .field("anchor_id", &self.anchor_id)
            .field("provider", &self.provider)
            .field("profile", &self.profile)
            .field("signature_algorithm", &self.signature_algorithm)
            .field(
                "public_key_digest",
                &Sha256::digest(&self.public_key).as_slice(),
            )
            .field("public_key_len", &self.public_key.len())
            .field("constraints_len", &self.constraints.len())
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("revision", &self.revision)
            .field("revocation_status", &self.revocation_status)
            .field("tcb_status", &self.tcb_status)
            .finish()
    }
}

impl TrustAnchor {
    pub fn validate(&self) -> TrustResult<()> {
        if self.version != TRUST_CONTRACT_VERSION {
            return Err(TrustError::UnsupportedVersion);
        }
        validate_identifier(&self.anchor_id)?;
        validate_identifier(&self.provider)?;
        validate_identifier(&self.profile)?;
        validate_bytes(&self.public_key, MAX_TRUST_PUBLIC_KEY_BYTES, true)?;
        validate_bytes(&self.constraints, MAX_TRUST_CONSTRAINT_BYTES, false)?;
        if self.public_key.len() != self.signature_algorithm.public_key_len()
            || self.not_before > self.not_after
        {
            return Err(TrustError::InvalidPayload);
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> TrustResult<Vec<u8>> {
        self.validate()?;
        let mut output = Vec::new();
        append_len_prefixed(&mut output, TRUST_ANCHOR_DOMAIN.as_bytes())?;
        output.extend_from_slice(&self.version.to_be_bytes());
        append_identifier(&mut output, &self.anchor_id)?;
        append_identifier(&mut output, &self.provider)?;
        append_identifier(&mut output, &self.profile)?;
        output.push(self.signature_algorithm.canonical_tag());
        append_len_prefixed(&mut output, &self.public_key)?;
        append_len_prefixed(&mut output, &self.constraints)?;
        output.extend_from_slice(&self.not_before.to_be_bytes());
        output.extend_from_slice(&self.not_after.to_be_bytes());
        output.extend_from_slice(&self.revision.to_be_bytes());
        output.push(self.revocation_status.canonical_tag());
        output.push(self.tcb_status.canonical_tag());
        Ok(output)
    }

    pub fn digest(&self) -> TrustResult<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }

    pub fn public_key_digest(&self) -> TrustResult<[u8; 32]> {
        Ok(Sha256::digest(&self.public_key).into())
    }
}

/// An authenticated, versioned set of trust anchors.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustBundle {
    pub version: u16,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub bundle_id: String,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub provider: String,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub profile: String,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub signer_anchor_id: String,
    pub signature_algorithm: TrustSignatureAlgorithm,
    pub revision: u64,
    pub rollback_floor: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(deserialize_with = "deserialize_bounded_anchors")]
    pub anchors: Vec<TrustAnchor>,
    pub payload_digest: [u8; 32],
    #[serde(deserialize_with = "deserialize_bounded_signature")]
    pub signature: Vec<u8>,
}

fn deserialize_bounded_signature<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes::<D, MAX_TRUST_SIGNATURE_BYTES>(deserializer)
}

impl fmt::Debug for TrustBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let anchor_ids = self
            .anchors
            .iter()
            .map(|anchor| anchor.anchor_id.as_str())
            .collect::<Vec<_>>();
        formatter
            .debug_struct("TrustBundle")
            .field("version", &self.version)
            .field("bundle_id", &self.bundle_id)
            .field("provider", &self.provider)
            .field("profile", &self.profile)
            .field("signer_anchor_id", &self.signer_anchor_id)
            .field("signature_algorithm", &self.signature_algorithm)
            .field("revision", &self.revision)
            .field("rollback_floor", &self.rollback_floor)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("anchor_ids", &anchor_ids)
            .field("payload_digest", &self.payload_digest)
            .field("signature_len", &self.signature.len())
            .finish()
    }
}

impl TrustBundle {
    pub fn validate(&self) -> TrustResult<()> {
        self.validate_shape()?;
        if self.revision < self.rollback_floor {
            return Err(TrustError::InvalidRevision);
        }

        let mut ids = std::collections::HashSet::with_capacity(self.anchors.len());
        for anchor in &self.anchors {
            anchor.validate()?;
            if anchor.provider != self.provider || anchor.profile != self.profile {
                return Err(TrustError::ProviderProfileMismatch);
            }
            if !ids.insert(anchor.anchor_id.as_str()) {
                return Err(TrustError::InvalidPayload);
            }
        }
        let expected: [u8; 32] = Sha256::digest(self.payload_canonical_bytes()?).into();
        if self.payload_digest != expected {
            return Err(TrustError::DigestMismatch);
        }
        Ok(())
    }

    fn validate_shape(&self) -> TrustResult<()> {
        if self.version != TRUST_CONTRACT_VERSION {
            return Err(TrustError::UnsupportedVersion);
        }
        validate_identifier(&self.bundle_id)?;
        validate_identifier(&self.provider)?;
        validate_identifier(&self.profile)?;
        validate_identifier(&self.signer_anchor_id)?;
        validate_bytes(&self.signature, MAX_TRUST_SIGNATURE_BYTES, true)?;
        if self.signature.len() != self.signature_algorithm.signature_len()
            || self.anchors.is_empty()
            || self.anchors.len() > MAX_TRUST_ANCHORS
            || self.issued_at > self.expires_at
        {
            return Err(TrustError::InvalidPayload);
        }
        Ok(())
    }

    fn append_header(&self, output: &mut Vec<u8>) -> TrustResult<()> {
        append_len_prefixed(output, TRUST_BUNDLE_DOMAIN.as_bytes())?;
        output.extend_from_slice(&self.version.to_be_bytes());
        append_identifier(output, &self.bundle_id)?;
        append_identifier(output, &self.provider)?;
        append_identifier(output, &self.profile)?;
        append_identifier(output, &self.signer_anchor_id)?;
        output.push(self.signature_algorithm.canonical_tag());
        output.extend_from_slice(&self.revision.to_be_bytes());
        output.extend_from_slice(&self.rollback_floor.to_be_bytes());
        output.extend_from_slice(&self.issued_at.to_be_bytes());
        output.extend_from_slice(&self.expires_at.to_be_bytes());
        Ok(())
    }

    fn payload_canonical_bytes(&self) -> TrustResult<Vec<u8>> {
        self.validate_shape()?;
        let mut output = Vec::new();
        self.append_header(&mut output)?;
        let mut anchors = self.anchors.iter().collect::<Vec<_>>();
        anchors.sort_by(|left, right| left.anchor_id.cmp(&right.anchor_id));
        let count = u32::try_from(anchors.len()).map_err(|_| TrustError::InvalidPayload)?;
        output.extend_from_slice(&count.to_be_bytes());
        for anchor in anchors {
            append_len_prefixed(&mut output, &anchor.canonical_bytes()?)?;
        }
        Ok(output)
    }

    fn signed_canonical_bytes(&self) -> TrustResult<Vec<u8>> {
        let mut output = self.payload_canonical_bytes()?;
        append_digest(&mut output, &self.payload_digest)?;
        Ok(output)
    }

    pub fn canonical_bytes(&self) -> TrustResult<Vec<u8>> {
        self.validate_shape()?;
        let mut output = self.signed_canonical_bytes()?;
        append_len_prefixed(&mut output, &self.signature)?;
        Ok(output)
    }

    pub fn digest(&self) -> TrustResult<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }

    pub fn anchor(&self, anchor_id: &str) -> Option<&TrustAnchor> {
        self.anchors
            .iter()
            .find(|anchor| anchor.anchor_id == anchor_id)
    }
}

/// A provider/profile/mechanism-scoped verification request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustVerificationRequest {
    provider: String,
    profile: String,
    mechanism: ProofKind,
    minimum_revision: u64,
}

impl TrustVerificationRequest {
    pub fn new(
        provider: impl Into<String>,
        profile: impl Into<String>,
        mechanism: ProofKind,
        minimum_revision: u64,
    ) -> TrustResult<Self> {
        let request = Self {
            provider: provider.into(),
            profile: profile.into(),
            mechanism,
            minimum_revision,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> TrustResult<()> {
        validate_identifier(&self.provider)?;
        validate_identifier(&self.profile)
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn mechanism(&self) -> ProofKind {
        self.mechanism
    }

    pub fn minimum_revision(&self) -> u64 {
        self.minimum_revision
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAuthenticatorStatus {
    Unavailable,
    TestOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustVerifierStatus {
    Unavailable,
    TestOnly,
}

/// Production and future provider authenticators are constructor-controlled.
/// The current production route is intentionally unavailable.
pub trait TrustAuthenticator: Send + Sync {
    fn status(&self) -> TrustAuthenticatorStatus;

    fn authenticate(
        &self,
        bundle: &TrustBundle,
        request: &TrustVerificationRequest,
        now_secs: u64,
    ) -> TrustResult<VerifiedTrustBundle>;
}

/// Provider verifier contract for collateral and evidence. The normalized
/// orchestration obtains the trusted time before invoking either route.
pub trait TrustVerifier: Send + Sync {
    fn status(&self) -> TrustVerifierStatus;

    fn verify_collateral(
        &self,
        collateral: &CollateralSnapshot,
        trust_bundle: &VerifiedTrustBundle,
        request: &TrustVerificationRequest,
        now_secs: u64,
    ) -> TrustResult<VerifiedCollateralSnapshot>;

    fn verify_evidence(
        &self,
        evidence: &AttestationEvidence,
        collateral: &VerifiedCollateralSnapshot,
        context: &ProofVerificationContext,
        request: &TrustVerificationRequest,
        now_secs: u64,
    ) -> TrustResult<VerifiedAttestationEvidence>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableTrustAuthenticator;

impl TrustAuthenticator for UnavailableTrustAuthenticator {
    fn status(&self) -> TrustAuthenticatorStatus {
        TrustAuthenticatorStatus::Unavailable
    }

    fn authenticate(
        &self,
        _bundle: &TrustBundle,
        _request: &TrustVerificationRequest,
        _now_secs: u64,
    ) -> TrustResult<VerifiedTrustBundle> {
        Err(TrustError::AuthenticatorUnavailable)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableTrustVerifier;

impl TrustVerifier for UnavailableTrustVerifier {
    fn status(&self) -> TrustVerifierStatus {
        TrustVerifierStatus::Unavailable
    }

    fn verify_collateral(
        &self,
        _collateral: &CollateralSnapshot,
        _trust_bundle: &VerifiedTrustBundle,
        _request: &TrustVerificationRequest,
        _now_secs: u64,
    ) -> TrustResult<VerifiedCollateralSnapshot> {
        Err(TrustError::VerifierUnavailable)
    }

    fn verify_evidence(
        &self,
        _evidence: &AttestationEvidence,
        _collateral: &VerifiedCollateralSnapshot,
        _context: &ProofVerificationContext,
        _request: &TrustVerificationRequest,
        _now_secs: u64,
    ) -> TrustResult<VerifiedAttestationEvidence> {
        Err(TrustError::VerifierUnavailable)
    }
}

pub fn production_trust_authenticator() -> UnavailableTrustAuthenticator {
    UnavailableTrustAuthenticator
}

pub fn production_trust_verifier() -> UnavailableTrustVerifier {
    UnavailableTrustVerifier
}

/// Authenticated collateral supplied by a provider release process.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CollateralSnapshot {
    pub version: u16,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub snapshot_id: String,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub provider: String,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub profile: String,
    pub mechanism: ProofKind,
    pub trust_bundle_revision: u64,
    pub revision: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revocation_status: RevocationStatus,
    pub tcb_status: TcbStatus,
    #[serde(deserialize_with = "deserialize_bounded_payload")]
    pub payload: Vec<u8>,
    pub payload_digest: [u8; 32],
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub signer_anchor_id: String,
    pub signature_algorithm: TrustSignatureAlgorithm,
    #[serde(deserialize_with = "deserialize_bounded_signature")]
    pub signature: Vec<u8>,
}

fn deserialize_bounded_payload<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes::<D, MAX_TRUST_PAYLOAD_BYTES>(deserializer)
}

impl fmt::Debug for CollateralSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollateralSnapshot")
            .field("version", &self.version)
            .field("snapshot_id", &self.snapshot_id)
            .field("provider", &self.provider)
            .field("profile", &self.profile)
            .field("mechanism", &self.mechanism)
            .field("trust_bundle_revision", &self.trust_bundle_revision)
            .field("revision", &self.revision)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("revocation_status", &self.revocation_status)
            .field("tcb_status", &self.tcb_status)
            .field("payload_digest", &self.payload_digest)
            .field("payload_len", &self.payload.len())
            .field("signer_anchor_id", &self.signer_anchor_id)
            .field("signature_len", &self.signature.len())
            .finish()
    }
}

impl CollateralSnapshot {
    fn validate_shape(&self) -> TrustResult<()> {
        if self.version != TRUST_CONTRACT_VERSION {
            return Err(TrustError::UnsupportedVersion);
        }
        validate_identifier(&self.snapshot_id)?;
        validate_identifier(&self.provider)?;
        validate_identifier(&self.profile)?;
        validate_identifier(&self.signer_anchor_id)?;
        validate_bytes(&self.payload, MAX_TRUST_PAYLOAD_BYTES, true)?;
        validate_bytes(&self.signature, MAX_TRUST_SIGNATURE_BYTES, true)?;
        if self.signature.len() != self.signature_algorithm.signature_len()
            || self.issued_at > self.expires_at
        {
            return Err(TrustError::InvalidPayload);
        }
        Ok(())
    }

    fn append_header(&self, output: &mut Vec<u8>) -> TrustResult<()> {
        append_len_prefixed(output, COLLATERAL_SNAPSHOT_DOMAIN.as_bytes())?;
        output.extend_from_slice(&self.version.to_be_bytes());
        append_identifier(output, &self.snapshot_id)?;
        append_identifier(output, &self.provider)?;
        append_identifier(output, &self.profile)?;
        output.push(self.mechanism.canonical_tag());
        output.extend_from_slice(&self.trust_bundle_revision.to_be_bytes());
        output.extend_from_slice(&self.revision.to_be_bytes());
        output.extend_from_slice(&self.issued_at.to_be_bytes());
        output.extend_from_slice(&self.expires_at.to_be_bytes());
        output.push(self.revocation_status.canonical_tag());
        output.push(self.tcb_status.canonical_tag());
        append_len_prefixed(output, &self.payload)?;
        Ok(())
    }

    fn payload_canonical_bytes(&self) -> TrustResult<Vec<u8>> {
        self.validate_shape()?;
        let mut output = Vec::new();
        self.append_header(&mut output)?;
        Ok(output)
    }

    fn signed_canonical_bytes(&self) -> TrustResult<Vec<u8>> {
        let mut output = self.payload_canonical_bytes()?;
        append_digest(&mut output, &self.payload_digest)?;
        append_identifier(&mut output, &self.signer_anchor_id)?;
        output.push(self.signature_algorithm.canonical_tag());
        Ok(output)
    }

    pub fn validate(&self) -> TrustResult<()> {
        self.validate_shape()?;
        let expected: [u8; 32] = Sha256::digest(self.payload_canonical_bytes()?).into();
        if self.payload_digest != expected {
            return Err(TrustError::DigestMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> TrustResult<Vec<u8>> {
        self.validate_shape()?;
        let mut output = self.signed_canonical_bytes()?;
        append_len_prefixed(&mut output, &self.signature)?;
        Ok(output)
    }

    pub fn digest(&self) -> TrustResult<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
}

/// Provider evidence received before appraisal.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttestationEvidence {
    pub version: u16,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub evidence_id: String,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub provider: String,
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub profile: String,
    pub mechanism: ProofKind,
    pub trust_bundle_revision: u64,
    pub collateral_revision: u64,
    pub subject_digest: [u8; 32],
    pub key_identity_digest: [u8; 32],
    pub context_binding_digest: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub revocation_status: RevocationStatus,
    pub tcb_status: TcbStatus,
    #[serde(deserialize_with = "deserialize_bounded_evidence")]
    pub evidence: Vec<u8>,
    pub evidence_digest: [u8; 32],
    #[serde(deserialize_with = "deserialize_bounded_identifier")]
    pub signer_anchor_id: String,
    pub signature_algorithm: TrustSignatureAlgorithm,
    #[serde(deserialize_with = "deserialize_bounded_signature")]
    pub signature: Vec<u8>,
}

fn deserialize_bounded_evidence<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes::<D, MAX_TRUST_PAYLOAD_BYTES>(deserializer)
}

impl fmt::Debug for AttestationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttestationEvidence")
            .field("version", &self.version)
            .field("evidence_id", &self.evidence_id)
            .field("provider", &self.provider)
            .field("profile", &self.profile)
            .field("mechanism", &self.mechanism)
            .field("trust_bundle_revision", &self.trust_bundle_revision)
            .field("collateral_revision", &self.collateral_revision)
            .field("subject_digest", &self.subject_digest)
            .field("key_identity_digest", &self.key_identity_digest)
            .field("context_binding_digest", &self.context_binding_digest)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("revocation_status", &self.revocation_status)
            .field("tcb_status", &self.tcb_status)
            .field("evidence_digest", &self.evidence_digest)
            .field("evidence_len", &self.evidence.len())
            .field("signer_anchor_id", &self.signer_anchor_id)
            .field("signature_len", &self.signature.len())
            .finish()
    }
}

impl AttestationEvidence {
    fn validate_shape(&self) -> TrustResult<()> {
        if self.version != TRUST_CONTRACT_VERSION {
            return Err(TrustError::UnsupportedVersion);
        }
        validate_identifier(&self.evidence_id)?;
        validate_identifier(&self.provider)?;
        validate_identifier(&self.profile)?;
        validate_identifier(&self.signer_anchor_id)?;
        validate_bytes(&self.evidence, MAX_TRUST_PAYLOAD_BYTES, true)?;
        validate_bytes(&self.signature, MAX_TRUST_SIGNATURE_BYTES, true)?;
        if self.signature.len() != self.signature_algorithm.signature_len()
            || self.issued_at > self.expires_at
        {
            return Err(TrustError::InvalidPayload);
        }
        Ok(())
    }

    fn append_header(&self, output: &mut Vec<u8>) -> TrustResult<()> {
        append_len_prefixed(output, ATTESTATION_EVIDENCE_DOMAIN.as_bytes())?;
        output.extend_from_slice(&self.version.to_be_bytes());
        append_identifier(output, &self.evidence_id)?;
        append_identifier(output, &self.provider)?;
        append_identifier(output, &self.profile)?;
        output.push(self.mechanism.canonical_tag());
        output.extend_from_slice(&self.trust_bundle_revision.to_be_bytes());
        output.extend_from_slice(&self.collateral_revision.to_be_bytes());
        append_digest(output, &self.subject_digest)?;
        append_digest(output, &self.key_identity_digest)?;
        append_digest(output, &self.context_binding_digest)?;
        output.extend_from_slice(&self.issued_at.to_be_bytes());
        output.extend_from_slice(&self.expires_at.to_be_bytes());
        output.push(self.revocation_status.canonical_tag());
        output.push(self.tcb_status.canonical_tag());
        append_len_prefixed(output, &self.evidence)?;
        Ok(())
    }

    fn payload_canonical_bytes(&self) -> TrustResult<Vec<u8>> {
        self.validate_shape()?;
        let mut output = Vec::new();
        self.append_header(&mut output)?;
        Ok(output)
    }

    fn signed_canonical_bytes(&self) -> TrustResult<Vec<u8>> {
        let mut output = self.payload_canonical_bytes()?;
        append_digest(&mut output, &self.evidence_digest)?;
        append_identifier(&mut output, &self.signer_anchor_id)?;
        output.push(self.signature_algorithm.canonical_tag());
        Ok(output)
    }

    pub fn validate(&self) -> TrustResult<()> {
        self.validate_shape()?;
        let expected: [u8; 32] = Sha256::digest(self.payload_canonical_bytes()?).into();
        if self.evidence_digest != expected {
            return Err(TrustError::DigestMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> TrustResult<Vec<u8>> {
        self.validate_shape()?;
        let mut output = self.signed_canonical_bytes()?;
        append_len_prefixed(&mut output, &self.signature)?;
        Ok(output)
    }

    pub fn digest(&self) -> TrustResult<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
}

#[cfg(test)]
fn verify_signature(
    algorithm: TrustSignatureAlgorithm,
    public_key: &[u8],
    signed_bytes: &[u8],
    signature: &[u8],
) -> TrustResult<()> {
    if algorithm != TrustSignatureAlgorithm::Ed25519
        || public_key.len() != algorithm.public_key_len()
        || signature.len() != algorithm.signature_len()
    {
        return Err(TrustError::InvalidSignature);
    }
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| TrustError::InvalidSignature)?;
    let key = VerifyingKey::from_bytes(&public_key).map_err(|_| TrustError::InvalidSignature)?;
    let signature = Signature::from_slice(signature).map_err(|_| TrustError::InvalidSignature)?;
    key.verify(signed_bytes, &signature)
        .map_err(|_| TrustError::InvalidSignature)
}

#[derive(Clone)]
pub struct VerifiedTrustBundle {
    bundle: TrustBundle,
    digest: [u8; 32],
}

impl fmt::Debug for VerifiedTrustBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTrustBundle")
            .field("digest", &self.digest)
            .field("provider", &self.bundle.provider)
            .field("profile", &self.bundle.profile)
            .field("revision", &self.bundle.revision)
            .field("rollback_floor", &self.bundle.rollback_floor)
            .field("anchor_count", &self.bundle.anchors.len())
            .finish()
    }
}

impl VerifiedTrustBundle {
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn provider(&self) -> &str {
        &self.bundle.provider
    }

    pub fn profile(&self) -> &str {
        &self.bundle.profile
    }

    pub fn revision(&self) -> u64 {
        self.bundle.revision
    }

    pub fn rollback_floor(&self) -> u64 {
        self.bundle.rollback_floor
    }

    pub fn anchor_count(&self) -> usize {
        self.bundle.anchors.len()
    }

    #[cfg(test)]
    fn anchor(&self, anchor_id: &str) -> Option<&TrustAnchor> {
        self.bundle.anchor(anchor_id)
    }
}

#[derive(Clone)]
pub struct VerifiedCollateralSnapshot {
    snapshot: CollateralSnapshot,
    digest: [u8; 32],
    #[cfg(test)]
    signer_public_key: Vec<u8>,
}

impl fmt::Debug for VerifiedCollateralSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedCollateralSnapshot")
            .field("digest", &self.digest)
            .field("provider", &self.snapshot.provider)
            .field("profile", &self.snapshot.profile)
            .field("mechanism", &self.snapshot.mechanism)
            .field("revision", &self.snapshot.revision)
            .field("revocation_status", &self.snapshot.revocation_status)
            .field("tcb_status", &self.snapshot.tcb_status)
            .finish()
    }
}

impl VerifiedCollateralSnapshot {
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn provider(&self) -> &str {
        &self.snapshot.provider
    }

    pub fn profile(&self) -> &str {
        &self.snapshot.profile
    }

    pub fn mechanism(&self) -> ProofKind {
        self.snapshot.mechanism
    }

    pub fn revision(&self) -> u64 {
        self.snapshot.revision
    }

    pub fn revocation_status(&self) -> RevocationStatus {
        self.snapshot.revocation_status
    }

    pub fn tcb_status(&self) -> TcbStatus {
        self.snapshot.tcb_status
    }
}

#[derive(Clone)]
pub struct VerifiedAttestationEvidence {
    evidence: AttestationEvidence,
    digest: [u8; 32],
}

impl fmt::Debug for VerifiedAttestationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedAttestationEvidence")
            .field("digest", &self.digest)
            .field("provider", &self.evidence.provider)
            .field("profile", &self.evidence.profile)
            .field("mechanism", &self.evidence.mechanism)
            .field("subject_digest", &self.evidence.subject_digest)
            .field("key_identity_digest", &self.evidence.key_identity_digest)
            .field("issued_at", &self.evidence.issued_at)
            .field("expires_at", &self.evidence.expires_at)
            .field("revocation_status", &self.evidence.revocation_status)
            .field("tcb_status", &self.evidence.tcb_status)
            .finish()
    }
}

impl VerifiedAttestationEvidence {
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn provider(&self) -> &str {
        &self.evidence.provider
    }

    pub fn profile(&self) -> &str {
        &self.evidence.profile
    }

    pub fn mechanism(&self) -> ProofKind {
        self.evidence.mechanism
    }

    pub fn subject_digest(&self) -> [u8; 32] {
        self.evidence.subject_digest
    }

    pub fn key_identity_digest(&self) -> [u8; 32] {
        self.evidence.key_identity_digest
    }

    pub fn context_binding_digest(&self) -> [u8; 32] {
        self.evidence.context_binding_digest
    }

    pub fn issued_at(&self) -> u64 {
        self.evidence.issued_at
    }

    pub fn expires_at(&self) -> u64 {
        self.evidence.expires_at
    }

    pub fn revocation_status(&self) -> RevocationStatus {
        self.evidence.revocation_status
    }

    pub fn tcb_status(&self) -> TcbStatus {
        self.evidence.tcb_status
    }
}

#[cfg(test)]
fn authenticate_bundle(
    bundle: &TrustBundle,
    request: &TrustVerificationRequest,
    now_secs: u64,
) -> TrustResult<VerifiedTrustBundle> {
    request.validate()?;
    bundle.validate()?;
    if bundle.provider != request.provider || bundle.profile != request.profile {
        return Err(TrustError::ProviderProfileMismatch);
    }
    if bundle.revision < request.minimum_revision {
        return Err(TrustError::RollbackRejected);
    }
    validate_window(bundle.issued_at, bundle.expires_at, now_secs)?;
    let signer = bundle
        .anchor(&bundle.signer_anchor_id)
        .ok_or(TrustError::InvalidSignature)?;
    if signer.revocation_status != RevocationStatus::Good
        || signer.tcb_status != TcbStatus::Good
        || signer.signature_algorithm != bundle.signature_algorithm
    {
        return Err(TrustError::StatusNotAuthorizable);
    }
    verify_signature(
        bundle.signature_algorithm,
        &signer.public_key,
        &bundle.signed_canonical_bytes()?,
        &bundle.signature,
    )?;
    Ok(VerifiedTrustBundle {
        digest: bundle.digest()?,
        bundle: bundle.clone(),
    })
}

#[cfg(test)]
fn verify_collateral(
    collateral: &CollateralSnapshot,
    trust_bundle: &VerifiedTrustBundle,
    request: &TrustVerificationRequest,
    now_secs: u64,
) -> TrustResult<VerifiedCollateralSnapshot> {
    request.validate()?;
    collateral.validate()?;
    if collateral.provider != request.provider
        || collateral.profile != request.profile
        || collateral.provider != trust_bundle.provider()
        || collateral.profile != trust_bundle.profile()
    {
        return Err(TrustError::ProviderProfileMismatch);
    }
    if collateral.mechanism != request.mechanism {
        return Err(TrustError::MechanismMismatch);
    }
    if collateral.trust_bundle_revision != trust_bundle.revision()
        || collateral.revision < trust_bundle.revision()
    {
        return Err(TrustError::InvalidRevision);
    }
    validate_window(collateral.issued_at, collateral.expires_at, now_secs)?;
    let signer = trust_bundle
        .anchor(&collateral.signer_anchor_id)
        .ok_or(TrustError::InvalidSignature)?;
    if signer.signature_algorithm != collateral.signature_algorithm {
        return Err(TrustError::InvalidSignature);
    }
    verify_signature(
        collateral.signature_algorithm,
        &signer.public_key,
        &collateral.signed_canonical_bytes()?,
        &collateral.signature,
    )?;
    Ok(VerifiedCollateralSnapshot {
        digest: collateral.digest()?,
        snapshot: collateral.clone(),
        signer_public_key: signer.public_key.clone(),
    })
}

#[cfg(test)]
fn verify_evidence(
    evidence: &AttestationEvidence,
    collateral: &VerifiedCollateralSnapshot,
    context: &ProofVerificationContext,
    request: &TrustVerificationRequest,
    now_secs: u64,
) -> TrustResult<VerifiedAttestationEvidence> {
    request.validate()?;
    context.validate().map_err(|_| TrustError::InvalidPayload)?;
    evidence.validate()?;
    if evidence.provider != request.provider
        || evidence.profile != request.profile
        || evidence.provider != collateral.provider()
        || evidence.profile != collateral.profile()
    {
        return Err(TrustError::ProviderProfileMismatch);
    }
    if evidence.mechanism != request.mechanism || evidence.mechanism != collateral.mechanism() {
        return Err(TrustError::MechanismMismatch);
    }
    if evidence.trust_bundle_revision != collateral.snapshot.trust_bundle_revision
        || evidence.collateral_revision != collateral.revision()
    {
        return Err(TrustError::InvalidRevision);
    }
    if evidence.context_binding_digest
        != context
            .binding_digest()
            .map_err(|_| TrustError::InvalidPayload)?
    {
        return Err(TrustError::InvalidPayload);
    }
    validate_window(evidence.issued_at, evidence.expires_at, now_secs)?;
    let signer = collateral.snapshot.signer_anchor_id.as_str();
    if evidence.signer_anchor_id != signer
        || evidence.signature_algorithm != collateral.snapshot.signature_algorithm
    {
        return Err(TrustError::InvalidSignature);
    }
    verify_signature(
        evidence.signature_algorithm,
        &collateral.signer_public_key,
        &evidence.signed_canonical_bytes()?,
        &evidence.signature,
    )?;
    Ok(VerifiedAttestationEvidence {
        digest: evidence.digest()?,
        evidence: evidence.clone(),
    })
}

/// Authenticate a bundle through the supplied route using the trusted clock.
pub fn authenticate_trust_bundle(
    bundle: &TrustBundle,
    authenticator: &dyn TrustAuthenticator,
    request: &TrustVerificationRequest,
    clock: &dyn TrustedClock,
) -> TrustResult<VerifiedTrustBundle> {
    let now_secs = clock.now_secs()?;
    authenticator.authenticate(bundle, request, now_secs)
}

/// Normalize verified evidence into a privacy-safe result. The trusted clock
/// is read before invoking the authenticator or verifier.
#[allow(clippy::too_many_arguments)]
pub fn normalize_attestation_result(
    evidence: &AttestationEvidence,
    collateral: &CollateralSnapshot,
    trust_bundle: &TrustBundle,
    context: &ProofVerificationContext,
    policy: &ProofPolicy,
    request: &TrustVerificationRequest,
    authenticator: &dyn TrustAuthenticator,
    verifier: &dyn TrustVerifier,
    clock: &dyn TrustedClock,
) -> TrustResult<AttestationResult> {
    let now_secs = clock.now_secs()?;
    let verified_bundle = authenticator.authenticate(trust_bundle, request, now_secs)?;
    let verified_collateral =
        verifier.verify_collateral(collateral, &verified_bundle, request, now_secs)?;
    let verified_evidence =
        verifier.verify_evidence(evidence, &verified_collateral, context, request, now_secs)?;
    AttestationResult::from_verified(
        verified_evidence,
        verified_bundle,
        verified_collateral,
        context,
        policy,
        now_secs,
    )
}

/// Normalized attestation output. Raw evidence, nonce bytes, anchor material,
/// collateral, and signatures remain private and are never emitted by the
/// default debug representation.
#[derive(Clone, PartialEq, Eq)]
pub struct AttestationResult {
    provider: String,
    profile: String,
    mechanism: ProofKind,
    subject_digest: [u8; 32],
    key_identity_digest: [u8; 32],
    context: ProofVerificationContext,
    context_binding_digest: [u8; 32],
    policy_digest: [u8; 32],
    evidence_digest: [u8; 32],
    trust_bundle_digest: [u8; 32],
    collateral_digest: [u8; 32],
    revocation_status: RevocationStatus,
    tcb_status: TcbStatus,
    issued_at: u64,
    expires_at: u64,
    verified_at: u64,
    result_digest: [u8; 32],
}

impl fmt::Debug for AttestationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttestationResult")
            .field("provider", &self.provider)
            .field("profile", &self.profile)
            .field("mechanism", &self.mechanism)
            .field("subject_digest", &self.subject_digest)
            .field("key_identity_digest", &self.key_identity_digest)
            .field("context", &self.context)
            .field("context_binding_digest", &self.context_binding_digest)
            .field("policy_digest", &self.policy_digest)
            .field("evidence_digest", &self.evidence_digest)
            .field("trust_bundle_digest", &self.trust_bundle_digest)
            .field("collateral_digest", &self.collateral_digest)
            .field("revocation_status", &self.revocation_status)
            .field("tcb_status", &self.tcb_status)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("verified_at", &self.verified_at)
            .field("result_digest", &self.result_digest)
            .finish()
    }
}

impl AttestationResult {
    fn from_verified(
        evidence: VerifiedAttestationEvidence,
        trust_bundle: VerifiedTrustBundle,
        collateral: VerifiedCollateralSnapshot,
        context: &ProofVerificationContext,
        policy: &ProofPolicy,
        verified_at: u64,
    ) -> TrustResult<Self> {
        context.validate().map_err(|_| TrustError::InvalidPayload)?;
        policy.validate().map_err(|_| TrustError::InvalidPayload)?;
        let context_binding_digest = context
            .binding_digest()
            .map_err(|_| TrustError::InvalidPayload)?;
        if evidence.context_binding_digest() != context_binding_digest {
            return Err(TrustError::InvalidPayload);
        }
        if evidence.provider() != trust_bundle.provider()
            || evidence.profile() != trust_bundle.profile()
            || evidence.provider() != collateral.provider()
            || evidence.profile() != collateral.profile()
        {
            return Err(TrustError::ProviderProfileMismatch);
        }
        if evidence.mechanism() != collateral.mechanism() {
            return Err(TrustError::MechanismMismatch);
        }
        let policy_digest = policy.digest().map_err(|_| TrustError::InvalidPayload)?;
        let mut result = Self {
            provider: evidence.provider().to_owned(),
            profile: evidence.profile().to_owned(),
            mechanism: evidence.mechanism(),
            subject_digest: evidence.subject_digest(),
            key_identity_digest: evidence.key_identity_digest(),
            context: context.clone(),
            context_binding_digest,
            policy_digest,
            evidence_digest: evidence.digest(),
            trust_bundle_digest: trust_bundle.digest(),
            collateral_digest: collateral.digest(),
            revocation_status: evidence.revocation_status(),
            tcb_status: evidence.tcb_status(),
            issued_at: evidence.issued_at(),
            expires_at: evidence.expires_at(),
            verified_at,
            result_digest: [0; 32],
        };
        result.result_digest = Sha256::digest(result.canonical_bytes()?).into();
        Ok(result)
    }

    fn canonical_bytes(&self) -> TrustResult<Vec<u8>> {
        let mut output = Vec::new();
        append_len_prefixed(&mut output, ATTESTATION_RESULT_DOMAIN.as_bytes())?;
        output.extend_from_slice(&TRUST_CONTRACT_VERSION.to_be_bytes());
        append_identifier(&mut output, &self.provider)?;
        append_identifier(&mut output, &self.profile)?;
        output.push(self.mechanism.canonical_tag());
        append_digest(&mut output, &self.subject_digest)?;
        append_digest(&mut output, &self.key_identity_digest)?;
        append_digest(&mut output, &self.context_binding_digest)?;
        append_digest(&mut output, &self.policy_digest)?;
        append_digest(&mut output, &self.evidence_digest)?;
        append_digest(&mut output, &self.trust_bundle_digest)?;
        append_digest(&mut output, &self.collateral_digest)?;
        output.extend_from_slice(&self.context.operation_digest);
        append_identifier(&mut output, &self.context.purpose)?;
        append_identifier(&mut output, &self.context.audience)?;
        append_digest(&mut output, &Sha256::digest(&self.context.nonce).into())?;
        output.extend_from_slice(&self.context.now_secs.to_be_bytes());
        output.extend_from_slice(&self.context.max_age_secs.to_be_bytes());
        output.extend_from_slice(&self.context.max_future_skew_secs.to_be_bytes());
        output.push(self.revocation_status.canonical_tag());
        output.push(self.tcb_status.canonical_tag());
        output.extend_from_slice(&self.issued_at.to_be_bytes());
        output.extend_from_slice(&self.expires_at.to_be_bytes());
        output.extend_from_slice(&self.verified_at.to_be_bytes());
        Ok(output)
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn mechanism(&self) -> ProofKind {
        self.mechanism
    }

    pub fn subject_digest(&self) -> [u8; 32] {
        self.subject_digest
    }

    pub fn key_identity_digest(&self) -> [u8; 32] {
        self.key_identity_digest
    }

    pub fn context_binding_digest(&self) -> [u8; 32] {
        self.context_binding_digest
    }

    pub fn operation_digest(&self) -> [u8; 32] {
        self.context.operation_digest
    }

    pub fn purpose(&self) -> &str {
        &self.context.purpose
    }

    pub fn audience(&self) -> &str {
        &self.context.audience
    }

    pub fn nonce_digest(&self) -> [u8; 32] {
        Sha256::digest(&self.context.nonce).into()
    }

    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    pub fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }

    pub fn trust_bundle_digest(&self) -> [u8; 32] {
        self.trust_bundle_digest
    }

    pub fn collateral_digest(&self) -> [u8; 32] {
        self.collateral_digest
    }

    pub fn revocation_status(&self) -> RevocationStatus {
        self.revocation_status
    }

    pub fn tcb_status(&self) -> TcbStatus {
        self.tcb_status
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

    pub fn result_digest(&self) -> [u8; 32] {
        self.result_digest
    }

    pub fn is_authorizable_at(&self, now_secs: u64) -> bool {
        self.revocation_status.is_authorizable()
            && self.tcb_status.is_authorizable()
            && self.issued_at <= now_secs
            && now_secs <= self.expires_at
    }

    pub fn audit_metadata(&self) -> AttestationAuditMetadata {
        AttestationAuditMetadata {
            provider_digest: digest_identifier(&self.provider),
            profile_digest: digest_identifier(&self.profile),
            mechanism: self.mechanism,
            subject_digest: self.subject_digest,
            key_identity_digest: self.key_identity_digest,
            operation_digest: self.operation_digest(),
            purpose_digest: digest_identifier(&self.context.purpose),
            audience_digest: digest_identifier(&self.context.audience),
            nonce_digest: self.nonce_digest(),
            policy_digest: self.policy_digest,
            evidence_digest: self.evidence_digest,
            trust_bundle_digest: self.trust_bundle_digest,
            collateral_digest: self.collateral_digest,
            result_digest: self.result_digest,
            revocation_status: self.revocation_status,
            tcb_status: self.tcb_status,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            verified_at: self.verified_at,
        }
    }
}

/// Privacy-minimized audit data. It contains no raw evidence, nonce, anchor,
/// collateral, signature, subject identifier, or key identifier.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AttestationAuditMetadata {
    pub provider_digest: [u8; 32],
    pub profile_digest: [u8; 32],
    pub mechanism: ProofKind,
    pub subject_digest: [u8; 32],
    pub key_identity_digest: [u8; 32],
    pub operation_digest: [u8; 32],
    pub purpose_digest: [u8; 32],
    pub audience_digest: [u8; 32],
    pub nonce_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub evidence_digest: [u8; 32],
    pub trust_bundle_digest: [u8; 32],
    pub collateral_digest: [u8; 32],
    pub result_digest: [u8; 32],
    pub revocation_status: RevocationStatus,
    pub tcb_status: TcbStatus,
    pub issued_at: u64,
    pub expires_at: u64,
    pub verified_at: u64,
}

pub fn deserialize_trust_bundle_json(input: &[u8]) -> TrustResult<TrustBundle> {
    if input.len() > MAX_TRUST_TRANSPORT_BYTES {
        return Err(TrustError::InvalidPayload);
    }
    serde_json::from_slice(input).map_err(|_| TrustError::InvalidPayload)
}

pub fn deserialize_collateral_snapshot_json(input: &[u8]) -> TrustResult<CollateralSnapshot> {
    if input.len() > MAX_TRUST_TRANSPORT_BYTES {
        return Err(TrustError::InvalidPayload);
    }
    serde_json::from_slice(input).map_err(|_| TrustError::InvalidPayload)
}

pub fn deserialize_attestation_evidence_json(input: &[u8]) -> TrustResult<AttestationEvidence> {
    if input.len() > MAX_TRUST_TRANSPORT_BYTES {
        return Err(TrustError::InvalidPayload);
    }
    serde_json::from_slice(input).map_err(|_| TrustError::InvalidPayload)
}

#[cfg(test)]
fn sign_ed25519(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    key.sign(message).to_bytes().to_vec()
}

#[cfg(test)]
fn fixture_anchor(key: &SigningKey, now_secs: u64) -> TrustAnchor {
    TrustAnchor {
        version: TRUST_CONTRACT_VERSION,
        anchor_id: "fixture-root".to_string(),
        provider: "fixture-provider".to_string(),
        profile: "fixture-profile".to_string(),
        signature_algorithm: TrustSignatureAlgorithm::Ed25519,
        public_key: key.verifying_key().to_bytes().to_vec(),
        constraints: b"fixture-constraint".to_vec(),
        not_before: now_secs.saturating_sub(10),
        not_after: now_secs.saturating_add(600),
        revision: 7,
        revocation_status: RevocationStatus::Good,
        tcb_status: TcbStatus::Good,
    }
}

#[cfg(test)]
fn fixture_bundle(key: &SigningKey, now_secs: u64) -> TrustBundle {
    let anchor = fixture_anchor(key, now_secs);
    let mut bundle = TrustBundle {
        version: TRUST_CONTRACT_VERSION,
        bundle_id: "fixture-bundle".to_string(),
        provider: "fixture-provider".to_string(),
        profile: "fixture-profile".to_string(),
        signer_anchor_id: "fixture-root".to_string(),
        signature_algorithm: TrustSignatureAlgorithm::Ed25519,
        revision: 7,
        rollback_floor: 6,
        issued_at: now_secs.saturating_sub(5),
        expires_at: now_secs.saturating_add(600),
        anchors: vec![anchor],
        payload_digest: [0; 32],
        signature: vec![0; 64],
    };
    bundle.payload_digest =
        Sha256::digest(bundle.payload_canonical_bytes().expect("fixture")).into();
    bundle.signature = sign_ed25519(key, &bundle.signed_canonical_bytes().expect("fixture"));
    bundle
}

#[cfg(test)]
fn fixture_collateral(key: &SigningKey, now_secs: u64, bundle: &TrustBundle) -> CollateralSnapshot {
    let mut collateral = CollateralSnapshot {
        version: TRUST_CONTRACT_VERSION,
        snapshot_id: "fixture-collateral".to_string(),
        provider: bundle.provider.clone(),
        profile: bundle.profile.clone(),
        mechanism: ProofKind::Tee,
        trust_bundle_revision: bundle.revision,
        revision: bundle.revision,
        issued_at: now_secs.saturating_sub(4),
        expires_at: now_secs.saturating_add(500),
        revocation_status: RevocationStatus::Good,
        tcb_status: TcbStatus::Good,
        payload: b"fixture-collateral-payload".to_vec(),
        payload_digest: [0; 32],
        signer_anchor_id: bundle.signer_anchor_id.clone(),
        signature_algorithm: TrustSignatureAlgorithm::Ed25519,
        signature: vec![0; 64],
    };
    collateral.payload_digest =
        Sha256::digest(collateral.payload_canonical_bytes().expect("fixture")).into();
    collateral.signature =
        sign_ed25519(key, &collateral.signed_canonical_bytes().expect("fixture"));
    collateral
}

#[cfg(test)]
fn fixture_evidence(
    key: &SigningKey,
    now_secs: u64,
    bundle: &TrustBundle,
    collateral: &CollateralSnapshot,
    context: &ProofVerificationContext,
) -> AttestationEvidence {
    let mut evidence = AttestationEvidence {
        version: TRUST_CONTRACT_VERSION,
        evidence_id: "fixture-evidence".to_string(),
        provider: bundle.provider.clone(),
        profile: bundle.profile.clone(),
        mechanism: ProofKind::Tee,
        trust_bundle_revision: bundle.revision,
        collateral_revision: collateral.revision,
        subject_digest: [1; 32],
        key_identity_digest: [2; 32],
        context_binding_digest: context.binding_digest().expect("fixture"),
        issued_at: now_secs.saturating_sub(3),
        expires_at: now_secs.saturating_add(300),
        revocation_status: RevocationStatus::Good,
        tcb_status: TcbStatus::Good,
        evidence: b"fixture-attestation-evidence".to_vec(),
        evidence_digest: [0; 32],
        signer_anchor_id: bundle.signer_anchor_id.clone(),
        signature_algorithm: TrustSignatureAlgorithm::Ed25519,
        signature: vec![0; 64],
    };
    evidence.evidence_digest =
        Sha256::digest(evidence.payload_canonical_bytes().expect("fixture")).into();
    evidence.signature = sign_ed25519(key, &evidence.signed_canonical_bytes().expect("fixture"));
    evidence
}

#[cfg(test)]
struct FixtureTrustAuthenticator;

#[cfg(test)]
impl TrustAuthenticator for FixtureTrustAuthenticator {
    fn status(&self) -> TrustAuthenticatorStatus {
        TrustAuthenticatorStatus::TestOnly
    }

    fn authenticate(
        &self,
        bundle: &TrustBundle,
        request: &TrustVerificationRequest,
        now_secs: u64,
    ) -> TrustResult<VerifiedTrustBundle> {
        authenticate_bundle(bundle, request, now_secs)
    }
}

#[cfg(test)]
struct FixtureTrustVerifier;

#[cfg(test)]
impl TrustVerifier for FixtureTrustVerifier {
    fn status(&self) -> TrustVerifierStatus {
        TrustVerifierStatus::TestOnly
    }

    fn verify_collateral(
        &self,
        collateral: &CollateralSnapshot,
        trust_bundle: &VerifiedTrustBundle,
        request: &TrustVerificationRequest,
        now_secs: u64,
    ) -> TrustResult<VerifiedCollateralSnapshot> {
        verify_collateral(collateral, trust_bundle, request, now_secs)
    }

    fn verify_evidence(
        &self,
        evidence: &AttestationEvidence,
        collateral: &VerifiedCollateralSnapshot,
        context: &ProofVerificationContext,
        request: &TrustVerificationRequest,
        now_secs: u64,
    ) -> TrustResult<VerifiedAttestationEvidence> {
        verify_evidence(evidence, collateral, context, request, now_secs)
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
struct FixtureClock {
    now_secs: u64,
}

#[cfg(test)]
impl TrustedClock for FixtureClock {
    fn now_secs(&self) -> TrustResult<u64> {
        Ok(self.now_secs)
    }
}

#[cfg(test)]
pub(crate) fn test_fixture_attestation_result(
    now_secs: u64,
    revocation_status: RevocationStatus,
    tcb_status: TcbStatus,
) -> AttestationResult {
    let key = SigningKey::from_bytes(&[9; 32]);
    let bundle = fixture_bundle(&key, now_secs);
    let collateral = fixture_collateral(&key, now_secs, &bundle);
    let context =
        ProofVerificationContext::new([3; 32], "SIGN", "fixture-audience", vec![4; 16], now_secs)
            .expect("fixture context");
    let mut evidence = fixture_evidence(&key, now_secs, &bundle, &collateral, &context);
    evidence.revocation_status = revocation_status;
    evidence.tcb_status = tcb_status;
    evidence.evidence_digest =
        Sha256::digest(evidence.payload_canonical_bytes().expect("fixture")).into();
    evidence.signature = sign_ed25519(&key, &evidence.signed_canonical_bytes().expect("fixture"));
    let request =
        TrustVerificationRequest::new("fixture-provider", "fixture-profile", ProofKind::Tee, 6)
            .expect("fixture request");
    let policy = ProofPolicy::new(
        vec![crate::enclave::proofs::ProofRequirement::new(
            ProofKind::Tee,
            ProofKind::Tee.production_verifier_id(),
        )
        .expect("fixture requirement")],
        false,
    )
    .expect("fixture policy");
    normalize_attestation_result(
        &evidence,
        &collateral,
        &bundle,
        &context,
        &policy,
        &request,
        &FixtureTrustAuthenticator,
        &FixtureTrustVerifier,
        &FixtureClock { now_secs },
    )
    .expect("fixture result")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::proofs::ProofRequirement;

    fn fixture() -> (
        SigningKey,
        TrustBundle,
        CollateralSnapshot,
        AttestationEvidence,
        ProofVerificationContext,
        TrustVerificationRequest,
        ProofPolicy,
        FixtureClock,
    ) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let now_secs = 100;
        let bundle = fixture_bundle(&key, now_secs);
        let collateral = fixture_collateral(&key, now_secs, &bundle);
        let context = ProofVerificationContext::new(
            [3; 32],
            "SIGN",
            "fixture-audience",
            vec![4; 16],
            now_secs,
        )
        .expect("context");
        let evidence = fixture_evidence(&key, now_secs, &bundle, &collateral, &context);
        let request =
            TrustVerificationRequest::new("fixture-provider", "fixture-profile", ProofKind::Tee, 6)
                .expect("request");
        let policy = ProofPolicy::new(
            vec![
                ProofRequirement::new(ProofKind::Tee, ProofKind::Tee.production_verifier_id())
                    .expect("requirement"),
            ],
            false,
        )
        .expect("policy");
        (
            key,
            bundle,
            collateral,
            evidence,
            context,
            request,
            policy,
            FixtureClock { now_secs },
        )
    }

    fn verify_fixture(
        bundle: &TrustBundle,
        collateral: &CollateralSnapshot,
        evidence: &AttestationEvidence,
        context: &ProofVerificationContext,
        request: &TrustVerificationRequest,
        policy: &ProofPolicy,
        clock: &FixtureClock,
    ) -> TrustResult<AttestationResult> {
        normalize_attestation_result(
            evidence,
            collateral,
            bundle,
            context,
            policy,
            request,
            &FixtureTrustAuthenticator,
            &FixtureTrustVerifier,
            clock,
        )
    }

    #[test]
    fn fixture_pipeline_produces_normalized_result_and_redacted_debug() {
        let (_key, bundle, collateral, evidence, context, request, policy, clock) = fixture();
        let result = verify_fixture(
            &bundle,
            &collateral,
            &evidence,
            &context,
            &request,
            &policy,
            &clock,
        )
        .expect("fixture should verify");
        assert!(result.is_authorizable_at(100));
        assert_eq!(result.policy_digest(), policy.digest().expect("digest"));
        let debug = format!("{result:?}");
        assert!(!debug.contains("fixture-attestation-evidence"));
        assert!(!debug.contains("fixture-collateral-payload"));
        assert!(!debug.contains("fixture-root"));
        assert!(!debug.contains("0000000000000000"));
        let audit = result.audit_metadata();
        let audit_json = serde_json::to_string(&audit).expect("audit json");
        assert!(!audit_json.contains("fixture-attestation-evidence"));
        assert!(!audit_json.contains("fixture-audience"));
    }

    #[test]
    fn transport_rejects_unknown_fields_and_oversized_values() {
        let unknown = br#"{"version":1,"bundle_id":"b","provider":"p","profile":"r","signer_anchor_id":"a","signature_algorithm":"Ed25519","revision":1,"rollback_floor":1,"issued_at":1,"expires_at":2,"anchors":[],"payload_digest":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"signature":[0],"unexpected":true}"#;
        assert_eq!(
            deserialize_trust_bundle_json(unknown),
            Err(TrustError::InvalidPayload)
        );
        let oversized = serde_json::json!({"version": 1, "bundle_id": "a".repeat(MAX_TRUST_IDENTIFIER_BYTES + 1), "provider": "p", "profile": "r", "signer_anchor_id": "a", "signature_algorithm": "Ed25519", "revision": 1, "rollback_floor": 1, "issued_at": 1, "expires_at": 2, "anchors": [], "payload_digest": vec![0; 32], "signature": vec![0; 65]});
        let bytes = serde_json::to_vec(&oversized).expect("json");
        assert_eq!(
            deserialize_trust_bundle_json(&bytes),
            Err(TrustError::InvalidPayload)
        );
    }

    #[test]
    fn anchor_duplicates_are_rejected_and_order_is_canonical() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut bundle = fixture_bundle(&key, 100);
        let mut second = bundle.anchors[0].clone();
        second.anchor_id = "fixture-second".to_string();
        bundle.anchors.push(second);
        bundle.payload_digest =
            Sha256::digest(bundle.payload_canonical_bytes().expect("payload")).into();
        bundle.signature = sign_ed25519(&key, &bundle.signed_canonical_bytes().expect("signed"));
        let canonical = bundle.canonical_bytes().expect("canonical");
        bundle.anchors.swap(0, 1);
        assert_eq!(bundle.canonical_bytes().expect("canonical"), canonical);
        bundle.anchors[1].anchor_id = bundle.anchors[0].anchor_id.clone();
        assert_eq!(bundle.validate(), Err(TrustError::InvalidPayload));
    }

    #[test]
    fn mutations_to_payload_digest_signature_and_provider_fail_closed() {
        let (key, bundle, collateral, evidence, context, request, policy, clock) = fixture();
        let mut bad_bundle = bundle.clone();
        bad_bundle.payload_digest[0] ^= 1;
        assert_eq!(
            verify_fixture(
                &bad_bundle,
                &collateral,
                &evidence,
                &context,
                &request,
                &policy,
                &clock
            ),
            Err(TrustError::DigestMismatch)
        );
        let mut bad_signature = bundle.clone();
        bad_signature.signature[0] ^= 1;
        assert_eq!(
            verify_fixture(
                &bad_signature,
                &collateral,
                &evidence,
                &context,
                &request,
                &policy,
                &clock
            ),
            Err(TrustError::InvalidSignature)
        );
        let mut bad_provider = bundle.clone();
        bad_provider.provider = "other-provider".to_string();
        bad_provider.payload_digest =
            Sha256::digest(bad_provider.payload_canonical_bytes().expect("payload")).into();
        bad_provider.signature = sign_ed25519(
            &key,
            &bad_provider.signed_canonical_bytes().expect("signed"),
        );
        assert_eq!(
            verify_fixture(
                &bad_provider,
                &collateral,
                &evidence,
                &context,
                &request,
                &policy,
                &clock
            ),
            Err(TrustError::ProviderProfileMismatch)
        );
    }

    #[test]
    fn rollback_floor_validity_and_statuses_are_explicit() {
        let (key, mut bundle, collateral, evidence, context, request, policy, clock) = fixture();
        bundle.revision = 5;
        bundle.rollback_floor = 6;
        bundle.payload_digest =
            Sha256::digest(bundle.payload_canonical_bytes().expect("payload")).into();
        bundle.signature = sign_ed25519(&key, &bundle.signed_canonical_bytes().expect("signed"));
        assert_eq!(
            verify_fixture(
                &bundle,
                &collateral,
                &evidence,
                &context,
                &request,
                &policy,
                &clock
            ),
            Err(TrustError::InvalidRevision)
        );
        let mut expired_clock = clock;
        expired_clock.now_secs = 1_000;
        assert_eq!(
            verify_fixture(
                &fixture().1,
                &collateral,
                &evidence,
                &context,
                &request,
                &policy,
                &expired_clock
            ),
            Err(TrustError::InvalidValidityWindow)
        );

        for status in [
            RevocationStatus::Revoked,
            RevocationStatus::Unknown,
            RevocationStatus::Unavailable,
            RevocationStatus::Expired,
            RevocationStatus::NotYetValid,
            RevocationStatus::Unsupported,
        ] {
            let result = test_fixture_attestation_result(100, status, TcbStatus::Good);
            assert!(!result.is_authorizable_at(100));
        }
        for status in [
            TcbStatus::Revoked,
            TcbStatus::Unknown,
            TcbStatus::Unavailable,
            TcbStatus::Expired,
            TcbStatus::NotYetValid,
            TcbStatus::Unsupported,
        ] {
            let result = test_fixture_attestation_result(100, RevocationStatus::Good, status);
            assert!(!result.is_authorizable_at(100));
        }
    }

    #[test]
    fn unavailable_routes_and_clock_fail_closed() {
        let (_key, bundle, collateral, evidence, context, request, policy, _clock) = fixture();
        assert_eq!(
            production_trust_authenticator().status(),
            TrustAuthenticatorStatus::Unavailable
        );
        assert_eq!(
            production_trust_verifier().status(),
            TrustVerifierStatus::Unavailable
        );
        let unavailable_clock = FixtureClock { now_secs: 0 };
        assert_eq!(
            normalize_attestation_result(
                &evidence,
                &collateral,
                &bundle,
                &context,
                &policy,
                &request,
                &production_trust_authenticator(),
                &production_trust_verifier(),
                &unavailable_clock,
            ),
            Err(TrustError::AuthenticatorUnavailable)
        );
    }

    #[test]
    fn canonical_result_changes_when_security_fields_change() {
        let result = test_fixture_attestation_result(100, RevocationStatus::Good, TcbStatus::Good);
        let mut changed = result.clone();
        changed.policy_digest[0] ^= 1;
        let digest = Sha256::digest(changed.canonical_bytes().expect("canonical"));
        assert_ne!(digest.as_slice(), result.result_digest());
        let mut changed_status = result.clone();
        changed_status.tcb_status = TcbStatus::Unknown;
        let status_digest = Sha256::digest(changed_status.canonical_bytes().expect("canonical"));
        assert_ne!(status_digest.as_slice(), result.result_digest());
    }
}
