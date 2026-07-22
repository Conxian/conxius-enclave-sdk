//! Bounded Android KeyMint/StrongBox authorization evidence.
//!
//! This module defines the first production-honest Android authorization
//! boundary. It validates a versioned request/evidence shape, binds the
//! request to the reported key/app/tier and evidence digests, and deliberately
//! stops short of provider verification. In particular, it does not parse
//! Android KeyMint ASN.1 authorization lists, trust Google roots, validate
//! Play Integrity server-side, or provide durable replay protection.

use crate::{ConclaveError, ConclaveResult};
use serde::de::{self, Deserializer, Error as DeError, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Version of the bounded Android authorization request/evidence contract.
pub const ANDROID_AUTHORIZATION_VERSION: u16 = 1;

/// Domain for canonical Android authorization structures.
pub const ANDROID_AUTHORIZATION_DOMAIN: &str = "CONXIAN-ANDROID-AUTHORIZATION/v1";

/// Domain for request bindings that include provider-evidence digests.
pub const ANDROID_AUTHORIZATION_BINDING_DOMAIN: &str = "CONXIAN-ANDROID-AUTHORIZATION-BINDING/v1";

/// Domain for bounded DER certificate-chain digests.
const ANDROID_DER_CHAIN_DOMAIN: &str = "CONXIAN-ANDROID-DER-CHAIN/v1";

/// Domain for opaque Play Integrity evidence digests.
const ANDROID_PLAY_INTEGRITY_DOMAIN: &str = "CONXIAN-PLAY-INTEGRITY-EVIDENCE/v1";

/// Explicit Android KeyMint route for the semantic `ProofKind::Phone` kind.
///
/// The route is intentionally unavailable in the production registry until
/// trusted roots/collateral, server-side Play Integrity validation, and the
/// durable replay boundary from issue #240 are implemented.
pub const ANDROID_KEYMINT_PROOF_VERIFIER_ID: &str =
    "conxian.proof.phone.android-keymint.unavailable.v1";

/// Alias that names the same explicit Android authorization route.
pub const ANDROID_AUTHORIZATION_VERIFIER_ID: &str = ANDROID_KEYMINT_PROOF_VERIFIER_ID;

pub const MAX_ANDROID_KEY_ID_BYTES: usize = 256;
pub const MAX_ANDROID_PACKAGE_NAME_BYTES: usize = 256;
pub const MAX_ANDROID_NONCE_BYTES: usize = 128;
pub const MAX_ANDROID_CHALLENGE_BYTES: usize = 128;
pub const MAX_ANDROID_DER_CERTIFICATE_BYTES: usize = 16 * 1024;
pub const MAX_ANDROID_DER_CHAIN_LENGTH: usize = 8;
pub const MAX_ANDROID_DER_CHAIN_BYTES: usize = 64 * 1024;
pub const MAX_PLAY_INTEGRITY_EVIDENCE_BYTES: usize = 16 * 1024;
pub const MAX_ANDROID_AUTHORIZATION_AGE_SECS: u64 = 5 * 60;
pub const MAX_ANDROID_AUTHORIZATION_FUTURE_SKEW_SECS: u64 = 30;
pub const MAX_ANDROID_AUTHORIZATION_LIFETIME_SECS: u64 = 24 * 60 * 60;

fn invalid_payload() -> ConclaveError {
    ConclaveError::InvalidPayload
}

fn authorization_mismatch() -> ConclaveError {
    ConclaveError::EnclaveFailure("android authorization binding mismatch".to_string())
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) -> ConclaveResult<()> {
    // Reuse the enclave-wide canonical length-prefix primitive rather than
    // introducing a second framing convention for security-sensitive data.
    super::append_len_prefixed(output, value)
}

fn append_identifier(output: &mut Vec<u8>, value: &str) -> ConclaveResult<()> {
    append_len_prefixed(output, value.as_bytes())
}

fn validate_identifier(value: &str, maximum: usize) -> ConclaveResult<()> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(invalid_payload());
    }
    Ok(())
}

fn validate_bounded_bytes(value: &[u8], maximum: usize) -> ConclaveResult<()> {
    if value.is_empty() || value.len() > maximum {
        return Err(invalid_payload());
    }
    Ok(())
}

fn validate_digest(value: &[u8; 32]) -> ConclaveResult<()> {
    if value == &[0; 32] {
        return Err(invalid_payload());
    }
    Ok(())
}

fn validate_version(version: u16) -> ConclaveResult<()> {
    if version != ANDROID_AUTHORIZATION_VERSION {
        return Err(invalid_payload());
    }
    Ok(())
}

fn validate_deserialized_identifier<E: DeError>(value: &str, maximum: usize) -> Result<String, E> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(E::custom("bounded Android identifier is invalid"));
    }
    Ok(value.to_string())
}

struct BoundedIdentifierVisitor {
    maximum: usize,
}

impl<'de> Visitor<'de> for BoundedIdentifierVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded Android identifier")
    }

    fn visit_str<E: DeError>(self, value: &str) -> Result<Self::Value, E> {
        validate_deserialized_identifier(value, self.maximum)
    }

    fn visit_borrowed_str<E: DeError>(self, value: &'de str) -> Result<Self::Value, E> {
        validate_deserialized_identifier(value, self.maximum)
    }

    fn visit_string<E: DeError>(self, value: String) -> Result<Self::Value, E> {
        validate_deserialized_identifier(&value, self.maximum)
    }
}

fn deserialize_bounded_identifier<'de, D, const MAXIMUM: usize>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_string(BoundedIdentifierVisitor { maximum: MAXIMUM })
}

struct BoundedBytesVisitor {
    maximum: usize,
}

impl<'de> Visitor<'de> for BoundedBytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {} bounded Android bytes", self.maximum)
    }

    fn visit_bytes<E: DeError>(self, value: &[u8]) -> Result<Self::Value, E> {
        if value.is_empty() || value.len() > self.maximum {
            return Err(E::custom("bounded Android byte field is invalid"));
        }
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
            return Err(A::Error::custom("bounded Android byte field is oversized"));
        }

        let capacity = sequence.size_hint().unwrap_or_default().min(self.maximum);
        let mut bytes = Vec::with_capacity(capacity);
        while bytes.len() < self.maximum {
            match sequence.next_element::<u8>()? {
                Some(byte) => bytes.push(byte),
                None => {
                    if bytes.is_empty() {
                        return Err(A::Error::custom("bounded Android byte field is empty"));
                    }
                    return Ok(bytes);
                }
            }
        }

        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("bounded Android byte field is oversized"));
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
    deserialize_bounded_bytes::<D, MAX_ANDROID_NONCE_BYTES>(deserializer)
}

fn deserialize_bounded_challenge<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes::<D, MAX_ANDROID_CHALLENGE_BYTES>(deserializer)
}

fn deserialize_bounded_play_integrity_evidence<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes::<D, MAX_PLAY_INTEGRITY_EVIDENCE_BYTES>(deserializer)
}

#[derive(Deserialize)]
#[serde(transparent)]
struct BoundedDerCertificate(
    #[serde(
        deserialize_with = "deserialize_bounded_bytes::<_, MAX_ANDROID_DER_CERTIFICATE_BYTES>"
    )]
    Vec<u8>,
);

struct BoundedDerChainVisitor;

impl<'de> Visitor<'de> for BoundedDerChainVisitor {
    type Value = Vec<Vec<u8>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded Android DER certificate chain")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        if sequence
            .size_hint()
            .is_some_and(|size| size > MAX_ANDROID_DER_CHAIN_LENGTH)
        {
            return Err(A::Error::custom("Android DER chain is oversized"));
        }

        let capacity = sequence
            .size_hint()
            .unwrap_or_default()
            .min(MAX_ANDROID_DER_CHAIN_LENGTH);
        let mut certificates = Vec::with_capacity(capacity);
        let mut total_bytes = 0usize;
        while certificates.len() < MAX_ANDROID_DER_CHAIN_LENGTH {
            let Some(certificate) = sequence.next_element::<BoundedDerCertificate>()? else {
                return Ok(certificates);
            };
            total_bytes = total_bytes
                .checked_add(certificate.0.len())
                .ok_or_else(|| A::Error::custom("Android DER chain size overflow"))?;
            if total_bytes > MAX_ANDROID_DER_CHAIN_BYTES {
                return Err(A::Error::custom("Android DER chain is oversized"));
            }
            certificates.push(certificate.0);
        }

        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("Android DER chain is oversized"));
        }
        Ok(certificates)
    }
}

fn deserialize_bounded_der_chain<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedDerChainVisitor)
}

/// Requested minimum Android hardware tier.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AndroidSecurityPolicy {
    StrongBoxRequired,
    AndroidTeeAllowed,
}

impl AndroidSecurityPolicy {
    const fn canonical_tag(self) -> u8 {
        match self {
            Self::StrongBoxRequired => 1,
            Self::AndroidTeeAllowed => 2,
        }
    }
}

/// Provider-reported tier. `Software` is represented so that a structural
/// fixture cannot be confused with Android TEE or StrongBox evidence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AndroidReportedTier {
    StrongBox,
    AndroidTee,
    Software,
}

impl AndroidReportedTier {
    const fn canonical_tag(self) -> u8 {
        match self {
            Self::StrongBox => 1,
            Self::AndroidTee => 2,
            Self::Software => 3,
        }
    }
}

/// Key purpose reported/requested for the Android authorization boundary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AndroidKeyPurpose {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    AgreeKey,
    AttestKey,
}

impl AndroidKeyPurpose {
    const fn canonical_tag(self) -> u8 {
        match self {
            Self::Sign => 1,
            Self::Verify => 2,
            Self::Encrypt => 3,
            Self::Decrypt => 4,
            Self::AgreeKey => 5,
            Self::AttestKey => 6,
        }
    }
}

/// Key algorithm reported/requested for the Android authorization boundary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AndroidKeyAlgorithm {
    EcP256,
    Rsa,
    Ed25519,
}

impl AndroidKeyAlgorithm {
    const fn canonical_tag(self) -> u8 {
        match self {
            Self::EcP256 => 1,
            Self::Rsa => 2,
            Self::Ed25519 => 3,
        }
    }
}

/// Opaque Play Integrity evidence carried across the boundary.
///
/// The bytes are transport-only until a server-side verifier authenticates
/// them and compares their request hash to the exact binding digest. This type
/// intentionally does not parse or trust a client-supplied verdict.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AndroidPlayIntegrityEvidence {
    pub version: u16,
    #[serde(deserialize_with = "deserialize_bounded_play_integrity_evidence")]
    pub opaque_evidence: Vec<u8>,
}

impl fmt::Debug for AndroidPlayIntegrityEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AndroidPlayIntegrityEvidence")
            .field("version", &self.version)
            .field("opaque_evidence_len", &self.opaque_evidence.len())
            .field(
                "opaque_evidence_digest",
                &Sha256::digest(&self.opaque_evidence),
            )
            .finish()
    }
}

impl AndroidPlayIntegrityEvidence {
    pub fn new(opaque_evidence: Vec<u8>) -> ConclaveResult<Self> {
        let evidence = Self {
            version: ANDROID_AUTHORIZATION_VERSION,
            opaque_evidence,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        validate_version(self.version)?;
        validate_bounded_bytes(&self.opaque_evidence, MAX_PLAY_INTEGRITY_EVIDENCE_BYTES)
    }

    // Internal structural digest only; never sufficient for authorization.
    fn digest(&self) -> ConclaveResult<[u8; 32]> {
        self.validate()?;
        let mut canonical = Vec::new();
        append_len_prefixed(&mut canonical, ANDROID_PLAY_INTEGRITY_DOMAIN.as_bytes())?;
        canonical.extend_from_slice(&self.version.to_be_bytes());
        append_len_prefixed(&mut canonical, &self.opaque_evidence)?;
        Ok(Sha256::digest(canonical).into())
    }
}

/// Exact authorization request to which Android evidence must bind.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AndroidAuthorizationRequest {
    pub version: u16,
    pub security_policy: AndroidSecurityPolicy,
    #[serde(deserialize_with = "deserialize_bounded_identifier::<_, MAX_ANDROID_KEY_ID_BYTES>")]
    pub key_id: String,
    pub public_key_digest: [u8; 32],
    #[serde(
        deserialize_with = "deserialize_bounded_identifier::<_, MAX_ANDROID_PACKAGE_NAME_BYTES>"
    )]
    pub package_name: String,
    pub signing_certificate_digest: [u8; 32],
    #[serde(deserialize_with = "deserialize_bounded_nonce")]
    pub nonce: Vec<u8>,
    #[serde(deserialize_with = "deserialize_bounded_challenge")]
    pub challenge: Vec<u8>,
    pub operation_digest: [u8; 32],
    pub key_purpose: AndroidKeyPurpose,
    pub key_algorithm: AndroidKeyAlgorithm,
}

impl fmt::Debug for AndroidAuthorizationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AndroidAuthorizationRequest")
            .field("version", &self.version)
            .field("security_policy", &self.security_policy)
            .field("key_id", &self.key_id)
            .field("public_key_digest", &self.public_key_digest)
            .field("package_name", &self.package_name)
            .field(
                "signing_certificate_digest",
                &self.signing_certificate_digest,
            )
            .field("nonce_len", &self.nonce.len())
            .field("challenge_len", &self.challenge.len())
            .field("operation_digest", &self.operation_digest)
            .field("key_purpose", &self.key_purpose)
            .field("key_algorithm", &self.key_algorithm)
            .finish()
    }
}

impl AndroidAuthorizationRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        security_policy: AndroidSecurityPolicy,
        key_id: impl Into<String>,
        public_key_digest: [u8; 32],
        package_name: impl Into<String>,
        signing_certificate_digest: [u8; 32],
        nonce: Vec<u8>,
        challenge: Vec<u8>,
        operation_digest: [u8; 32],
        key_purpose: AndroidKeyPurpose,
        key_algorithm: AndroidKeyAlgorithm,
    ) -> ConclaveResult<Self> {
        let request = Self {
            version: ANDROID_AUTHORIZATION_VERSION,
            security_policy,
            key_id: key_id.into(),
            public_key_digest,
            package_name: package_name.into(),
            signing_certificate_digest,
            nonce,
            challenge,
            operation_digest,
            key_purpose,
            key_algorithm,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        validate_version(self.version)?;
        validate_identifier(&self.key_id, MAX_ANDROID_KEY_ID_BYTES)?;
        validate_identifier(&self.package_name, MAX_ANDROID_PACKAGE_NAME_BYTES)?;
        validate_digest(&self.public_key_digest)?;
        validate_digest(&self.signing_certificate_digest)?;
        validate_digest(&self.operation_digest)?;
        validate_bounded_bytes(&self.nonce, MAX_ANDROID_NONCE_BYTES)?;
        validate_bounded_bytes(&self.challenge, MAX_ANDROID_CHALLENGE_BYTES)
    }

    pub fn binding_digest_at(
        &self,
        evidence: &AndroidAuthorizationEvidence,
        now_secs: u64,
    ) -> ConclaveResult<[u8; 32]> {
        request_binding_digest_at(self, evidence, now_secs)
    }
}

/// Android-reported evidence for one exact authorization request.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AndroidAuthorizationEvidence {
    pub version: u16,
    pub actual_tier: AndroidReportedTier,
    #[serde(deserialize_with = "deserialize_bounded_identifier::<_, MAX_ANDROID_KEY_ID_BYTES>")]
    pub key_id: String,
    pub public_key_digest: [u8; 32],
    #[serde(
        deserialize_with = "deserialize_bounded_identifier::<_, MAX_ANDROID_PACKAGE_NAME_BYTES>"
    )]
    pub package_name: String,
    pub signing_certificate_digest: [u8; 32],
    #[serde(deserialize_with = "deserialize_bounded_nonce")]
    pub nonce: Vec<u8>,
    #[serde(deserialize_with = "deserialize_bounded_challenge")]
    pub challenge: Vec<u8>,
    pub operation_digest: [u8; 32],
    pub key_purpose: AndroidKeyPurpose,
    pub key_algorithm: AndroidKeyAlgorithm,
    #[serde(deserialize_with = "deserialize_bounded_der_chain")]
    pub certificate_chain: Vec<Vec<u8>>,
    pub play_integrity_evidence: Option<AndroidPlayIntegrityEvidence>,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl fmt::Debug for AndroidAuthorizationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AndroidAuthorizationEvidence")
            .field("version", &self.version)
            .field("actual_tier", &self.actual_tier)
            .field("key_id", &self.key_id)
            .field("public_key_digest", &self.public_key_digest)
            .field("package_name", &self.package_name)
            .field(
                "signing_certificate_digest",
                &self.signing_certificate_digest,
            )
            .field("nonce_len", &self.nonce.len())
            .field("challenge_len", &self.challenge.len())
            .field("operation_digest", &self.operation_digest)
            .field("key_purpose", &self.key_purpose)
            .field("key_algorithm", &self.key_algorithm)
            .field("certificate_count", &self.certificate_chain.len())
            .field(
                "certificate_chain_bytes",
                &self.certificate_chain.iter().map(Vec::len).sum::<usize>(),
            )
            .field(
                "certificate_chain_digest",
                &self.certificate_chain_digest().ok(),
            )
            .field(
                "play_integrity_evidence",
                &self
                    .play_integrity_evidence
                    .as_ref()
                    .map(|evidence| (evidence.version, evidence.opaque_evidence.len())),
            )
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl AndroidAuthorizationEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        actual_tier: AndroidReportedTier,
        key_id: impl Into<String>,
        public_key_digest: [u8; 32],
        package_name: impl Into<String>,
        signing_certificate_digest: [u8; 32],
        nonce: Vec<u8>,
        challenge: Vec<u8>,
        operation_digest: [u8; 32],
        key_purpose: AndroidKeyPurpose,
        key_algorithm: AndroidKeyAlgorithm,
        certificate_chain: Vec<Vec<u8>>,
        play_integrity_evidence: Option<AndroidPlayIntegrityEvidence>,
        issued_at: u64,
        expires_at: u64,
    ) -> ConclaveResult<Self> {
        let evidence = Self {
            version: ANDROID_AUTHORIZATION_VERSION,
            actual_tier,
            key_id: key_id.into(),
            public_key_digest,
            package_name: package_name.into(),
            signing_certificate_digest,
            nonce,
            challenge,
            operation_digest,
            key_purpose,
            key_algorithm,
            certificate_chain,
            play_integrity_evidence,
            issued_at,
            expires_at,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Validates only the bounded structural shape. This is not an
    /// authorization or freshness check; use [`Self::validate_at`] or
    /// [`Self::validate_against`] before treating evidence as current.
    pub fn validate(&self) -> ConclaveResult<()> {
        validate_version(self.version)?;
        validate_identifier(&self.key_id, MAX_ANDROID_KEY_ID_BYTES)?;
        validate_identifier(&self.package_name, MAX_ANDROID_PACKAGE_NAME_BYTES)?;
        validate_digest(&self.public_key_digest)?;
        validate_digest(&self.signing_certificate_digest)?;
        validate_digest(&self.operation_digest)?;
        validate_bounded_bytes(&self.nonce, MAX_ANDROID_NONCE_BYTES)?;
        validate_bounded_bytes(&self.challenge, MAX_ANDROID_CHALLENGE_BYTES)?;
        self.validate_certificate_chain()?;
        self.play_integrity_evidence
            .as_ref()
            .ok_or_else(invalid_payload)?
            .validate()?;

        if self.expires_at < self.issued_at {
            return Err(invalid_payload());
        }
        let maximum_expiry = self
            .issued_at
            .checked_add(MAX_ANDROID_AUTHORIZATION_LIFETIME_SECS)
            .ok_or_else(invalid_payload)?;
        if self.expires_at > maximum_expiry {
            return Err(invalid_payload());
        }
        Ok(())
    }

    /// Validates evidence freshness against an explicit trusted clock value.
    pub fn validate_at(&self, now_secs: u64) -> ConclaveResult<()> {
        self.validate()?;
        let future_limit = now_secs
            .checked_add(MAX_ANDROID_AUTHORIZATION_FUTURE_SKEW_SECS)
            .ok_or_else(invalid_payload)?;
        if self.issued_at > future_limit {
            return Err(authorization_mismatch());
        }
        if self.issued_at <= now_secs
            && now_secs.saturating_sub(self.issued_at) > MAX_ANDROID_AUTHORIZATION_AGE_SECS
        {
            return Err(authorization_mismatch());
        }
        if self.expires_at < now_secs {
            return Err(authorization_mismatch());
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        request: &AndroidAuthorizationRequest,
        now_secs: u64,
    ) -> ConclaveResult<()> {
        request.validate()?;
        self.validate_at(now_secs)?;
        validate_request_match(request, self)?;
        validate_security_policy(request.security_policy, self.actual_tier)
    }

    // Internal component digest only; never sufficient for authorization.
    fn certificate_chain_digest(&self) -> ConclaveResult<[u8; 32]> {
        self.validate_certificate_chain()?;
        let mut canonical = Vec::new();
        append_len_prefixed(&mut canonical, ANDROID_DER_CHAIN_DOMAIN.as_bytes())?;
        let count = u32::try_from(self.certificate_chain.len()).map_err(|_| invalid_payload())?;
        canonical.extend_from_slice(&count.to_be_bytes());
        for certificate in &self.certificate_chain {
            append_len_prefixed(&mut canonical, certificate)?;
        }
        Ok(Sha256::digest(canonical).into())
    }

    // Internal component digest only; never sufficient for authorization.
    fn play_integrity_digest(&self) -> ConclaveResult<[u8; 32]> {
        self.play_integrity_evidence
            .as_ref()
            .ok_or_else(invalid_payload)?
            .digest()
    }

    pub fn binding_digest_at(
        &self,
        request: &AndroidAuthorizationRequest,
        now_secs: u64,
    ) -> ConclaveResult<[u8; 32]> {
        request_binding_digest_at(request, self, now_secs)
    }

    fn validate_certificate_chain(&self) -> ConclaveResult<()> {
        if self.certificate_chain.is_empty()
            || self.certificate_chain.len() > MAX_ANDROID_DER_CHAIN_LENGTH
        {
            return Err(invalid_payload());
        }

        let mut total_bytes = 0usize;
        for certificate in &self.certificate_chain {
            validate_bounded_bytes(certificate, MAX_ANDROID_DER_CERTIFICATE_BYTES)?;
            total_bytes = total_bytes
                .checked_add(certificate.len())
                .ok_or_else(invalid_payload)?;
            if total_bytes > MAX_ANDROID_DER_CHAIN_BYTES {
                return Err(invalid_payload());
            }
        }
        Ok(())
    }
}

fn append_request_fields(
    output: &mut Vec<u8>,
    request: &AndroidAuthorizationRequest,
) -> ConclaveResult<()> {
    output.extend_from_slice(&request.version.to_be_bytes());
    output.push(request.security_policy.canonical_tag());
    append_identifier(output, &request.key_id)?;
    output.extend_from_slice(&request.public_key_digest);
    append_identifier(output, &request.package_name)?;
    output.extend_from_slice(&request.signing_certificate_digest);
    append_len_prefixed(output, &request.nonce)?;
    append_len_prefixed(output, &request.challenge)?;
    output.extend_from_slice(&request.operation_digest);
    output.push(request.key_purpose.canonical_tag());
    output.push(request.key_algorithm.canonical_tag());
    Ok(())
}

fn validate_request_match(
    request: &AndroidAuthorizationRequest,
    evidence: &AndroidAuthorizationEvidence,
) -> ConclaveResult<()> {
    if request.version != evidence.version
        || request.key_id != evidence.key_id
        || request.public_key_digest != evidence.public_key_digest
        || request.package_name != evidence.package_name
        || request.signing_certificate_digest != evidence.signing_certificate_digest
        || request.nonce != evidence.nonce
        || request.challenge != evidence.challenge
        || request.operation_digest != evidence.operation_digest
        || request.key_purpose != evidence.key_purpose
        || request.key_algorithm != evidence.key_algorithm
    {
        return Err(authorization_mismatch());
    }
    Ok(())
}

fn validate_security_policy(
    policy: AndroidSecurityPolicy,
    actual_tier: AndroidReportedTier,
) -> ConclaveResult<()> {
    let allowed = match policy {
        AndroidSecurityPolicy::StrongBoxRequired => actual_tier == AndroidReportedTier::StrongBox,
        AndroidSecurityPolicy::AndroidTeeAllowed => {
            matches!(
                actual_tier,
                AndroidReportedTier::StrongBox | AndroidReportedTier::AndroidTee
            )
        }
    };
    if allowed {
        Ok(())
    } else {
        Err(authorization_mismatch())
    }
}

fn request_binding_bytes(
    request: &AndroidAuthorizationRequest,
    evidence: &AndroidAuthorizationEvidence,
) -> ConclaveResult<Vec<u8>> {
    request.validate()?;
    evidence.validate()?;
    validate_request_match(request, evidence)?;
    validate_security_policy(request.security_policy, evidence.actual_tier)?;

    let mut canonical = Vec::new();
    append_len_prefixed(
        &mut canonical,
        ANDROID_AUTHORIZATION_BINDING_DOMAIN.as_bytes(),
    )?;
    append_request_fields(&mut canonical, request)?;
    canonical.extend_from_slice(&evidence.version.to_be_bytes());
    canonical.push(evidence.actual_tier.canonical_tag());
    canonical.extend_from_slice(&evidence.certificate_chain_digest()?);
    canonical.extend_from_slice(&evidence.play_integrity_digest()?);
    canonical.extend_from_slice(&evidence.issued_at.to_be_bytes());
    canonical.extend_from_slice(&evidence.expires_at.to_be_bytes());
    Ok(canonical)
}

/// Internal structural binding helper. It deliberately does not consume a
/// replay record, so callers must perform the freshness-aware public validation
/// before reaching it.
fn structural_request_binding_digest(
    request: &AndroidAuthorizationRequest,
    evidence: &AndroidAuthorizationEvidence,
) -> ConclaveResult<[u8; 32]> {
    Ok(Sha256::digest(request_binding_bytes(request, evidence)?).into())
}

/// Freshness-aware request binding. The digest itself is independent of the
/// wall clock; `now_secs` is used only to reject stale or future evidence
/// before returning it.
pub fn request_binding_digest_at(
    request: &AndroidAuthorizationRequest,
    evidence: &AndroidAuthorizationEvidence,
    now_secs: u64,
) -> ConclaveResult<[u8; 32]> {
    evidence.validate_against(request, now_secs)?;
    structural_request_binding_digest(request, evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::replay_guard::ReplayGuard;
    use crate::enclave::{
        ProofBundle, ProofEnvelope, ProofKind, ProofPolicy, ProofRequirement,
        ProofVerificationContext, ProofVerifierRegistry, ProofVerifierStatus,
        PHONE_PROOF_VERIFIER_ID,
    };

    const NOW: u64 = 1_000_000;

    fn digest(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn request(policy: AndroidSecurityPolicy) -> AndroidAuthorizationRequest {
        AndroidAuthorizationRequest::new(
            policy,
            "android-key-1",
            digest(2),
            "com.example.authorization",
            digest(3),
            vec![4; 16],
            vec![5; 32],
            digest(6),
            AndroidKeyPurpose::Sign,
            AndroidKeyAlgorithm::EcP256,
        )
        .expect("fixture request")
    }

    fn play_integrity() -> AndroidPlayIntegrityEvidence {
        AndroidPlayIntegrityEvidence::new(b"synthetic-play-integrity-evidence".to_vec())
            .expect("fixture Play Integrity evidence")
    }

    fn evidence(actual_tier: AndroidReportedTier) -> AndroidAuthorizationEvidence {
        AndroidAuthorizationEvidence::new(
            actual_tier,
            "android-key-1",
            digest(2),
            "com.example.authorization",
            digest(3),
            vec![4; 16],
            vec![5; 32],
            digest(6),
            AndroidKeyPurpose::Sign,
            AndroidKeyAlgorithm::EcP256,
            vec![vec![0x30, 0x03, 0x01, 0x01, 0x00]],
            Some(play_integrity()),
            NOW - 10,
            NOW + 60,
        )
        .expect("fixture evidence")
    }

    #[test]
    fn positive_structural_boundary_is_canonical_and_deterministic() {
        let request = request(AndroidSecurityPolicy::StrongBoxRequired);
        let evidence = evidence(AndroidReportedTier::StrongBox);
        let first = request
            .binding_digest_at(&evidence, NOW)
            .expect("matching evidence should bind");
        let second = request
            .binding_digest_at(&evidence, NOW)
            .expect("matching evidence should bind deterministically");
        assert_eq!(first, second);
        assert_eq!(
            first,
            request_binding_digest_at(&request, &evidence, NOW).unwrap()
        );
        assert_eq!(
            first,
            evidence
                .binding_digest_at(&request, NOW)
                .expect("matching evidence should bind")
        );
    }

    #[test]
    fn binding_changes_when_security_context_or_evidence_changes() {
        let request = request(AndroidSecurityPolicy::StrongBoxRequired);
        let evidence = evidence(AndroidReportedTier::StrongBox);
        let baseline = request
            .binding_digest_at(&evidence, NOW)
            .expect("baseline binding");

        let mut changed_request = request.clone();
        changed_request.key_id = "android-key-2".to_string();
        let mut changed_key_evidence = evidence.clone();
        changed_key_evidence.key_id = "android-key-2".to_string();
        assert_ne!(
            baseline,
            changed_request
                .binding_digest_at(&changed_key_evidence, NOW)
                .expect("changed key identity remains structurally valid")
        );

        let mut changed_evidence = evidence.clone();
        changed_evidence.certificate_chain[0].push(0x00);
        assert_ne!(
            baseline,
            request
                .binding_digest_at(&changed_evidence, NOW)
                .expect("changed DER evidence remains bounded")
        );

        let mut changed_play = evidence;
        changed_play
            .play_integrity_evidence
            .as_mut()
            .expect("Play evidence")
            .opaque_evidence
            .push(0x01);
        assert_ne!(
            baseline,
            request
                .binding_digest_at(&changed_play, NOW)
                .expect("changed Play evidence remains bounded")
        );
    }

    #[test]
    fn android_tee_policy_accepts_tee_and_strongbox_but_not_software() {
        let request = request(AndroidSecurityPolicy::AndroidTeeAllowed);
        assert!(request
            .binding_digest_at(&evidence(AndroidReportedTier::AndroidTee), NOW)
            .is_ok());
        assert!(request
            .binding_digest_at(&evidence(AndroidReportedTier::StrongBox), NOW)
            .is_ok());
        assert!(request
            .binding_digest_at(&evidence(AndroidReportedTier::Software), NOW)
            .is_err());
    }

    #[test]
    fn strongbox_required_rejects_android_tee_downgrade() {
        let request = request(AndroidSecurityPolicy::StrongBoxRequired);
        let evidence = evidence(AndroidReportedTier::AndroidTee);
        assert!(matches!(
            request.binding_digest_at(&evidence, NOW),
            Err(ConclaveError::EnclaveFailure(_))
        ));
    }

    #[test]
    fn mismatched_request_fields_are_rejected_without_fallback() {
        let request = request(AndroidSecurityPolicy::StrongBoxRequired);
        let evidence = evidence(AndroidReportedTier::StrongBox);

        let mut mismatched = evidence.clone();
        mismatched.operation_digest = digest(7);
        assert!(request.binding_digest_at(&mismatched, NOW).is_err());

        let mut mismatched_package = evidence.clone();
        mismatched_package.package_name = "com.example.other".to_string();
        assert!(request.binding_digest_at(&mismatched_package, NOW).is_err());

        let mut mismatched_algorithm = evidence;
        mismatched_algorithm.key_algorithm = AndroidKeyAlgorithm::Rsa;
        assert!(request
            .binding_digest_at(&mismatched_algorithm, NOW)
            .is_err());
    }

    #[test]
    fn missing_play_integrity_evidence_is_rejected() {
        let request = request(AndroidSecurityPolicy::StrongBoxRequired);
        let mut evidence = evidence(AndroidReportedTier::StrongBox);
        evidence.play_integrity_evidence = None;
        assert!(matches!(
            request.binding_digest_at(&evidence, NOW),
            Err(ConclaveError::InvalidPayload)
        ));
    }

    #[test]
    fn every_public_binding_method_rejects_stale_expired_and_future_evidence() {
        let request = request(AndroidSecurityPolicy::StrongBoxRequired);

        let mut stale = evidence(AndroidReportedTier::StrongBox);
        stale.issued_at = NOW - MAX_ANDROID_AUTHORIZATION_AGE_SECS - 1;
        stale.expires_at = NOW + 60;
        assert!(request.binding_digest_at(&stale, NOW).is_err());
        assert!(stale.binding_digest_at(&request, NOW).is_err());
        assert!(request_binding_digest_at(&request, &stale, NOW).is_err());

        let mut expired = evidence(AndroidReportedTier::StrongBox);
        expired.expires_at = NOW - 1;
        assert!(request.binding_digest_at(&expired, NOW).is_err());
        assert!(expired.binding_digest_at(&request, NOW).is_err());
        assert!(request_binding_digest_at(&request, &expired, NOW).is_err());

        let mut future = evidence(AndroidReportedTier::StrongBox);
        future.issued_at = NOW + MAX_ANDROID_AUTHORIZATION_FUTURE_SKEW_SECS + 1;
        future.expires_at = future.issued_at + 60;
        assert!(request.binding_digest_at(&future, NOW).is_err());
        assert!(future.binding_digest_at(&request, NOW).is_err());
        assert!(request_binding_digest_at(&request, &future, NOW).is_err());
    }

    #[test]
    fn empty_and_oversized_fields_are_rejected() {
        let mut empty_key = request(AndroidSecurityPolicy::StrongBoxRequired);
        empty_key.key_id.clear();
        assert!(empty_key.validate().is_err());

        let mut empty_nonce = request(AndroidSecurityPolicy::StrongBoxRequired);
        empty_nonce.nonce.clear();
        assert!(empty_nonce.validate().is_err());

        let mut empty_chain = evidence(AndroidReportedTier::StrongBox);
        empty_chain.certificate_chain.clear();
        assert!(empty_chain.validate().is_err());

        let mut oversized_play = evidence(AndroidReportedTier::StrongBox);
        oversized_play
            .play_integrity_evidence
            .as_mut()
            .expect("Play evidence")
            .opaque_evidence = vec![0; MAX_PLAY_INTEGRITY_EVIDENCE_BYTES + 1];
        assert!(oversized_play.validate().is_err());

        let mut oversized_chain = evidence(AndroidReportedTier::StrongBox);
        oversized_chain.certificate_chain =
            vec![vec![1; MAX_ANDROID_DER_CERTIFICATE_BYTES]; MAX_ANDROID_DER_CHAIN_LENGTH];
        assert!(oversized_chain.validate().is_err());
    }

    #[test]
    fn serde_rejects_unknown_and_private_key_fields() {
        let request = request(AndroidSecurityPolicy::StrongBoxRequired);
        let mut request_json = serde_json::to_value(request).expect("request serialization");
        request_json["unexpected"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<AndroidAuthorizationRequest>(request_json).is_err());

        let evidence = evidence(AndroidReportedTier::StrongBox);
        let mut evidence_json = serde_json::to_value(evidence).expect("evidence serialization");
        evidence_json["private_key"] = serde_json::Value::String("never-accepted".to_string());
        assert!(serde_json::from_value::<AndroidAuthorizationEvidence>(evidence_json).is_err());
    }

    #[test]
    fn serde_bounds_nested_der_and_play_evidence() {
        let mut evidence_json = serde_json::to_value(evidence(AndroidReportedTier::StrongBox))
            .expect("evidence serialization");
        evidence_json["certificate_chain"] =
            serde_json::Value::Array(vec![serde_json::Value::Array(
                (0..MAX_ANDROID_DER_CERTIFICATE_BYTES + 1)
                    .map(|_| serde_json::Value::from(1u8))
                    .collect(),
            )]);
        assert!(serde_json::from_value::<AndroidAuthorizationEvidence>(evidence_json).is_err());

        let mut play_json = serde_json::to_value(play_integrity()).expect("Play serialization");
        play_json["opaque_evidence"] = serde_json::Value::Array(
            (0..MAX_PLAY_INTEGRITY_EVIDENCE_BYTES + 1)
                .map(|_| serde_json::Value::from(1u8))
                .collect(),
        );
        assert!(serde_json::from_value::<AndroidPlayIntegrityEvidence>(play_json).is_err());
    }

    #[test]
    fn debug_redacts_raw_provider_evidence() {
        let evidence = evidence(AndroidReportedTier::StrongBox);
        let debug = format!("{evidence:?}");
        assert!(!debug.contains("synthetic-play-integrity-evidence"));
        assert!(!debug.contains("48, 3, 1, 1, 0"));
        assert!(debug.contains("certificate_chain_digest"));
        assert!(debug.contains("play_integrity_evidence"));
    }

    #[test]
    fn phone_route_is_explicit_android_keymint_but_production_unavailable() {
        let request = request(AndroidSecurityPolicy::StrongBoxRequired);
        let evidence = evidence(AndroidReportedTier::StrongBox);
        let raw_evidence = serde_json::to_vec(&evidence).expect("synthetic evidence encoding");
        let context = ProofVerificationContext::new(
            request.operation_digest,
            "ANDROID_AUTHORIZATION",
            "conxian/android-authorization/v1",
            request.nonce.clone(),
            NOW,
        )
        .expect("proof context");
        let proof = ProofEnvelope::new(
            ProofKind::Phone,
            "android-proof-1",
            ANDROID_KEYMINT_PROOF_VERIFIER_ID,
            context.operation_digest,
            context.purpose.clone(),
            context.audience.clone(),
            context.nonce.clone(),
            NOW - 10,
            NOW + 60,
            raw_evidence,
        )
        .expect("well-shaped synthetic phone proof");
        let bundle = ProofBundle::new(vec![proof]).expect("proof bundle");
        let policy = ProofPolicy::new(
            vec![
                ProofRequirement::new(ProofKind::Phone, ANDROID_KEYMINT_PROOF_VERIFIER_ID)
                    .expect("phone requirement"),
            ],
            false,
        )
        .expect("phone policy");
        let registry = ProofVerifierRegistry::production();

        assert_eq!(
            ProofKind::Phone.production_verifier_id(),
            PHONE_PROOF_VERIFIER_ID
        );
        assert_eq!(
            PHONE_PROOF_VERIFIER_ID,
            "conxian.proof.phone.unavailable.v1"
        );
        assert_eq!(
            ProofPolicy::production()
                .required
                .iter()
                .find(|requirement| requirement.kind == ProofKind::Phone)
                .expect("production phone requirement")
                .verifier_id,
            PHONE_PROOF_VERIFIER_ID
        );
        assert_eq!(
            registry.verifier_status(ProofKind::Phone, PHONE_PROOF_VERIFIER_ID),
            ProofVerifierStatus::Unavailable
        );
        assert_eq!(
            registry.verifier_status(ProofKind::Phone, ANDROID_KEYMINT_PROOF_VERIFIER_ID),
            ProofVerifierStatus::Unavailable
        );
        assert!(matches!(
            registry.verify_bundle(&bundle, &policy, &context, &ReplayGuard::new(300, 32),),
            Err(ConclaveError::Unsupported(_))
        ));
    }
}
