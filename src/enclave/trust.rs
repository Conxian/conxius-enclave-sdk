//! Provider-neutral trust-bundle contracts.
//!
//! This module deliberately stops at the authenticated verifier boundary. It
//! models versioned bundle metadata, collateral policy, revocation, rotation,
//! and refresh state without shipping vendor roots or claiming provider
//! support. The production verifier registry is unavailable by design.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

/// Current schema version for provider-neutral trust snapshots.
pub const TRUST_BUNDLE_SCHEMA_VERSION: u16 = 1;
/// Domain separator for the canonical snapshot digest.
pub const TRUST_BUNDLE_DOMAIN: &str = "CONXIAN-TRUST-BUNDLE/v1";
/// Domain separator for the authenticated envelope digest. This digest binds
/// route and source metadata in addition to the snapshot digest.
pub const TRUST_AUTHENTICATED_ENVELOPE_DOMAIN: &str = "CONXIAN-TRUST-ENVELOPE/v1";
/// Authentication profile used by the current fixture verifier and reserved
/// as the default for route descriptors until provider-specific profiles exist.
pub const TRUST_AUTHENTICATION_PROFILE_ED25519: &str = "ed25519-signature";
pub const TRUST_AUTHENTICATION_PROFILE_VERSION: u16 = 1;
/// Maximum serialized trust-bundle transport accepted by the bounded entry
/// point.
pub const MAX_TRUST_BUNDLE_TRANSPORT_BYTES: usize = 256 * 1024;

/// Default trusted-evidence freshness policy. Provider integrations may choose
/// a stricter policy, but cannot exceed the bounded maxima below.
pub const DEFAULT_MAX_TRUST_EVIDENCE_AGE_SECS: u64 = 5 * 60;
pub const DEFAULT_MAX_TRUST_EVIDENCE_FUTURE_SKEW_SECS: u64 = 30;
pub const MAX_TRUST_EVIDENCE_AGE_SECS: u64 = 24 * 60 * 60;
pub const MAX_TRUST_EVIDENCE_FUTURE_SKEW_SECS: u64 = 15 * 60;

pub const TRUST_PROVIDER_ANDROID_KEYMINT: &str = "android.keymint";
pub const TRUST_PROVIDER_AWS_NITRO: &str = "aws.nitro";
pub const TRUST_PROVIDER_INTEL_DCAP: &str = "intel.dcap";
pub const TRUST_PROVIDER_AMD_SEV_SNP: &str = "amd.sev-snp";
pub const TRUST_PROVIDER_TPM: &str = "tpm.quote";
pub const TRUST_PROVIDER_FIDO: &str = "fido.metadata";

pub const TRUST_VERIFIER_ANDROID_KEYMINT: &str = "conxian.trust.android.keymint.unavailable.v1";
pub const TRUST_VERIFIER_AWS_NITRO: &str = "conxian.trust.aws.nitro.unavailable.v1";
pub const TRUST_VERIFIER_INTEL_DCAP: &str = "conxian.trust.intel.dcap.unavailable.v1";
pub const TRUST_VERIFIER_AMD_SEV_SNP: &str = "conxian.trust.amd.sev-snp.unavailable.v1";
pub const TRUST_VERIFIER_TPM: &str = "conxian.trust.tpm.quote.unavailable.v1";
pub const TRUST_VERIFIER_FIDO: &str = "conxian.trust.fido.metadata.unavailable.v1";

#[cfg(test)]
const TEST_FIXTURE_VERIFIER_ID: &str = "conxian.trust.test-fixture.v1";
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_TCB_ENTRIES: usize = 64;
const MAX_MEASUREMENT_ENTRIES: usize = 64;
const MAX_REVOKED_EVIDENCE_ENTRIES: usize = 128;
const MAX_SIGNATURE_BYTES: usize = 4096;

/// Deterministic fail-closed states for trust validation and refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrustValidationError {
    #[error("trust bundle schema version is unknown")]
    UnknownSchema,
    #[error("trust bundle provider is unknown")]
    UnknownProvider,
    #[error("trust bundle authentication route is unknown")]
    UnknownAuthentication,
    #[error("trust bundle authentication is unavailable")]
    AuthenticationUnavailable,
    #[error("trust bundle authentication failed")]
    Unauthenticated,
    #[error("trust bundle is malformed")]
    Malformed,
    #[error("trust bundle content exceeds its bound")]
    Oversized,
    #[error("trust bundle is not yet valid")]
    NotYetValid,
    #[error("trust bundle has expired")]
    Expired,
    #[error("trust collateral is stale")]
    StaleCollateral,
    #[error("trust evidence has been revoked")]
    RevokedEvidence,
    #[error("trust evidence has an unacceptable TCB")]
    UnacceptableTcb,
    #[error("trust evidence has an unacceptable measurement")]
    UnacceptableMeasurement,
    #[error("trust bundle sequence moved backwards")]
    SequenceRollback,
    #[error("test or software fixture cannot be promoted")]
    TestFixturePromotion,
    #[error("trust refresh backend is unavailable")]
    BackendUnavailable,
    #[error("trusted security clock is unavailable")]
    ClockUnavailable,
    #[error("trusted security clock is untrusted")]
    ClockUntrusted,
    #[error("trusted security clock moved backwards")]
    ClockRollback,
    #[error("trust evidence provider does not match the bundle")]
    ProviderMismatch,
    #[error("trust evidence is outside the bundle validity interval")]
    EvidenceOutsideBundleValidity,
    #[error("trust evidence is not yet valid under the trusted clock")]
    EvidenceNotYetValid,
    #[error("trust evidence is stale under the freshness policy")]
    EvidenceStale,
}

/// Clock input is explicit so an untrusted wall clock cannot be silently used
/// for security decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustClockObservation {
    Trusted(u64),
    Untrusted(u64),
    Unavailable,
    Rollback,
}

/// The source class is authenticated as part of the envelope and is never
/// enough by itself to authenticate a bundle. A test source is accepted only
/// by the crate-internal fixture validator.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustBundleSource {
    Provider,
    TestFixture,
}

impl TrustBundleSource {
    fn canonical_tag(self) -> u8 {
        match self {
            Self::Provider => 1,
            Self::TestFixture => 2,
        }
    }
}

/// Explicit policy for the `TrustEvidence::issued_at` field. Evidence is
/// accepted only when it is within the trusted-clock freshness window and the
/// authenticated bundle validity interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustEvidenceFreshnessPolicy {
    max_age_secs: u64,
    max_future_skew_secs: u64,
}

impl TrustEvidenceFreshnessPolicy {
    pub fn new(max_age_secs: u64, max_future_skew_secs: u64) -> Result<Self, TrustValidationError> {
        if max_age_secs == 0
            || max_age_secs > MAX_TRUST_EVIDENCE_AGE_SECS
            || max_future_skew_secs > MAX_TRUST_EVIDENCE_FUTURE_SKEW_SECS
        {
            return Err(TrustValidationError::Malformed);
        }
        Ok(Self {
            max_age_secs,
            max_future_skew_secs,
        })
    }

    pub const fn defaults() -> Self {
        Self {
            max_age_secs: DEFAULT_MAX_TRUST_EVIDENCE_AGE_SECS,
            max_future_skew_secs: DEFAULT_MAX_TRUST_EVIDENCE_FUTURE_SKEW_SECS,
        }
    }

    pub const fn max_age_secs(self) -> u64 {
        self.max_age_secs
    }

    pub const fn max_future_skew_secs(self) -> u64 {
        self.max_future_skew_secs
    }
}

fn validate_identifier(value: &str) -> Result<(), TrustValidationError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(TrustValidationError::Malformed);
    }
    Ok(())
}

fn validate_digest(value: &[u8; 32]) -> Result<(), TrustValidationError> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(TrustValidationError::Malformed);
    }
    Ok(())
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Result<(), TrustValidationError> {
    let length = u32::try_from(value.len()).map_err(|_| TrustValidationError::Oversized)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn append_identifier(output: &mut Vec<u8>, value: &str) -> Result<(), TrustValidationError> {
    append_len_prefixed(output, value.as_bytes())
}

fn known_provider(provider: &str) -> bool {
    matches!(
        provider,
        TRUST_PROVIDER_ANDROID_KEYMINT
            | TRUST_PROVIDER_AWS_NITRO
            | TRUST_PROVIDER_INTEL_DCAP
            | TRUST_PROVIDER_AMD_SEV_SNP
            | TRUST_PROVIDER_TPM
            | TRUST_PROVIDER_FIDO
    )
}

fn production_verifier_id(provider: &str) -> Option<&'static str> {
    match provider {
        TRUST_PROVIDER_ANDROID_KEYMINT => Some(TRUST_VERIFIER_ANDROID_KEYMINT),
        TRUST_PROVIDER_AWS_NITRO => Some(TRUST_VERIFIER_AWS_NITRO),
        TRUST_PROVIDER_INTEL_DCAP => Some(TRUST_VERIFIER_INTEL_DCAP),
        TRUST_PROVIDER_AMD_SEV_SNP => Some(TRUST_VERIFIER_AMD_SEV_SNP),
        TRUST_PROVIDER_TPM => Some(TRUST_VERIFIER_TPM),
        TRUST_PROVIDER_FIDO => Some(TRUST_VERIFIER_FIDO),
        _ => None,
    }
}

/// Versioned collateral and policy snapshot. It stores only digests and
/// bounded policy identifiers; raw provider evidence is intentionally absent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustBundleSnapshot {
    pub schema_version: u16,
    pub provider: String,
    pub sequence: u64,
    pub issued_at: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub stale_after: u64,
    pub collateral_digest: [u8; 32],
    pub acceptable_tcb: Vec<String>,
    pub acceptable_measurements: Vec<[u8; 32]>,
    pub revoked_evidence: Vec<[u8; 32]>,
    pub fixture: bool,
}

impl TrustBundleSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: impl Into<String>,
        sequence: u64,
        issued_at: u64,
        not_before: u64,
        expires_at: u64,
        stale_after: u64,
        collateral_digest: [u8; 32],
        acceptable_tcb: Vec<String>,
        acceptable_measurements: Vec<[u8; 32]>,
        revoked_evidence: Vec<[u8; 32]>,
        fixture: bool,
    ) -> Result<Self, TrustValidationError> {
        let snapshot = Self {
            schema_version: TRUST_BUNDLE_SCHEMA_VERSION,
            provider: provider.into(),
            sequence,
            issued_at,
            not_before,
            expires_at,
            stale_after,
            collateral_digest,
            acceptable_tcb,
            acceptable_measurements,
            revoked_evidence,
            fixture,
        };
        snapshot.validate_shape()?;
        Ok(snapshot)
    }

    pub fn validate_shape(&self) -> Result<(), TrustValidationError> {
        if self.schema_version != TRUST_BUNDLE_SCHEMA_VERSION {
            return Err(TrustValidationError::UnknownSchema);
        }
        validate_identifier(&self.provider)?;
        if self.sequence == 0
            || self.issued_at > self.not_before
            || self.not_before >= self.expires_at
            || self.not_before >= self.stale_after
            || self.stale_after > self.expires_at
        {
            return Err(TrustValidationError::Malformed);
        }
        validate_digest(&self.collateral_digest)?;

        if self.acceptable_tcb.is_empty() || self.acceptable_tcb.len() > MAX_TCB_ENTRIES {
            return if self.acceptable_tcb.len() > MAX_TCB_ENTRIES {
                Err(TrustValidationError::Oversized)
            } else {
                Err(TrustValidationError::Malformed)
            };
        }
        let mut tcb = self.acceptable_tcb.clone();
        for value in &tcb {
            validate_identifier(value)?;
        }
        tcb.sort_unstable();
        if tcb.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(TrustValidationError::Malformed);
        }

        if self.acceptable_measurements.is_empty()
            || self.acceptable_measurements.len() > MAX_MEASUREMENT_ENTRIES
        {
            return if self.acceptable_measurements.len() > MAX_MEASUREMENT_ENTRIES {
                Err(TrustValidationError::Oversized)
            } else {
                Err(TrustValidationError::Malformed)
            };
        }
        for measurement in &self.acceptable_measurements {
            validate_digest(measurement)?;
        }
        let mut measurements = self.acceptable_measurements.clone();
        measurements.sort_unstable();
        if measurements.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(TrustValidationError::Malformed);
        }

        if self.revoked_evidence.len() > MAX_REVOKED_EVIDENCE_ENTRIES {
            return Err(TrustValidationError::Oversized);
        }
        for evidence in &self.revoked_evidence {
            validate_digest(evidence)?;
        }
        let mut revoked = self.revoked_evidence.clone();
        revoked.sort_unstable();
        if revoked.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(TrustValidationError::Malformed);
        }

        Ok(())
    }

    /// Canonical bytes sort set-like collateral fields. Construction order
    /// therefore cannot change the authenticated digest.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TrustValidationError> {
        self.validate_shape()?;

        let mut output = Vec::new();
        append_len_prefixed(&mut output, TRUST_BUNDLE_DOMAIN.as_bytes())?;
        output.extend_from_slice(&self.schema_version.to_be_bytes());
        append_identifier(&mut output, &self.provider)?;
        output.extend_from_slice(&self.sequence.to_be_bytes());
        output.extend_from_slice(&self.issued_at.to_be_bytes());
        output.extend_from_slice(&self.not_before.to_be_bytes());
        output.extend_from_slice(&self.expires_at.to_be_bytes());
        output.extend_from_slice(&self.stale_after.to_be_bytes());
        output.extend_from_slice(&self.collateral_digest);
        output.push(u8::from(self.fixture));

        let mut tcb = self.acceptable_tcb.clone();
        tcb.sort_unstable();
        let tcb_count = u32::try_from(tcb.len()).map_err(|_| TrustValidationError::Oversized)?;
        output.extend_from_slice(&tcb_count.to_be_bytes());
        for value in tcb {
            append_identifier(&mut output, &value)?;
        }

        let mut measurements = self.acceptable_measurements.clone();
        measurements.sort_unstable();
        let measurement_count =
            u32::try_from(measurements.len()).map_err(|_| TrustValidationError::Oversized)?;
        output.extend_from_slice(&measurement_count.to_be_bytes());
        for measurement in measurements {
            output.extend_from_slice(&measurement);
        }

        let mut revoked = self.revoked_evidence.clone();
        revoked.sort_unstable();
        let revoked_count =
            u32::try_from(revoked.len()).map_err(|_| TrustValidationError::Oversized)?;
        output.extend_from_slice(&revoked_count.to_be_bytes());
        for evidence in revoked {
            output.extend_from_slice(&evidence);
        }

        Ok(output)
    }

    pub fn canonical_digest(&self) -> Result<[u8; 32], TrustValidationError> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
}

/// Provider evidence represented only by its authenticated identity digest and
/// policy-relevant claims. Raw quotes, certificates, and credentials do not
/// enter the trust cache.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustEvidence {
    pub provider: String,
    pub evidence_digest: [u8; 32],
    pub tcb: String,
    pub measurement: [u8; 32],
    pub issued_at: u64,
}

impl TrustEvidence {
    pub fn new(
        provider: impl Into<String>,
        evidence_digest: [u8; 32],
        tcb: impl Into<String>,
        measurement: [u8; 32],
        issued_at: u64,
    ) -> Result<Self, TrustValidationError> {
        let evidence = Self {
            provider: provider.into(),
            evidence_digest,
            tcb: tcb.into(),
            measurement,
            issued_at,
        };
        evidence.validate_shape()?;
        Ok(evidence)
    }

    pub fn validate_shape(&self) -> Result<(), TrustValidationError> {
        validate_identifier(&self.provider)?;
        validate_digest(&self.evidence_digest)?;
        validate_identifier(&self.tcb)?;
        validate_digest(&self.measurement)
    }
}

/// Authenticated envelope around a canonical snapshot. The signed digest is an
/// authenticated envelope digest binding the snapshot and route/profile/source
/// metadata before the verifier sees the signature. A URI or digest without
/// this signature path is never accepted.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustBundleEnvelope {
    pub snapshot: TrustBundleSnapshot,
    /// Digest of the authenticated envelope encoding, not merely the snapshot
    /// digest. The signature must cover this field.
    pub signed_digest: [u8; 32],
    pub verifier_id: String,
    pub verifier_version: u16,
    pub authentication_profile: String,
    pub signature: Vec<u8>,
    pub source: TrustBundleSource,
}

impl fmt::Debug for TrustBundleEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustBundleEnvelope")
            .field("snapshot", &self.snapshot)
            .field("signed_digest", &self.signed_digest)
            .field("verifier_id", &self.verifier_id)
            .field("verifier_version", &self.verifier_version)
            .field("authentication_profile", &self.authentication_profile)
            .field("signature_len", &self.signature.len())
            .field("source", &self.source)
            .finish()
    }
}

impl TrustBundleEnvelope {
    pub fn new(
        snapshot: TrustBundleSnapshot,
        verifier_id: impl Into<String>,
        signature: Vec<u8>,
    ) -> Result<Self, TrustValidationError> {
        Self::new_with_authentication_and_source(
            snapshot,
            verifier_id,
            TRUST_AUTHENTICATION_PROFILE_VERSION,
            TRUST_AUTHENTICATION_PROFILE_ED25519,
            signature,
            TrustBundleSource::Provider,
        )
    }

    /// Constructs an envelope with an explicit authenticated route/profile.
    /// Operational transport locations are intentionally absent from this
    /// schema; only security-relevant route metadata is authenticated.
    pub fn new_with_authentication(
        snapshot: TrustBundleSnapshot,
        verifier_id: impl Into<String>,
        verifier_version: u16,
        authentication_profile: impl Into<String>,
        signature: Vec<u8>,
    ) -> Result<Self, TrustValidationError> {
        Self::new_with_authentication_and_source(
            snapshot,
            verifier_id,
            verifier_version,
            authentication_profile,
            signature,
            TrustBundleSource::Provider,
        )
    }

    #[cfg(test)]
    fn new_with_source(
        snapshot: TrustBundleSnapshot,
        verifier_id: impl Into<String>,
        signature: Vec<u8>,
        source: TrustBundleSource,
    ) -> Result<Self, TrustValidationError> {
        Self::new_with_authentication_and_source(
            snapshot,
            verifier_id,
            TRUST_AUTHENTICATION_PROFILE_VERSION,
            TRUST_AUTHENTICATION_PROFILE_ED25519,
            signature,
            source,
        )
    }

    fn new_with_authentication_and_source(
        snapshot: TrustBundleSnapshot,
        verifier_id: impl Into<String>,
        verifier_version: u16,
        authentication_profile: impl Into<String>,
        signature: Vec<u8>,
        source: TrustBundleSource,
    ) -> Result<Self, TrustValidationError> {
        let mut envelope = Self {
            snapshot,
            signed_digest: [0; 32],
            verifier_id: verifier_id.into(),
            verifier_version,
            authentication_profile: authentication_profile.into(),
            signature,
            source,
        };
        envelope.signed_digest = envelope.authenticated_digest()?;
        envelope.validate_shape()?;
        Ok(envelope)
    }

    pub fn validate_shape(&self) -> Result<(), TrustValidationError> {
        self.snapshot.validate_shape()?;
        validate_identifier(&self.verifier_id)?;
        if self.verifier_version == 0 {
            return Err(TrustValidationError::Malformed);
        }
        validate_identifier(&self.authentication_profile)?;
        if self.signature.is_empty() {
            return Err(TrustValidationError::Malformed);
        }
        if self.signature.len() > MAX_SIGNATURE_BYTES {
            return Err(TrustValidationError::Oversized);
        }
        if self.signed_digest != self.authenticated_digest()? {
            return Err(TrustValidationError::Malformed);
        }
        Ok(())
    }

    /// Returns the canonical snapshot digest for callers that need to inspect
    /// the snapshot commitment separately from the authenticated route digest.
    pub fn canonical_digest(&self) -> Result<[u8; 32], TrustValidationError> {
        self.snapshot.canonical_digest()
    }

    /// Canonical authenticated envelope bytes bind the snapshot digest,
    /// provider, verifier identity/version, authentication profile, and source
    /// classification. Mutable transport/URI text is deliberately excluded.
    fn authenticated_canonical_bytes(&self) -> Result<Vec<u8>, TrustValidationError> {
        self.snapshot.validate_shape()?;
        validate_identifier(&self.verifier_id)?;
        if self.verifier_version == 0 {
            return Err(TrustValidationError::Malformed);
        }
        validate_identifier(&self.authentication_profile)?;

        let mut output = Vec::new();
        append_len_prefixed(&mut output, TRUST_AUTHENTICATED_ENVELOPE_DOMAIN.as_bytes())?;
        output.extend_from_slice(&TRUST_AUTHENTICATION_PROFILE_VERSION.to_be_bytes());
        output.extend_from_slice(&self.snapshot.canonical_digest()?);
        append_identifier(&mut output, &self.snapshot.provider)?;
        append_identifier(&mut output, &self.verifier_id)?;
        output.extend_from_slice(&self.verifier_version.to_be_bytes());
        append_identifier(&mut output, &self.authentication_profile)?;
        output.push(self.source.canonical_tag());
        Ok(output)
    }

    pub fn authenticated_digest(&self) -> Result<[u8; 32], TrustValidationError> {
        Ok(Sha256::digest(self.authenticated_canonical_bytes()?).into())
    }

    pub fn snapshot(&self) -> &TrustBundleSnapshot {
        &self.snapshot
    }

    pub fn signed_digest(&self) -> &[u8; 32] {
        &self.signed_digest
    }

    pub fn verifier_id(&self) -> &str {
        &self.verifier_id
    }

    pub fn verifier_version(&self) -> u16 {
        self.verifier_version
    }

    pub fn authentication_profile(&self) -> &str {
        &self.authentication_profile
    }

    pub fn source(&self) -> TrustBundleSource {
        self.source
    }

    pub fn signature_len(&self) -> usize {
        self.signature.len()
    }

    fn signature_bytes(&self) -> &[u8] {
        &self.signature
    }

    #[cfg(test)]
    fn test_fixture(
        snapshot: TrustBundleSnapshot,
        signature: Vec<u8>,
    ) -> Result<Self, TrustValidationError> {
        Self::new_with_authentication_and_source(
            snapshot,
            TEST_FIXTURE_VERIFIER_ID,
            TRUST_AUTHENTICATION_PROFILE_VERSION,
            TRUST_AUTHENTICATION_PROFILE_ED25519,
            signature,
            TrustBundleSource::TestFixture,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustBundleWire {
    snapshot: TrustBundleSnapshot,
    signed_digest: [u8; 32],
    verifier_id: String,
    verifier_version: u16,
    authentication_profile: String,
    signature: Vec<u8>,
    source: TrustBundleSource,
}

/// Bounded JSON transport entry point. The resulting envelope is still
/// unauthenticated until a registered signature verifier validates it.
pub fn deserialize_trust_bundle_json(
    input: &[u8],
) -> Result<TrustBundleEnvelope, TrustValidationError> {
    if input.len() > MAX_TRUST_BUNDLE_TRANSPORT_BYTES {
        return Err(TrustValidationError::Oversized);
    }
    let wire: TrustBundleWire =
        serde_json::from_slice(input).map_err(|_| TrustValidationError::Malformed)?;
    let envelope = TrustBundleEnvelope {
        snapshot: wire.snapshot,
        signed_digest: wire.signed_digest,
        verifier_id: wire.verifier_id,
        verifier_version: wire.verifier_version,
        authentication_profile: wire.authentication_profile,
        signature: wire.signature,
        source: wire.source,
    };
    envelope.validate_shape()?;
    Ok(envelope)
}

/// Provider signature-verifier status. The production registry currently
/// exposes only `Unavailable`; test-only verification is not provider support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustBundleVerifierStatus {
    Unavailable,
    #[cfg(test)]
    TestOnly,
}

/// Authenticated verifier boundary for a canonical envelope digest.
pub trait TrustBundleVerifier: Send + Sync {
    fn provider(&self) -> &str;
    fn verifier_id(&self) -> &str;
    fn verifier_version(&self) -> u16;
    fn authentication_profile(&self) -> &str;
    fn status(&self) -> TrustBundleVerifierStatus;
    fn verify(
        &self,
        authenticated_digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), TrustValidationError>;
}

struct UnavailableTrustBundleVerifier {
    provider: &'static str,
    verifier_id: &'static str,
    verifier_version: u16,
    authentication_profile: &'static str,
}

impl TrustBundleVerifier for UnavailableTrustBundleVerifier {
    fn provider(&self) -> &str {
        self.provider
    }

    fn verifier_id(&self) -> &str {
        self.verifier_id
    }

    fn verifier_version(&self) -> u16 {
        self.verifier_version
    }

    fn authentication_profile(&self) -> &str {
        self.authentication_profile
    }

    fn status(&self) -> TrustBundleVerifierStatus {
        TrustBundleVerifierStatus::Unavailable
    }

    fn verify(
        &self,
        _authenticated_digest: &[u8; 32],
        _signature: &[u8],
    ) -> Result<(), TrustValidationError> {
        Err(TrustValidationError::AuthenticationUnavailable)
    }
}

#[cfg(test)]
struct FixtureTrustBundleVerifier {
    provider: &'static str,
}

#[cfg(test)]
impl TrustBundleVerifier for FixtureTrustBundleVerifier {
    fn provider(&self) -> &str {
        self.provider
    }

    fn verifier_id(&self) -> &str {
        TEST_FIXTURE_VERIFIER_ID
    }

    fn verifier_version(&self) -> u16 {
        TRUST_AUTHENTICATION_PROFILE_VERSION
    }

    fn authentication_profile(&self) -> &str {
        TRUST_AUTHENTICATION_PROFILE_ED25519
    }

    fn status(&self) -> TrustBundleVerifierStatus {
        TrustBundleVerifierStatus::TestOnly
    }

    fn verify(
        &self,
        authenticated_digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), TrustValidationError> {
        let verifying_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]).verifying_key();
        let signature = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| TrustValidationError::Unauthenticated)?;
        ed25519_dalek::Verifier::verify(&verifying_key, authenticated_digest, &signature)
            .map_err(|_| TrustValidationError::Unauthenticated)
    }
}

/// Exact `(provider, verifier_id, version, profile)` trust routes. No provider
/// roots or URI fetches are installed by this registry.
pub struct TrustBundleVerifierRegistry {
    verifiers: HashMap<(String, String, u16, String), Arc<dyn TrustBundleVerifier>>,
}

impl fmt::Debug for TrustBundleVerifierRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustBundleVerifierRegistry")
            .field("route_count", &self.verifiers.len())
            .finish()
    }
}

impl TrustBundleVerifierRegistry {
    pub fn production() -> Self {
        let mut verifiers: HashMap<(String, String, u16, String), Arc<dyn TrustBundleVerifier>> =
            HashMap::new();
        for provider in [
            TRUST_PROVIDER_ANDROID_KEYMINT,
            TRUST_PROVIDER_AWS_NITRO,
            TRUST_PROVIDER_INTEL_DCAP,
            TRUST_PROVIDER_AMD_SEV_SNP,
            TRUST_PROVIDER_TPM,
            TRUST_PROVIDER_FIDO,
        ] {
            if let Some(verifier_id) = production_verifier_id(provider) {
                verifiers.insert(
                    (
                        provider.to_string(),
                        verifier_id.to_string(),
                        TRUST_AUTHENTICATION_PROFILE_VERSION,
                        TRUST_AUTHENTICATION_PROFILE_ED25519.to_string(),
                    ),
                    Arc::new(UnavailableTrustBundleVerifier {
                        provider,
                        verifier_id,
                        verifier_version: TRUST_AUTHENTICATION_PROFILE_VERSION,
                        authentication_profile: TRUST_AUTHENTICATION_PROFILE_ED25519,
                    }),
                );
            }
        }
        Self { verifiers }
    }

    pub fn route_count(&self) -> usize {
        self.verifiers.len()
    }

    fn verifier(
        &self,
        provider: &str,
        verifier_id: &str,
        verifier_version: u16,
        authentication_profile: &str,
    ) -> Option<&Arc<dyn TrustBundleVerifier>> {
        self.verifiers.get(&(
            provider.to_string(),
            verifier_id.to_string(),
            verifier_version,
            authentication_profile.to_string(),
        ))
    }

    #[cfg(test)]
    fn test_fixture() -> Self {
        let mut verifiers: HashMap<(String, String, u16, String), Arc<dyn TrustBundleVerifier>> =
            HashMap::new();
        for provider in [
            TRUST_PROVIDER_ANDROID_KEYMINT,
            TRUST_PROVIDER_AWS_NITRO,
            TRUST_PROVIDER_INTEL_DCAP,
            TRUST_PROVIDER_AMD_SEV_SNP,
            TRUST_PROVIDER_TPM,
            TRUST_PROVIDER_FIDO,
        ] {
            verifiers.insert(
                (
                    provider.to_string(),
                    TEST_FIXTURE_VERIFIER_ID.to_string(),
                    TRUST_AUTHENTICATION_PROFILE_VERSION,
                    TRUST_AUTHENTICATION_PROFILE_ED25519.to_string(),
                ),
                Arc::new(FixtureTrustBundleVerifier { provider }),
            );
        }
        Self { verifiers }
    }
}

impl Default for TrustBundleVerifierRegistry {
    fn default() -> Self {
        Self::production()
    }
}

/// Result of authenticating and policy-validating one bundle/evidence pair.
/// Only digests, policy identifiers, and validity metadata cross this boundary.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TrustValidationReceipt {
    provider: String,
    sequence: u64,
    bundle_digest: [u8; 32],
    evidence_digest: [u8; 32],
    valid_until: u64,
}

impl TrustValidationReceipt {
    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn bundle_digest(&self) -> &[u8; 32] {
        &self.bundle_digest
    }

    pub fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence_digest
    }

    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
}

/// Stateless validator boundary. Sequence and refresh state belong to the
/// explicit cache below so rotation/rollback behavior is reviewable.
pub struct TrustBundleValidator {
    registry: Arc<TrustBundleVerifierRegistry>,
    allow_test_fixture: bool,
    evidence_freshness: TrustEvidenceFreshnessPolicy,
}

impl fmt::Debug for TrustBundleValidator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustBundleValidator")
            .field("route_count", &self.registry.route_count())
            .field("allow_test_fixture", &self.allow_test_fixture)
            .finish()
    }
}

impl TrustBundleValidator {
    pub fn production() -> Self {
        Self {
            registry: Arc::new(TrustBundleVerifierRegistry::production()),
            allow_test_fixture: false,
            evidence_freshness: TrustEvidenceFreshnessPolicy::defaults(),
        }
    }

    #[cfg(test)]
    fn test_fixture() -> Self {
        Self {
            registry: Arc::new(TrustBundleVerifierRegistry::test_fixture()),
            allow_test_fixture: true,
            evidence_freshness: TrustEvidenceFreshnessPolicy::defaults(),
        }
    }

    pub fn with_evidence_freshness_policy(
        mut self,
        evidence_freshness: TrustEvidenceFreshnessPolicy,
    ) -> Self {
        self.evidence_freshness = evidence_freshness;
        self
    }

    pub fn validate(
        &self,
        bundle: &TrustBundleEnvelope,
        evidence: &TrustEvidence,
        clock: TrustClockObservation,
    ) -> Result<TrustValidationReceipt, TrustValidationError> {
        bundle.validate_shape()?;
        evidence.validate_shape()?;

        let snapshot = bundle.snapshot();
        if !known_provider(&snapshot.provider) {
            return Err(TrustValidationError::UnknownProvider);
        }
        if (bundle.source() == TrustBundleSource::TestFixture || snapshot.fixture)
            && !self.allow_test_fixture
        {
            return Err(TrustValidationError::TestFixturePromotion);
        }

        let now_secs = match clock {
            TrustClockObservation::Trusted(now_secs) => now_secs,
            TrustClockObservation::Untrusted(_) => {
                return Err(TrustValidationError::ClockUntrusted)
            }
            TrustClockObservation::Unavailable => {
                return Err(TrustValidationError::ClockUnavailable)
            }
            TrustClockObservation::Rollback => return Err(TrustValidationError::ClockRollback),
        };

        let verifier = self
            .registry
            .verifier(
                &snapshot.provider,
                bundle.verifier_id(),
                bundle.verifier_version(),
                bundle.authentication_profile(),
            )
            .ok_or(TrustValidationError::UnknownAuthentication)?;
        if verifier.provider() != snapshot.provider
            || verifier.verifier_id() != bundle.verifier_id()
            || verifier.verifier_version() != bundle.verifier_version()
            || verifier.authentication_profile() != bundle.authentication_profile()
        {
            return Err(TrustValidationError::UnknownAuthentication);
        }
        if verifier.status() == TrustBundleVerifierStatus::Unavailable {
            return Err(TrustValidationError::AuthenticationUnavailable);
        }
        #[cfg(test)]
        if verifier.status() == TrustBundleVerifierStatus::TestOnly && !self.allow_test_fixture {
            return Err(TrustValidationError::TestFixturePromotion);
        }
        verifier.verify(bundle.signed_digest(), bundle.signature_bytes())?;

        if now_secs < snapshot.not_before {
            return Err(TrustValidationError::NotYetValid);
        }
        if now_secs >= snapshot.expires_at {
            return Err(TrustValidationError::Expired);
        }
        if now_secs >= snapshot.stale_after {
            return Err(TrustValidationError::StaleCollateral);
        }
        if evidence.provider != snapshot.provider {
            return Err(TrustValidationError::ProviderMismatch);
        }
        if snapshot
            .revoked_evidence
            .contains(&evidence.evidence_digest)
        {
            return Err(TrustValidationError::RevokedEvidence);
        }
        if !snapshot
            .acceptable_tcb
            .iter()
            .any(|tcb| tcb == &evidence.tcb)
        {
            return Err(TrustValidationError::UnacceptableTcb);
        }
        if !snapshot
            .acceptable_measurements
            .contains(&evidence.measurement)
        {
            return Err(TrustValidationError::UnacceptableMeasurement);
        }

        if evidence.issued_at < snapshot.not_before || evidence.issued_at >= snapshot.expires_at {
            return Err(TrustValidationError::EvidenceOutsideBundleValidity);
        }
        if evidence.issued_at
            > now_secs.saturating_add(self.evidence_freshness.max_future_skew_secs())
        {
            return Err(TrustValidationError::EvidenceNotYetValid);
        }
        if evidence.issued_at <= now_secs {
            let age = now_secs
                .checked_sub(evidence.issued_at)
                .ok_or(TrustValidationError::EvidenceStale)?;
            if age > self.evidence_freshness.max_age_secs() {
                return Err(TrustValidationError::EvidenceStale);
            }
        }

        Ok(TrustValidationReceipt {
            provider: snapshot.provider.clone(),
            sequence: snapshot.sequence,
            bundle_digest: *bundle.signed_digest(),
            evidence_digest: evidence.evidence_digest,
            valid_until: snapshot.stale_after.min(snapshot.expires_at),
        })
    }
}

/// Refresh/cache state for one provider-neutral trust cache. A cache is local
/// coordination only; it is not evidence of durable multi-replica state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustRefreshState {
    Empty,
    Active,
    RefreshUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustRefreshOutcome {
    Installed,
    Recovered,
}

#[derive(Debug)]
struct TrustCacheState {
    current: HashMap<String, TrustValidationReceipt>,
    refresh_state: TrustRefreshState,
    last_observed_secs: Option<u64>,
}

/// Process-local trust snapshot cache used to define rotation and outage
/// semantics. Durable refresh coordination remains an integration gap.
#[derive(Debug)]
pub struct TrustBundleCache {
    validator: TrustBundleValidator,
    state: Mutex<TrustCacheState>,
}

impl TrustBundleCache {
    pub fn new(validator: TrustBundleValidator) -> Self {
        Self {
            validator,
            state: Mutex::new(TrustCacheState {
                current: HashMap::new(),
                refresh_state: TrustRefreshState::Empty,
                last_observed_secs: None,
            }),
        }
    }

    fn observe_trusted_time(
        &self,
        clock: TrustClockObservation,
    ) -> Result<u64, TrustValidationError> {
        let now_secs = match clock {
            TrustClockObservation::Trusted(now_secs) => now_secs,
            TrustClockObservation::Untrusted(_) => {
                return Err(TrustValidationError::ClockUntrusted)
            }
            TrustClockObservation::Unavailable => {
                return Err(TrustValidationError::ClockUnavailable)
            }
            TrustClockObservation::Rollback => return Err(TrustValidationError::ClockRollback),
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| TrustValidationError::BackendUnavailable)?;
        if state
            .last_observed_secs
            .is_some_and(|last_observed_secs| now_secs < last_observed_secs)
        {
            return Err(TrustValidationError::ClockRollback);
        }
        state.last_observed_secs = Some(now_secs);
        Ok(now_secs)
    }

    pub fn install(
        &self,
        bundle: &TrustBundleEnvelope,
        evidence: &TrustEvidence,
        clock: TrustClockObservation,
    ) -> Result<TrustRefreshOutcome, TrustValidationError> {
        let now_secs = self.observe_trusted_time(clock)?;
        let receipt =
            self.validator
                .validate(bundle, evidence, TrustClockObservation::Trusted(now_secs))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| TrustValidationError::BackendUnavailable)?;
        if state
            .current
            .get(receipt.provider())
            .is_some_and(|current| current.sequence() >= receipt.sequence())
        {
            return Err(TrustValidationError::SequenceRollback);
        }

        let was_unavailable = state.refresh_state == TrustRefreshState::RefreshUnavailable;
        state
            .current
            .insert(receipt.provider().to_string(), receipt);
        state.refresh_state = TrustRefreshState::Active;
        Ok(if was_unavailable {
            TrustRefreshOutcome::Recovered
        } else {
            TrustRefreshOutcome::Installed
        })
    }

    pub fn mark_refresh_unavailable(&self) -> TrustRefreshState {
        match self.state.lock() {
            Ok(mut state) => {
                state.refresh_state = TrustRefreshState::RefreshUnavailable;
                state.refresh_state
            }
            Err(_) => TrustRefreshState::RefreshUnavailable,
        }
    }

    pub fn refresh_state(&self) -> TrustRefreshState {
        self.state
            .lock()
            .map(|state| state.refresh_state)
            .unwrap_or(TrustRefreshState::RefreshUnavailable)
    }

    /// Returns only a currently valid receipt after observing a trusted clock.
    /// Expired receipts and refresh-outage cache entries at the expiry boundary
    /// are rejected rather than returned for downstream validation.
    pub fn current_for(
        &self,
        provider: &str,
        clock: TrustClockObservation,
    ) -> Result<Option<TrustValidationReceipt>, TrustValidationError> {
        let now_secs = self.observe_trusted_time(clock)?;
        let state = self
            .state
            .lock()
            .map_err(|_| TrustValidationError::BackendUnavailable)?;
        match state.current.get(provider).cloned() {
            Some(receipt) if now_secs < receipt.valid_until() => Ok(Some(receipt)),
            Some(_) => Err(TrustValidationError::Expired),
            None => Ok(None),
        }
    }

    /// Applies an explicit refresh result. Backend errors transition the cache
    /// to an outage state and never preserve an unverified replacement.
    pub fn apply_refresh(
        &self,
        result: Result<(TrustBundleEnvelope, TrustEvidence), TrustValidationError>,
        clock: TrustClockObservation,
    ) -> Result<TrustRefreshOutcome, TrustValidationError> {
        let now_secs = self.observe_trusted_time(clock)?;
        match result {
            Ok((bundle, evidence)) => {
                self.install(&bundle, &evidence, TrustClockObservation::Trusted(now_secs))
            }
            Err(TrustValidationError::BackendUnavailable) => {
                self.mark_refresh_unavailable();
                Err(TrustValidationError::BackendUnavailable)
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: u64 = 150;

    fn snapshot(sequence: u64, fixture: bool) -> TrustBundleSnapshot {
        TrustBundleSnapshot::new(
            TRUST_PROVIDER_ANDROID_KEYMINT,
            sequence,
            90,
            100,
            400,
            300,
            [8; 32],
            vec!["TCB-1".to_string(), "TCB-2".to_string()],
            vec![[7; 32], [6; 32]],
            vec![[9; 32]],
            fixture,
        )
        .expect("snapshot should be valid")
    }

    fn signed_fixture(sequence: u64) -> TrustBundleEnvelope {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let snapshot = snapshot(sequence, true);
        let mut bundle = TrustBundleEnvelope::test_fixture(snapshot, vec![0; 64])
            .expect("fixture bundle should be valid");
        let digest = *bundle.signed_digest();
        bundle.signature = signing_key.sign(&digest).to_bytes().to_vec();
        bundle
            .validate_shape()
            .expect("signed fixture should remain well formed");
        bundle
    }

    fn resign_fixture(bundle: &mut TrustBundleEnvelope) {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        bundle.signed_digest = bundle
            .authenticated_digest()
            .expect("fixture digest should be valid");
        bundle.signature = signing_key.sign(bundle.signed_digest()).to_bytes().to_vec();
    }

    fn evidence() -> TrustEvidence {
        evidence_at(120)
    }

    fn evidence_at(issued_at: u64) -> TrustEvidence {
        TrustEvidence::new(
            TRUST_PROVIDER_ANDROID_KEYMINT,
            [1; 32],
            "TCB-1",
            [7; 32],
            issued_at,
        )
        .expect("evidence should be valid")
    }

    #[test]
    fn canonical_digest_is_stable_across_set_order() {
        let left = snapshot(1, false);
        let mut right = left.clone();
        right.acceptable_tcb.reverse();
        right.acceptable_measurements.reverse();
        assert_eq!(
            left.canonical_digest().expect("left digest"),
            right.canonical_digest().expect("right digest")
        );
    }

    #[test]
    fn production_registry_is_explicitly_unavailable() {
        let registry = TrustBundleVerifierRegistry::production();
        assert_eq!(registry.route_count(), 6);
        let bundle = TrustBundleEnvelope::new(
            snapshot(1, false),
            TRUST_VERIFIER_ANDROID_KEYMINT,
            vec![1; 64],
        )
        .expect("bundle shape");
        assert_eq!(
            TrustBundleValidator::production().validate(
                &bundle,
                &evidence(),
                TrustClockObservation::Trusted(NOW),
            ),
            Err(TrustValidationError::AuthenticationUnavailable)
        );
    }

    #[test]
    fn fixture_cannot_promote_to_production() {
        assert_eq!(
            TrustBundleValidator::production().validate(
                &signed_fixture(1),
                &evidence(),
                TrustClockObservation::Trusted(NOW),
            ),
            Err(TrustValidationError::TestFixturePromotion)
        );
        assert!(TrustBundleValidator::test_fixture()
            .validate(
                &signed_fixture(1),
                &evidence(),
                TrustClockObservation::Trusted(NOW),
            )
            .is_ok());
    }

    #[test]
    fn authenticated_digest_binds_route_source_and_receipt_identity() {
        let validator = TrustBundleValidator::test_fixture();
        let bundle = signed_fixture(1);
        let receipt = validator
            .validate(&bundle, &evidence(), TrustClockObservation::Trusted(NOW))
            .expect("fixture bundle should validate");
        assert_eq!(receipt.bundle_digest(), bundle.signed_digest());
        assert_eq!(
            bundle.authenticated_digest().expect("auth digest"),
            *bundle.signed_digest()
        );
        assert_ne!(
            bundle.canonical_digest().expect("snapshot digest"),
            *bundle.signed_digest()
        );

        let mut verifier_id = bundle.clone();
        verifier_id.verifier_id = "mutated-verifier".to_string();
        assert_eq!(
            validator.validate(
                &verifier_id,
                &evidence(),
                TrustClockObservation::Trusted(NOW)
            ),
            Err(TrustValidationError::Malformed)
        );

        let mut version = bundle.clone();
        version.verifier_version += 1;
        assert_eq!(
            validator.validate(&version, &evidence(), TrustClockObservation::Trusted(NOW)),
            Err(TrustValidationError::Malformed)
        );

        let mut profile = bundle.clone();
        profile.authentication_profile = "mutated-profile".to_string();
        assert_eq!(
            validator.validate(&profile, &evidence(), TrustClockObservation::Trusted(NOW)),
            Err(TrustValidationError::Malformed)
        );

        let mut source = bundle.clone();
        source.source = TrustBundleSource::Provider;
        assert_eq!(
            validator.validate(&source, &evidence(), TrustClockObservation::Trusted(NOW)),
            Err(TrustValidationError::Malformed)
        );

        let mut provider = bundle;
        provider.snapshot.provider = TRUST_PROVIDER_AWS_NITRO.to_string();
        assert_eq!(
            validator.validate(&provider, &evidence(), TrustClockObservation::Trusted(NOW)),
            Err(TrustValidationError::Malformed)
        );
    }

    #[test]
    fn evidence_freshness_enforces_bundle_interval_skew_and_age_boundaries() {
        let validator = TrustBundleValidator::test_fixture().with_evidence_freshness_policy(
            TrustEvidenceFreshnessPolicy::new(10, 5).expect("freshness policy"),
        );
        let bundle = signed_fixture(1);

        assert!(validator
            .validate(
                &bundle,
                &evidence_at(NOW - 10),
                TrustClockObservation::Trusted(NOW),
            )
            .is_ok());
        assert_eq!(
            validator.validate(
                &bundle,
                &evidence_at(NOW - 11),
                TrustClockObservation::Trusted(NOW),
            ),
            Err(TrustValidationError::EvidenceStale)
        );
        assert!(validator
            .validate(
                &bundle,
                &evidence_at(NOW + 5),
                TrustClockObservation::Trusted(NOW),
            )
            .is_ok());
        assert_eq!(
            validator.validate(
                &bundle,
                &evidence_at(NOW + 6),
                TrustClockObservation::Trusted(NOW),
            ),
            Err(TrustValidationError::EvidenceNotYetValid)
        );
        assert_eq!(
            validator.validate(
                &bundle,
                &evidence_at(99),
                TrustClockObservation::Trusted(NOW),
            ),
            Err(TrustValidationError::EvidenceOutsideBundleValidity)
        );
        assert_eq!(
            validator.validate(
                &bundle,
                &evidence_at(400),
                TrustClockObservation::Trusted(NOW),
            ),
            Err(TrustValidationError::EvidenceOutsideBundleValidity)
        );
    }

    #[test]
    fn validator_exposes_each_fail_closed_state() {
        let validator = TrustBundleValidator::test_fixture();
        let base = signed_fixture(1);

        let mut unknown_schema = base.clone();
        unknown_schema.snapshot.schema_version += 1;
        assert_eq!(
            validator.validate(
                &unknown_schema,
                &evidence(),
                TrustClockObservation::Trusted(NOW)
            ),
            Err(TrustValidationError::UnknownSchema)
        );

        let mut unknown_provider = base.clone();
        unknown_provider.snapshot.provider = "unknown.provider".to_string();
        resign_fixture(&mut unknown_provider);
        assert_eq!(
            validator.validate(
                &unknown_provider,
                &evidence(),
                TrustClockObservation::Trusted(NOW)
            ),
            Err(TrustValidationError::UnknownProvider)
        );

        let mut unknown_authentication = base.clone();
        unknown_authentication.verifier_id = "unknown.verifier".to_string();
        resign_fixture(&mut unknown_authentication);
        assert_eq!(
            validator.validate(
                &unknown_authentication,
                &evidence(),
                TrustClockObservation::Trusted(NOW),
            ),
            Err(TrustValidationError::UnknownAuthentication)
        );

        let mut not_yet_valid = signed_fixture(1);
        not_yet_valid.snapshot.not_before = NOW + 1;
        resign_fixture(&mut not_yet_valid);
        assert_eq!(
            validator.validate(
                &not_yet_valid,
                &evidence(),
                TrustClockObservation::Trusted(NOW),
            ),
            Err(TrustValidationError::NotYetValid)
        );

        let mut expired = signed_fixture(1);
        expired.snapshot.expires_at = NOW;
        expired.snapshot.stale_after = NOW;
        resign_fixture(&mut expired);
        assert_eq!(
            validator.validate(&expired, &evidence(), TrustClockObservation::Trusted(NOW)),
            Err(TrustValidationError::Expired)
        );

        let mut stale = signed_fixture(1);
        stale.snapshot.stale_after = NOW;
        resign_fixture(&mut stale);
        assert_eq!(
            validator.validate(&stale, &evidence(), TrustClockObservation::Trusted(NOW)),
            Err(TrustValidationError::StaleCollateral)
        );

        let mut unauthenticated = signed_fixture(1);
        unauthenticated.signature[0] ^= 1;
        assert_eq!(
            validator.validate(
                &unauthenticated,
                &evidence(),
                TrustClockObservation::Trusted(NOW),
            ),
            Err(TrustValidationError::Unauthenticated)
        );

        let mut revoked = evidence();
        revoked.evidence_digest = [9; 32];
        assert_eq!(
            validator.validate(&base, &revoked, TrustClockObservation::Trusted(NOW)),
            Err(TrustValidationError::RevokedEvidence)
        );

        let mut unacceptable_tcb = evidence();
        unacceptable_tcb.tcb = "TCB-unknown".to_string();
        assert_eq!(
            validator.validate(
                &base,
                &unacceptable_tcb,
                TrustClockObservation::Trusted(NOW),
            ),
            Err(TrustValidationError::UnacceptableTcb)
        );

        let mut unacceptable_measurement = evidence();
        unacceptable_measurement.measurement = [5; 32];
        assert_eq!(
            validator.validate(
                &base,
                &unacceptable_measurement,
                TrustClockObservation::Trusted(NOW),
            ),
            Err(TrustValidationError::UnacceptableMeasurement)
        );

        let mut mismatched_provider = evidence();
        mismatched_provider.provider = TRUST_PROVIDER_AWS_NITRO.to_string();
        assert_eq!(
            validator.validate(
                &base,
                &mismatched_provider,
                TrustClockObservation::Trusted(NOW),
            ),
            Err(TrustValidationError::ProviderMismatch)
        );

        assert_eq!(
            validator.validate(&base, &evidence(), TrustClockObservation::Untrusted(NOW)),
            Err(TrustValidationError::ClockUntrusted)
        );
        assert_eq!(
            validator.validate(&base, &evidence(), TrustClockObservation::Unavailable),
            Err(TrustValidationError::ClockUnavailable)
        );
        assert_eq!(
            validator.validate(&base, &evidence(), TrustClockObservation::Rollback),
            Err(TrustValidationError::ClockRollback)
        );
    }

    #[test]
    fn digest_and_signature_are_both_required() {
        let mut malformed = signed_fixture(1);
        malformed.signed_digest[0] ^= 1;
        assert_eq!(
            TrustBundleValidator::test_fixture().validate(
                &malformed,
                &evidence(),
                TrustClockObservation::Trusted(NOW),
            ),
            Err(TrustValidationError::Malformed)
        );

        let empty_signature = TrustBundleEnvelope::new_with_source(
            snapshot(1, true),
            TEST_FIXTURE_VERIFIER_ID,
            Vec::new(),
            TrustBundleSource::TestFixture,
        );
        assert_eq!(empty_signature, Err(TrustValidationError::Malformed));
    }

    #[test]
    fn cache_rotates_and_rejects_sequence_rollback() {
        let cache = TrustBundleCache::new(TrustBundleValidator::test_fixture());
        assert_eq!(
            cache.install(
                &signed_fixture(1),
                &evidence(),
                TrustClockObservation::Trusted(NOW),
            ),
            Ok(TrustRefreshOutcome::Installed)
        );
        assert_eq!(cache.refresh_state(), TrustRefreshState::Active);
        assert_eq!(
            cache.install(
                &signed_fixture(1),
                &evidence(),
                TrustClockObservation::Trusted(NOW),
            ),
            Err(TrustValidationError::SequenceRollback)
        );
        assert_eq!(
            cache.install(
                &signed_fixture(2),
                &evidence(),
                TrustClockObservation::Trusted(NOW),
            ),
            Ok(TrustRefreshOutcome::Installed)
        );
        assert_eq!(
            cache
                .current_for(
                    TRUST_PROVIDER_ANDROID_KEYMINT,
                    TrustClockObservation::Trusted(NOW),
                )
                .map(|receipt| receipt.map(|r| r.sequence())),
            Ok(Some(2))
        );
    }

    #[test]
    fn cache_requires_trusted_monotonic_time_and_rejects_expiry_equality() {
        let cache = TrustBundleCache::new(TrustBundleValidator::test_fixture());
        cache
            .install(
                &signed_fixture(1),
                &evidence(),
                TrustClockObservation::Trusted(NOW),
            )
            .expect("install fixture");
        let valid_until = 300;

        assert!(cache
            .current_for(
                TRUST_PROVIDER_ANDROID_KEYMINT,
                TrustClockObservation::Trusted(valid_until - 1),
            )
            .expect("current receipt")
            .is_some());
        assert_eq!(
            cache.current_for(
                TRUST_PROVIDER_ANDROID_KEYMINT,
                TrustClockObservation::Trusted(valid_until),
            ),
            Err(TrustValidationError::Expired)
        );
        assert_eq!(
            cache.current_for(
                TRUST_PROVIDER_ANDROID_KEYMINT,
                TrustClockObservation::Trusted(valid_until + 1),
            ),
            Err(TrustValidationError::Expired)
        );
        assert_eq!(
            cache.current_for(
                TRUST_PROVIDER_ANDROID_KEYMINT,
                TrustClockObservation::Trusted(valid_until - 2),
            ),
            Err(TrustValidationError::ClockRollback)
        );
        assert_eq!(
            cache.install(
                &signed_fixture(2),
                &evidence(),
                TrustClockObservation::Trusted(valid_until - 3),
            ),
            Err(TrustValidationError::ClockRollback)
        );
        assert_eq!(
            cache.current_for(
                TRUST_PROVIDER_ANDROID_KEYMINT,
                TrustClockObservation::Untrusted(valid_until + 2),
            ),
            Err(TrustValidationError::ClockUntrusted)
        );
        assert_eq!(
            cache.current_for(
                TRUST_PROVIDER_ANDROID_KEYMINT,
                TrustClockObservation::Unavailable,
            ),
            Err(TrustValidationError::ClockUnavailable)
        );
    }

    #[test]
    fn refresh_unavailable_never_returns_expired_cached_trust() {
        let cache = TrustBundleCache::new(TrustBundleValidator::test_fixture());
        cache
            .install(
                &signed_fixture(1),
                &evidence(),
                TrustClockObservation::Trusted(NOW),
            )
            .expect("install fixture");
        assert_eq!(
            cache.mark_refresh_unavailable(),
            TrustRefreshState::RefreshUnavailable
        );
        assert!(cache
            .current_for(
                TRUST_PROVIDER_ANDROID_KEYMINT,
                TrustClockObservation::Trusted(NOW + 1),
            )
            .expect("valid cached receipt")
            .is_some());
        assert_eq!(
            cache.current_for(
                TRUST_PROVIDER_ANDROID_KEYMINT,
                TrustClockObservation::Trusted(300),
            ),
            Err(TrustValidationError::Expired)
        );
        assert_eq!(cache.refresh_state(), TrustRefreshState::RefreshUnavailable);
    }

    #[test]
    fn refresh_outage_and_recovery_are_explicit() {
        let cache = TrustBundleCache::new(TrustBundleValidator::test_fixture());
        assert_eq!(
            cache.mark_refresh_unavailable(),
            TrustRefreshState::RefreshUnavailable
        );
        assert_eq!(
            cache.apply_refresh(
                Err(TrustValidationError::BackendUnavailable),
                TrustClockObservation::Trusted(NOW),
            ),
            Err(TrustValidationError::BackendUnavailable)
        );
        assert_eq!(cache.refresh_state(), TrustRefreshState::RefreshUnavailable);
        assert_eq!(
            cache.apply_refresh(
                Ok((signed_fixture(1), evidence())),
                TrustClockObservation::Trusted(NOW),
            ),
            Ok(TrustRefreshOutcome::Recovered)
        );
        assert_eq!(cache.refresh_state(), TrustRefreshState::Active);
    }

    #[test]
    fn malformed_and_oversized_content_is_rejected() {
        assert!(TrustBundleSnapshot::new(
            TRUST_PROVIDER_ANDROID_KEYMINT,
            1,
            90,
            100,
            100,
            100,
            [8; 32],
            vec!["TCB-1".to_string()],
            vec![[7; 32]],
            Vec::new(),
            true,
        )
        .is_err());
        assert!(TrustBundleSnapshot::new(
            TRUST_PROVIDER_ANDROID_KEYMINT,
            1,
            90,
            100,
            200,
            100,
            [8; 32],
            vec!["TCB-1".to_string()],
            vec![[7; 32]],
            Vec::new(),
            true,
        )
        .is_err());
        let mut oversized = snapshot(1, true);
        oversized.acceptable_tcb = (0..=MAX_TCB_ENTRIES)
            .map(|index| format!("TCB-{index}"))
            .collect();
        assert_eq!(
            oversized.validate_shape(),
            Err(TrustValidationError::Oversized)
        );

        let malformed_json = vec![b'{'; MAX_TRUST_BUNDLE_TRANSPORT_BYTES + 1];
        assert_eq!(
            deserialize_trust_bundle_json(&malformed_json),
            Err(TrustValidationError::Oversized)
        );
    }

    #[test]
    fn debug_does_not_expose_signature_bytes() {
        let bundle = signed_fixture(1);
        let debug = format!("{bundle:?}");
        assert!(!debug.contains("66".repeat(64).as_str()));
        assert!(debug.contains("signature_len"));
    }
}
