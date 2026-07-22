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
/// Maximum serialized trust-bundle transport accepted by the bounded entry
/// point.
pub const MAX_TRUST_BUNDLE_TRANSPORT_BYTES: usize = 256 * 1024;

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

/// The source class is signed as part of the snapshot and is never enough by
/// itself to authenticate a bundle. A test source is accepted only by the
/// crate-internal fixture validator.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustBundleSource {
    Provider,
    TestFixture,
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
            || self.not_before > self.stale_after
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

/// Authenticated envelope around a canonical snapshot. The signed digest is
/// checked against the canonical snapshot bytes before the verifier sees the
/// signature. A URI or digest without this signature path is never accepted.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustBundleEnvelope {
    pub snapshot: TrustBundleSnapshot,
    pub signed_digest: [u8; 32],
    pub verifier_id: String,
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
        Self::new_with_source(
            snapshot,
            verifier_id,
            signature,
            TrustBundleSource::Provider,
        )
    }

    fn new_with_source(
        snapshot: TrustBundleSnapshot,
        verifier_id: impl Into<String>,
        signature: Vec<u8>,
        source: TrustBundleSource,
    ) -> Result<Self, TrustValidationError> {
        let signed_digest = snapshot.canonical_digest()?;
        let envelope = Self {
            snapshot,
            signed_digest,
            verifier_id: verifier_id.into(),
            signature,
            source,
        };
        envelope.validate_shape()?;
        Ok(envelope)
    }

    pub fn validate_shape(&self) -> Result<(), TrustValidationError> {
        self.snapshot.validate_shape()?;
        validate_identifier(&self.verifier_id)?;
        if self.signature.is_empty() {
            return Err(TrustValidationError::Malformed);
        }
        if self.signature.len() > MAX_SIGNATURE_BYTES {
            return Err(TrustValidationError::Oversized);
        }
        if self.signed_digest != self.snapshot.canonical_digest()? {
            return Err(TrustValidationError::Malformed);
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> Result<[u8; 32], TrustValidationError> {
        self.snapshot.canonical_digest()
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
        Self::new_with_source(
            snapshot,
            TEST_FIXTURE_VERIFIER_ID,
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

/// Authenticated verifier boundary for a canonical bundle digest.
pub trait TrustBundleVerifier: Send + Sync {
    fn provider(&self) -> &str;
    fn verifier_id(&self) -> &str;
    fn status(&self) -> TrustBundleVerifierStatus;
    fn verify(
        &self,
        canonical_digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), TrustValidationError>;
}

struct UnavailableTrustBundleVerifier {
    provider: &'static str,
    verifier_id: &'static str,
}

impl TrustBundleVerifier for UnavailableTrustBundleVerifier {
    fn provider(&self) -> &str {
        self.provider
    }

    fn verifier_id(&self) -> &str {
        self.verifier_id
    }

    fn status(&self) -> TrustBundleVerifierStatus {
        TrustBundleVerifierStatus::Unavailable
    }

    fn verify(
        &self,
        _canonical_digest: &[u8; 32],
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

    fn status(&self) -> TrustBundleVerifierStatus {
        TrustBundleVerifierStatus::TestOnly
    }

    fn verify(
        &self,
        canonical_digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), TrustValidationError> {
        let verifying_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]).verifying_key();
        let signature = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| TrustValidationError::Unauthenticated)?;
        ed25519_dalek::Verifier::verify(&verifying_key, canonical_digest, &signature)
            .map_err(|_| TrustValidationError::Unauthenticated)
    }
}

/// Exact `(provider, verifier_id)` trust routes. No provider roots or URI
/// fetches are installed by this registry.
pub struct TrustBundleVerifierRegistry {
    verifiers: HashMap<(String, String), Arc<dyn TrustBundleVerifier>>,
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
        let mut verifiers: HashMap<(String, String), Arc<dyn TrustBundleVerifier>> = HashMap::new();
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
                    (provider.to_string(), verifier_id.to_string()),
                    Arc::new(UnavailableTrustBundleVerifier {
                        provider,
                        verifier_id,
                    }),
                );
            }
        }
        Self { verifiers }
    }

    pub fn route_count(&self) -> usize {
        self.verifiers.len()
    }

    fn verifier(&self, provider: &str, verifier_id: &str) -> Option<&Arc<dyn TrustBundleVerifier>> {
        self.verifiers
            .get(&(provider.to_string(), verifier_id.to_string()))
    }

    #[cfg(test)]
    fn test_fixture() -> Self {
        let mut verifiers: HashMap<(String, String), Arc<dyn TrustBundleVerifier>> = HashMap::new();
        for provider in [
            TRUST_PROVIDER_ANDROID_KEYMINT,
            TRUST_PROVIDER_AWS_NITRO,
            TRUST_PROVIDER_INTEL_DCAP,
            TRUST_PROVIDER_AMD_SEV_SNP,
            TRUST_PROVIDER_TPM,
            TRUST_PROVIDER_FIDO,
        ] {
            verifiers.insert(
                (provider.to_string(), TEST_FIXTURE_VERIFIER_ID.to_string()),
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
        }
    }

    #[cfg(test)]
    fn test_fixture() -> Self {
        Self {
            registry: Arc::new(TrustBundleVerifierRegistry::test_fixture()),
            allow_test_fixture: true,
        }
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
            .verifier(&snapshot.provider, bundle.verifier_id())
            .ok_or(TrustValidationError::UnknownAuthentication)?;
        if verifier.provider() != snapshot.provider
            || verifier.verifier_id() != bundle.verifier_id()
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
            }),
        }
    }

    pub fn install(
        &self,
        bundle: &TrustBundleEnvelope,
        evidence: &TrustEvidence,
        clock: TrustClockObservation,
    ) -> Result<TrustRefreshOutcome, TrustValidationError> {
        let receipt = self.validator.validate(bundle, evidence, clock)?;
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

    pub fn current_for(&self, provider: &str) -> Option<TrustValidationReceipt> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.current.get(provider).cloned())
    }

    /// Applies an explicit refresh result. Backend errors transition the cache
    /// to an outage state and never preserve an unverified replacement.
    pub fn apply_refresh(
        &self,
        result: Result<(TrustBundleEnvelope, TrustEvidence), TrustValidationError>,
        clock: TrustClockObservation,
    ) -> Result<TrustRefreshOutcome, TrustValidationError> {
        match result {
            Ok((bundle, evidence)) => self.install(&bundle, &evidence, clock),
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
        let digest = snapshot.canonical_digest().expect("digest should be valid");
        TrustBundleEnvelope::test_fixture(snapshot, signing_key.sign(&digest).to_bytes().to_vec())
            .expect("fixture bundle should be valid")
    }

    fn evidence() -> TrustEvidence {
        TrustEvidence::new(
            TRUST_PROVIDER_ANDROID_KEYMINT,
            [1; 32],
            "TCB-1",
            [7; 32],
            120,
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
        unknown_provider.signed_digest = unknown_provider
            .snapshot
            .canonical_digest()
            .expect("unknown provider digest");
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
        not_yet_valid.signed_digest = not_yet_valid
            .snapshot
            .canonical_digest()
            .expect("future digest");
        let digest = *not_yet_valid.signed_digest();
        not_yet_valid.signature = SigningKey::from_bytes(&[0x42; 32])
            .sign(&digest)
            .to_bytes()
            .to_vec();
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
        expired.signed_digest = expired.snapshot.canonical_digest().expect("expired digest");
        let digest = *expired.signed_digest();
        expired.signature = SigningKey::from_bytes(&[0x42; 32])
            .sign(&digest)
            .to_bytes()
            .to_vec();
        assert_eq!(
            validator.validate(&expired, &evidence(), TrustClockObservation::Trusted(NOW)),
            Err(TrustValidationError::Expired)
        );

        let mut stale = signed_fixture(1);
        stale.snapshot.stale_after = NOW;
        stale.signed_digest = stale.snapshot.canonical_digest().expect("stale digest");
        let digest = *stale.signed_digest();
        stale.signature = SigningKey::from_bytes(&[0x42; 32])
            .sign(&digest)
            .to_bytes()
            .to_vec();
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
                .current_for(TRUST_PROVIDER_ANDROID_KEYMINT)
                .map(|r| r.sequence()),
            Some(2)
        );
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
