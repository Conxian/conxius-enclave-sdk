//! Provider-neutral trust-input, replay, and release-evidence contracts.
//!
//! This module intentionally stops at typed, authenticated-input boundaries.
//! It does not install provider roots, choose an authority, provide a durable
//! backend, or promote any capability to production support. The existing
//! [`super::replay_guard::ReplayGuard`] remains a process-local compatibility
//! guard; [`NonProductionInMemoryReplayStore`] is a test/development adapter
//! and is not wired into a production path. That adapter retains consumed
//! binding tombstones for the process lifetime, independently of reservation
//! expiry; production retention and storage remain architecture decisions.

use super::attestation::AttestationLevel;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Mutex;

/// Fixed digest width used by every contract in this module.
pub const TRUST_DIGEST_BYTES: usize = 32;
/// Provider-neutral collateral metadata schema version.
pub const COLLATERAL_SCHEMA_VERSION: u16 = 1;
/// Provider-neutral verifier vocabulary version.
pub const COLLATERAL_VERIFIER_VERSION: u32 = 1;
/// No default future-dated collateral grace is applied.
pub const COLLATERAL_DEFAULT_FUTURE_SKEW_SECS: u64 = 0;
/// An explicitly configured future skew remains bounded and reviewable.
pub const COLLATERAL_MAX_FUTURE_SKEW_SECS: u64 = 300;
/// Domain separator for authenticated collateral metadata bindings.
pub const COLLATERAL_DOMAIN: &str = "CONXIAN-ATTESTATION-COLLATERAL/v1";

/// Versioned domain separator for secret-free replay bindings.
pub const REPLAY_BINDING_VERSION: u16 = 1;
pub const REPLAY_BINDING_DOMAIN: &str = "CONXIAN-REPLAY-BINDING/v1";
/// Maximum raw nonce retained transiently while computing its digest.
pub const MAX_REPLAY_NONCE_BYTES: usize = 4096;
/// Maximum raw evidence input retained transiently while computing its digest.
pub const MAX_REPLAY_EVIDENCE_BYTES: usize = 64 * 1024;
/// Maximum raw key identity input retained transiently while computing its digest.
pub const MAX_REPLAY_KEY_IDENTITY_BYTES: usize = 4096;

/// Contract version for a future durable replay implementation.
pub const DURABLE_REPLAY_CONTRACT_VERSION: u16 = 1;
pub const DURABLE_REPLAY_DOMAIN: &str = "CONXIAN-DURABLE-REPLAY/v1";
pub const MAX_DURABLE_REPLAY_BATCH: usize = 128;

/// Provider-neutral release-evidence manifest schema version.
pub const RELEASE_EVIDENCE_SCHEMA_VERSION: u16 = 1;
pub const RELEASE_EVIDENCE_DOMAIN: &str = "CONXIAN-RELEASE-EVIDENCE/v1";
pub const MAX_EVIDENCE_REFERENCE_BYTES: usize = 1024;

/// Digest-only representation shared by trust and evidence contracts.
pub type TrustDigest = [u8; TRUST_DIGEST_BYTES];

fn is_zero_digest(digest: &TrustDigest) -> bool {
    digest.iter().all(|byte| *byte == 0)
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Option<()> {
    let length = u32::try_from(value.len()).ok()?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Some(())
}

fn digest_labeled_input(label: &str, value: &[u8]) -> Option<TrustDigest> {
    let mut canonical = Vec::new();
    append_len_prefixed(&mut canonical, REPLAY_BINDING_DOMAIN.as_bytes())?;
    canonical.extend_from_slice(&REPLAY_BINDING_VERSION.to_be_bytes());
    append_len_prefixed(&mut canonical, label.as_bytes())?;
    append_len_prefixed(&mut canonical, value)?;
    Some(Sha256::digest(canonical).into())
}

fn digest_bytes(canonical: &[u8]) -> TrustDigest {
    Sha256::digest(canonical).into()
}

/// Typed provider identity used by collateral and replay contracts.
///
/// These variants are vocabulary only. They do not install roots, activate a
/// provider verifier, or establish a production support decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttestationProvider {
    AndroidKeyMintStrongBox,
    AwsNitroEnclave,
    IntelSgxDcap,
    AmdSevSnp,
    ArmPsaCca,
}

impl AttestationProvider {
    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::AndroidKeyMintStrongBox => "android_keymint_strongbox",
            Self::AwsNitroEnclave => "aws_nitro_enclave",
            Self::IntelSgxDcap => "intel_sgx_dcap",
            Self::AmdSevSnp => "amd_sev_snp",
            Self::ArmPsaCca => "arm_psa_cca",
        }
    }

    const fn canonical_tag(self) -> u8 {
        match self {
            Self::AndroidKeyMintStrongBox => 1,
            Self::AwsNitroEnclave => 2,
            Self::IntelSgxDcap => 3,
            Self::AmdSevSnp => 4,
            Self::ArmPsaCca => 5,
        }
    }

    /// Performs only safe one-way interoperability with the existing broad
    /// attestation levels. A generic `CloudTEE` or `TEE` label cannot identify
    /// Nitro, SGX, SEV-SNP, or CCA, so those levels intentionally return `None`.
    pub fn from_attestation_level(level: AttestationLevel) -> Option<Self> {
        match level {
            AttestationLevel::StrongBox => Some(Self::AndroidKeyMintStrongBox),
            AttestationLevel::Software | AttestationLevel::TEE | AttestationLevel::CloudTEE => None,
        }
    }

    /// Returns the broadest existing attestation level that is safe to expose
    /// for this typed provider identity. The reverse conversion is not exact.
    pub const fn attestation_level(self) -> AttestationLevel {
        match self {
            Self::AndroidKeyMintStrongBox => AttestationLevel::StrongBox,
            Self::AwsNitroEnclave => AttestationLevel::CloudTEE,
            Self::IntelSgxDcap | Self::AmdSevSnp | Self::ArmPsaCca => AttestationLevel::TEE,
        }
    }
}

impl FromStr for AttestationProvider {
    type Err = CollateralValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "android_keymint_strongbox" => Ok(Self::AndroidKeyMintStrongBox),
            "aws_nitro_enclave" => Ok(Self::AwsNitroEnclave),
            "intel_sgx_dcap" => Ok(Self::IntelSgxDcap),
            "amd_sev_snp" => Ok(Self::AmdSevSnp),
            "arm_psa_cca" => Ok(Self::ArmPsaCca),
            _ => Err(CollateralValidationError::UnknownProvider),
        }
    }
}

/// Deterministic, secret-free collateral validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum CollateralValidationError {
    #[error("collateral metadata is malformed")]
    Malformed,
    #[error("collateral provider is unknown")]
    UnknownProvider,
    #[error("collateral schema version is unknown")]
    UnknownSchema,
    #[error("collateral verifier version is unknown")]
    UnknownVerifierVersion,
    #[error("collateral provider does not match the validation context")]
    ProviderMismatch,
    #[error("collateral root-set digest does not match the validation context")]
    RootSetMismatch,
    #[error("collateral is not yet valid")]
    NotYetValid,
    #[error("collateral has expired")]
    Expired,
    #[error("collateral revocation epoch moved backwards")]
    RevocationRollback,
    #[error("collateral revocation epoch is stale")]
    StaleRevocation,
    #[error("collateral validation context is invalid or unavailable")]
    ValidationUnavailable,
    #[error("collateral authentication authority or verifier is unavailable")]
    AuthenticationUnavailable,
}

/// Validation inputs supplied by a future provider-neutral trust authority.
///
/// The context contains only a digest for the selected root set. It has no API
/// for importing certificates, roots, URLs, or arbitrary provider strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollateralValidationContext {
    expected_provider: AttestationProvider,
    expected_root_set_digest: TrustDigest,
    expected_schema_version: u16,
    expected_verifier_version: u32,
    now_secs: u64,
    max_future_skew_secs: u64,
    observed_revocation_epoch: u64,
    minimum_revocation_epoch: u64,
}

impl CollateralValidationContext {
    pub fn strict_for(
        expected_provider: AttestationProvider,
        expected_root_set_digest: TrustDigest,
        now_secs: u64,
        observed_revocation_epoch: u64,
        minimum_revocation_epoch: u64,
    ) -> Result<Self, CollateralValidationError> {
        Self::new(
            expected_provider,
            expected_root_set_digest,
            COLLATERAL_SCHEMA_VERSION,
            COLLATERAL_VERIFIER_VERSION,
            now_secs,
            observed_revocation_epoch,
            minimum_revocation_epoch,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        expected_provider: AttestationProvider,
        expected_root_set_digest: TrustDigest,
        expected_schema_version: u16,
        expected_verifier_version: u32,
        now_secs: u64,
        observed_revocation_epoch: u64,
        minimum_revocation_epoch: u64,
    ) -> Result<Self, CollateralValidationError> {
        if is_zero_digest(&expected_root_set_digest)
            || expected_schema_version == 0
            || expected_verifier_version == 0
            || minimum_revocation_epoch < observed_revocation_epoch
        {
            return Err(CollateralValidationError::ValidationUnavailable);
        }

        Ok(Self {
            expected_provider,
            expected_root_set_digest,
            expected_schema_version,
            expected_verifier_version,
            now_secs,
            max_future_skew_secs: COLLATERAL_DEFAULT_FUTURE_SKEW_SECS,
            observed_revocation_epoch,
            minimum_revocation_epoch,
        })
    }

    /// Explicit skew is opt-in and bounded. The default remains zero.
    pub fn with_future_skew_secs(
        mut self,
        max_future_skew_secs: u64,
    ) -> Result<Self, CollateralValidationError> {
        if max_future_skew_secs > COLLATERAL_MAX_FUTURE_SKEW_SECS {
            return Err(CollateralValidationError::ValidationUnavailable);
        }
        self.max_future_skew_secs = max_future_skew_secs;
        Ok(self)
    }

    pub fn expected_provider(&self) -> AttestationProvider {
        self.expected_provider
    }

    pub fn expected_root_set_digest(&self) -> &TrustDigest {
        &self.expected_root_set_digest
    }

    pub fn now_secs(&self) -> u64 {
        self.now_secs
    }

    pub fn observed_revocation_epoch(&self) -> u64 {
        self.observed_revocation_epoch
    }

    pub fn minimum_revocation_epoch(&self) -> u64 {
        self.minimum_revocation_epoch
    }
}

/// Provider-neutral metadata describing one authenticated collateral bundle.
///
/// This type stores identifiers and digests only. It never stores raw roots,
/// certificates, measurements, TCB records, or provider collateral bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralMetadata {
    provider: AttestationProvider,
    bundle_id: String,
    bundle_version: u32,
    root_set_digest: TrustDigest,
    collateral_digest: TrustDigest,
    issued_at: u64,
    expires_at: u64,
    revocation_epoch: u64,
    verifier_version: u32,
    schema_version: u16,
    policy_digest: TrustDigest,
    measurement_digest: TrustDigest,
    tcb_digest: TrustDigest,
}

impl CollateralMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        provider: AttestationProvider,
        bundle_id: impl Into<String>,
        bundle_version: u32,
        root_set_digest: TrustDigest,
        collateral_digest: TrustDigest,
        issued_at: u64,
        expires_at: u64,
        revocation_epoch: u64,
        verifier_version: u32,
        schema_version: u16,
        policy_digest: TrustDigest,
        measurement_digest: TrustDigest,
        tcb_digest: TrustDigest,
    ) -> Result<Self, CollateralValidationError> {
        let metadata = Self {
            provider,
            bundle_id: bundle_id.into(),
            bundle_version,
            root_set_digest,
            collateral_digest,
            issued_at,
            expires_at,
            revocation_epoch,
            verifier_version,
            schema_version,
            policy_digest,
            measurement_digest,
            tcb_digest,
        };
        metadata.validate_shape()?;
        Ok(metadata)
    }

    fn validate_shape(&self) -> Result<(), CollateralValidationError> {
        if !valid_identifier(&self.bundle_id, 128)
            || self.bundle_version == 0
            || is_zero_digest(&self.root_set_digest)
            || is_zero_digest(&self.collateral_digest)
            || is_zero_digest(&self.policy_digest)
            || is_zero_digest(&self.measurement_digest)
            || is_zero_digest(&self.tcb_digest)
            || self.expires_at <= self.issued_at
        {
            return Err(CollateralValidationError::Malformed);
        }
        if self.schema_version != COLLATERAL_SCHEMA_VERSION {
            return Err(CollateralValidationError::UnknownSchema);
        }
        if self.verifier_version != COLLATERAL_VERIFIER_VERSION {
            return Err(CollateralValidationError::UnknownVerifierVersion);
        }
        Ok(())
    }

    /// Validates metadata only. This is deterministic and has no stale grace:
    /// `now_secs >= expires_at` is expired.
    pub fn validate(
        &self,
        context: &CollateralValidationContext,
    ) -> Result<(), CollateralValidationError> {
        self.validate_shape()?;
        if self.provider != context.expected_provider {
            return Err(CollateralValidationError::ProviderMismatch);
        }
        if self.schema_version != context.expected_schema_version {
            return Err(CollateralValidationError::UnknownSchema);
        }
        if self.verifier_version != context.expected_verifier_version {
            return Err(CollateralValidationError::UnknownVerifierVersion);
        }
        if self.root_set_digest != context.expected_root_set_digest {
            return Err(CollateralValidationError::RootSetMismatch);
        }
        if self.issued_at
            > context
                .now_secs
                .saturating_add(context.max_future_skew_secs)
        {
            return Err(CollateralValidationError::NotYetValid);
        }
        if context.now_secs >= self.expires_at {
            return Err(CollateralValidationError::Expired);
        }
        if self.revocation_epoch < context.observed_revocation_epoch {
            return Err(CollateralValidationError::RevocationRollback);
        }
        if self.revocation_epoch < context.minimum_revocation_epoch {
            return Err(CollateralValidationError::StaleRevocation);
        }
        Ok(())
    }

    /// Returns a deterministic digest of all trust-input metadata.
    pub fn canonical_digest(&self) -> Result<TrustDigest, CollateralValidationError> {
        self.validate_shape()?;
        let mut canonical = Vec::new();
        append_len_prefixed(&mut canonical, COLLATERAL_DOMAIN.as_bytes())
            .ok_or(CollateralValidationError::Malformed)?;
        canonical.extend_from_slice(&self.schema_version.to_be_bytes());
        canonical.push(self.provider.canonical_tag());
        append_len_prefixed(&mut canonical, self.bundle_id.as_bytes())
            .ok_or(CollateralValidationError::Malformed)?;
        canonical.extend_from_slice(&self.bundle_version.to_be_bytes());
        canonical.extend_from_slice(&self.root_set_digest);
        canonical.extend_from_slice(&self.collateral_digest);
        canonical.extend_from_slice(&self.issued_at.to_be_bytes());
        canonical.extend_from_slice(&self.expires_at.to_be_bytes());
        canonical.extend_from_slice(&self.revocation_epoch.to_be_bytes());
        canonical.extend_from_slice(&self.verifier_version.to_be_bytes());
        canonical.extend_from_slice(&self.policy_digest);
        canonical.extend_from_slice(&self.measurement_digest);
        canonical.extend_from_slice(&self.tcb_digest);
        Ok(digest_bytes(&canonical))
    }

    pub fn provider(&self) -> AttestationProvider {
        self.provider
    }

    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    pub fn bundle_version(&self) -> u32 {
        self.bundle_version
    }

    pub fn root_set_digest(&self) -> &TrustDigest {
        &self.root_set_digest
    }

    pub fn collateral_digest(&self) -> &TrustDigest {
        &self.collateral_digest
    }

    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }

    pub fn verifier_version(&self) -> u32 {
        self.verifier_version
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn policy_digest(&self) -> &TrustDigest {
        &self.policy_digest
    }

    pub fn measurement_digest(&self) -> &TrustDigest {
        &self.measurement_digest
    }

    pub fn tcb_digest(&self) -> &TrustDigest {
        &self.tcb_digest
    }
}

/// Digest-only wrapper for collateral metadata that is expected to be
/// authenticated by a future provider authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedCollateralMetadata {
    metadata: CollateralMetadata,
    authority_key_id_digest: TrustDigest,
    authentication_digest: TrustDigest,
}

impl AuthenticatedCollateralMetadata {
    pub fn try_new(
        metadata: CollateralMetadata,
        authority_key_id_digest: TrustDigest,
        authentication_digest: TrustDigest,
    ) -> Result<Self, CollateralValidationError> {
        if is_zero_digest(&authority_key_id_digest) || is_zero_digest(&authentication_digest) {
            return Err(CollateralValidationError::Malformed);
        }
        Ok(Self {
            metadata,
            authority_key_id_digest,
            authentication_digest,
        })
    }

    pub fn metadata(&self) -> &CollateralMetadata {
        &self.metadata
    }

    pub fn authority_key_id_digest(&self) -> &TrustDigest {
        &self.authority_key_id_digest
    }

    pub fn authentication_digest(&self) -> &TrustDigest {
        &self.authentication_digest
    }

    pub fn validate_metadata(
        &self,
        context: &CollateralValidationContext,
    ) -> Result<(), CollateralValidationError> {
        self.metadata.validate(context)
    }

    /// Fails closed until a provider-specific authority and authenticator are
    /// selected. The digest fields are bindings, not a simulated signature.
    pub fn validate(
        &self,
        context: &CollateralValidationContext,
    ) -> Result<(), CollateralValidationError> {
        self.metadata.validate(context)?;
        Err(CollateralValidationError::AuthenticationUnavailable)
    }

    pub fn binding_digest(&self) -> Result<TrustDigest, CollateralValidationError> {
        let metadata_digest = self.metadata.canonical_digest()?;
        let mut canonical = Vec::new();
        append_len_prefixed(&mut canonical, COLLATERAL_DOMAIN.as_bytes())
            .ok_or(CollateralValidationError::Malformed)?;
        canonical.extend_from_slice(&metadata_digest);
        canonical.extend_from_slice(&self.authority_key_id_digest);
        canonical.extend_from_slice(&self.authentication_digest);
        Ok(digest_bytes(&canonical))
    }
}

/// Typed proof subject covered by a replay binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReplayProofSubject {
    Device,
    Workload,
    SignerKey,
    UserAuthorization,
    ServerIdentity,
}

impl ReplayProofSubject {
    const fn canonical_tag(self) -> u8 {
        match self {
            Self::Device => 1,
            Self::Workload => 2,
            Self::SignerKey => 3,
            Self::UserAuthorization => 4,
            Self::ServerIdentity => 5,
        }
    }
}

/// Typed proof mechanism covered by a replay binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReplayProofMechanism {
    DeviceIntegrityReport,
    AndroidKeyMintAuthorization,
    AwsNitroAttestationDocument,
    IntelSgxDcapQuote,
    AmdSevSnpReport,
    ArmPsaCcaToken,
    Fido2Assertion,
    TpmQuote,
    ServerSignature,
}

impl ReplayProofMechanism {
    const fn canonical_tag(self) -> u8 {
        match self {
            Self::DeviceIntegrityReport => 1,
            Self::AndroidKeyMintAuthorization => 2,
            Self::AwsNitroAttestationDocument => 3,
            Self::IntelSgxDcapQuote => 4,
            Self::AmdSevSnpReport => 5,
            Self::ArmPsaCcaToken => 6,
            Self::Fido2Assertion => 7,
            Self::TpmQuote => 8,
            Self::ServerSignature => 9,
        }
    }
}

/// Typed operation covered by a replay binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReplayOperation {
    AttestationVerification,
    ProofAuthorization,
    ValueBearingSigning,
    SettlementDispatch,
    KeyReleaseAuthorization,
}

impl ReplayOperation {
    const fn canonical_tag(self) -> u8 {
        match self {
            Self::AttestationVerification => 1,
            Self::ProofAuthorization => 2,
            Self::ValueBearingSigning => 3,
            Self::SettlementDispatch => 4,
            Self::KeyReleaseAuthorization => 5,
        }
    }
}

/// Typed purpose covered by a replay binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReplayPurpose {
    Sign,
    Verify,
    Authorize,
    Settle,
    Release,
}

impl ReplayPurpose {
    const fn canonical_tag(self) -> u8 {
        match self {
            Self::Sign => 1,
            Self::Verify => 2,
            Self::Authorize => 3,
            Self::Settle => 4,
            Self::Release => 5,
        }
    }
}

/// Construction failures for secret-free replay bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum ReplayBindingError {
    #[error("replay binding input is invalid")]
    InvalidInput,
    #[error("replay binding input exceeds its bounded limit")]
    InputTooLarge,
}

/// Canonical replay binding that retains only typed fields and digests.
///
/// The raw nonce, key identity, and evidence are accepted only long enough to
/// calculate labelled SHA-256 digests. They are never stored, serialized, or
/// exposed by this type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReplayBinding {
    version: u16,
    provider: AttestationProvider,
    proof_subject: ReplayProofSubject,
    proof_mechanism: ReplayProofMechanism,
    nonce_digest: TrustDigest,
    operation: ReplayOperation,
    purpose: ReplayPurpose,
    policy_digest: TrustDigest,
    key_identity_digest: TrustDigest,
    evidence_digest: TrustDigest,
}

impl ReplayBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        provider: AttestationProvider,
        proof_subject: ReplayProofSubject,
        proof_mechanism: ReplayProofMechanism,
        nonce: &[u8],
        operation: ReplayOperation,
        purpose: ReplayPurpose,
        policy_digest: TrustDigest,
        key_identity: &[u8],
        evidence: &[u8],
    ) -> Result<Self, ReplayBindingError> {
        if nonce.is_empty()
            || key_identity.is_empty()
            || evidence.is_empty()
            || is_zero_digest(&policy_digest)
        {
            return Err(ReplayBindingError::InvalidInput);
        }
        if nonce.len() > MAX_REPLAY_NONCE_BYTES
            || key_identity.len() > MAX_REPLAY_KEY_IDENTITY_BYTES
            || evidence.len() > MAX_REPLAY_EVIDENCE_BYTES
        {
            return Err(ReplayBindingError::InputTooLarge);
        }

        let nonce_digest =
            digest_labeled_input("nonce", nonce).ok_or(ReplayBindingError::InputTooLarge)?;
        let key_identity_digest = digest_labeled_input("key-identity", key_identity)
            .ok_or(ReplayBindingError::InputTooLarge)?;
        let evidence_digest =
            digest_labeled_input("evidence", evidence).ok_or(ReplayBindingError::InputTooLarge)?;

        Ok(Self {
            version: REPLAY_BINDING_VERSION,
            provider,
            proof_subject,
            proof_mechanism,
            nonce_digest,
            operation,
            purpose,
            policy_digest,
            key_identity_digest,
            evidence_digest,
        })
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut canonical = Vec::with_capacity(2 + 9 + 5 * TRUST_DIGEST_BYTES);
        canonical.extend_from_slice(REPLAY_BINDING_DOMAIN.as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(&self.version.to_be_bytes());
        canonical.push(self.provider.canonical_tag());
        canonical.push(self.proof_subject.canonical_tag());
        canonical.push(self.proof_mechanism.canonical_tag());
        canonical.extend_from_slice(&self.nonce_digest);
        canonical.push(self.operation.canonical_tag());
        canonical.push(self.purpose.canonical_tag());
        canonical.extend_from_slice(&self.policy_digest);
        canonical.extend_from_slice(&self.key_identity_digest);
        canonical.extend_from_slice(&self.evidence_digest);
        canonical
    }

    /// Returns the deterministic, domain-separated replay digest.
    pub fn digest(&self) -> TrustDigest {
        digest_bytes(&self.canonical_bytes())
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn provider(&self) -> AttestationProvider {
        self.provider
    }

    pub fn proof_subject(&self) -> ReplayProofSubject {
        self.proof_subject
    }

    pub fn proof_mechanism(&self) -> ReplayProofMechanism {
        self.proof_mechanism
    }

    pub fn nonce_digest(&self) -> &TrustDigest {
        &self.nonce_digest
    }

    pub fn operation(&self) -> ReplayOperation {
        self.operation
    }

    pub fn purpose(&self) -> ReplayPurpose {
        self.purpose
    }

    pub fn policy_digest(&self) -> &TrustDigest {
        &self.policy_digest
    }

    pub fn key_identity_digest(&self) -> &TrustDigest {
        &self.key_identity_digest
    }

    pub fn evidence_digest(&self) -> &TrustDigest {
        &self.evidence_digest
    }
}

/// Errors a durable replay backend must expose without collapsing uncertainty
/// into success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum DurableReplayError {
    #[error("replay reservation is duplicated")]
    Duplicate,
    #[error("durable replay backend is unavailable")]
    Unavailable,
    #[error("durable replay backend outcome is uncertain")]
    Uncertain,
    #[error("replay clock moved backwards")]
    ClockRollback,
    #[error("replay reservation expiry is ambiguous")]
    ExpiryAmbiguous,
    #[error("replay reservation is invalid")]
    InvalidReservation,
    #[error("durable replay backend rolled back")]
    BackendRollback,
    #[error("durable replay backend requires recovery before retry")]
    RecoveryRequired,
}

/// A typed one-shot replay reservation. It contains a binding digest and an
/// absolute expiry, never the original nonce, evidence, key, or credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReplayReservation {
    binding_digest: TrustDigest,
    expires_at: u64,
}

impl ReplayReservation {
    pub fn new(binding_digest: TrustDigest, expires_at: u64) -> Result<Self, DurableReplayError> {
        if is_zero_digest(&binding_digest) || expires_at == 0 {
            return Err(DurableReplayError::InvalidReservation);
        }
        Ok(Self {
            binding_digest,
            expires_at,
        })
    }

    pub fn from_binding(
        binding: &ReplayBinding,
        expires_at: u64,
    ) -> Result<Self, DurableReplayError> {
        Self::new(binding.digest(), expires_at)
    }

    pub fn binding_digest(&self) -> &TrustDigest {
        &self.binding_digest
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// Backend-neutral durable replay contract.
///
/// Production implementations must provide an atomic insert-if-absent
/// transaction for the complete batch, durable replica/restart/region
/// behavior, and fail closed with [`DurableReplayError::Unavailable`],
/// [`DurableReplayError::Uncertain`], [`DurableReplayError::BackendRollback`],
/// or [`DurableReplayError::RecoveryRequired`] whenever the outcome cannot be
/// proven. Reservation validity is separate from retention of a consumed
/// binding identity after that validity expires. This contract deliberately
/// does not choose a database, replay owner, retention policy, or deployment
/// topology.
pub trait DurableReplayStore: Send + Sync {
    /// Atomically consumes every reservation or consumes none of the new
    /// reservations. Implementations may advance internal clock metadata on a
    /// rejected monotonic observation, but must not partially insert a batch.
    fn consume_once_batch(
        &self,
        reservations: &[ReplayReservation],
        now_secs: u64,
    ) -> Result<(), DurableReplayError>;

    /// Single-reservation convenience method retaining the same atomic
    /// insert-if-absent semantics.
    fn consume_once(
        &self,
        reservation: &ReplayReservation,
        now_secs: u64,
    ) -> Result<(), DurableReplayError> {
        self.consume_once_batch(std::slice::from_ref(reservation), now_secs)
    }
}

#[derive(Debug, Clone, Copy)]
struct InMemoryReplayTombstone;

#[derive(Debug, Default)]
struct InMemoryReplayState {
    /// Consumed binding identities are retained independently of reservation
    /// expiry so a caller cannot reuse a digest by submitting a later expiry.
    entries: HashMap<TrustDigest, InMemoryReplayTombstone>,
    last_observed_secs: Option<u64>,
}

/// Explicitly non-production, process-local replay adapter for tests and
/// development. It is not wired into signing, settlement, or provider paths.
/// A successfully consumed binding remains as a process-lifetime tombstone
/// after its reservation expires. That is intentionally distinct from
/// reservation validity; production retention and storage policy remain an
/// architecture decision.
#[derive(Debug, Default)]
pub struct NonProductionInMemoryReplayStore {
    state: Mutex<InMemoryReplayState>,
}

impl NonProductionInMemoryReplayStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl DurableReplayStore for NonProductionInMemoryReplayStore {
    fn consume_once_batch(
        &self,
        reservations: &[ReplayReservation],
        now_secs: u64,
    ) -> Result<(), DurableReplayError> {
        if reservations.is_empty() || reservations.len() > MAX_DURABLE_REPLAY_BATCH {
            return Err(DurableReplayError::InvalidReservation);
        }

        let mut requested = HashSet::with_capacity(reservations.len());
        for reservation in reservations {
            if reservation.expires_at <= now_secs {
                return Err(DurableReplayError::ExpiryAmbiguous);
            }
            if is_zero_digest(&reservation.binding_digest)
                || !requested.insert(reservation.binding_digest)
            {
                return Err(DurableReplayError::Duplicate);
            }
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| DurableReplayError::Unavailable)?;
        if state
            .last_observed_secs
            .is_some_and(|last_observed_secs| now_secs < last_observed_secs)
        {
            return Err(DurableReplayError::ClockRollback);
        }

        // Advance the monotonic observation before backend-visible replay
        // checks. No new reservation is written until the cloned next state
        // passes every check, so a rejected batch cannot partially insert.
        state.last_observed_secs = Some(now_secs);
        let mut next_entries = state.entries.clone();
        for reservation in reservations {
            if next_entries.contains_key(&reservation.binding_digest) {
                return Err(DurableReplayError::Duplicate);
            }
        }
        for reservation in reservations {
            next_entries.insert(reservation.binding_digest, InMemoryReplayTombstone);
        }
        state.entries = next_entries;
        Ok(())
    }
}

/// Kinds of exact references required by a release-evidence manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReleaseEvidenceKind {
    Candidate,
    Commit,
    Package,
    Sbom,
    Provenance,
    IndependentReview,
    SupportDecision,
}

impl ReleaseEvidenceKind {
    const fn canonical_tag(self) -> u8 {
        match self {
            Self::Candidate => 1,
            Self::Commit => 2,
            Self::Package => 3,
            Self::Sbom => 4,
            Self::Provenance => 5,
            Self::IndependentReview => 6,
            Self::SupportDecision => 7,
        }
    }
}

/// A stable reference plus its exact digest and candidate-scope digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceReference {
    reference: String,
    digest: TrustDigest,
    scope_digest: TrustDigest,
}

impl EvidenceReference {
    pub fn new(
        reference: impl Into<String>,
        digest: TrustDigest,
        scope_digest: TrustDigest,
    ) -> Result<Self, ReleaseEvidenceError> {
        let evidence = Self {
            reference: reference.into(),
            digest,
            scope_digest,
        };
        if !evidence.is_well_formed() {
            return Err(ReleaseEvidenceError::Malformed);
        }
        Ok(evidence)
    }

    fn is_well_formed(&self) -> bool {
        valid_identifier(&self.reference, MAX_EVIDENCE_REFERENCE_BYTES)
            && !is_zero_digest(&self.digest)
            && !is_zero_digest(&self.scope_digest)
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }

    pub fn digest(&self) -> &TrustDigest {
        &self.digest
    }

    pub fn scope_digest(&self) -> &TrustDigest {
        &self.scope_digest
    }
}

/// Exact digests required to validate a release-evidence manifest's scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseEvidenceExpectation {
    candidate_digest: TrustDigest,
    commit_digest: TrustDigest,
    package_digest: TrustDigest,
}

impl ReleaseEvidenceExpectation {
    pub fn new(
        candidate_digest: TrustDigest,
        commit_digest: TrustDigest,
        package_digest: TrustDigest,
    ) -> Result<Self, ReleaseEvidenceError> {
        if is_zero_digest(&candidate_digest)
            || is_zero_digest(&commit_digest)
            || is_zero_digest(&package_digest)
        {
            return Err(ReleaseEvidenceError::InvalidExpectation);
        }
        Ok(Self {
            candidate_digest,
            commit_digest,
            package_digest,
        })
    }
}

/// Deterministic release-evidence validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum ReleaseEvidenceError {
    #[error("release-evidence manifest is malformed")]
    Malformed,
    #[error("release-evidence manifest schema is unknown")]
    UnknownSchema,
    #[error("release-evidence manifest is missing a required reference")]
    Missing(ReleaseEvidenceKind),
    #[error("release-evidence manifest scope is inconsistent")]
    InconsistentScope,
    #[error("release candidate digest does not match the expected candidate")]
    CandidateMismatch,
    #[error("release commit digest does not match the expected commit")]
    CommitMismatch,
    #[error("release package digest does not match the expected package")]
    PackageMismatch,
    #[error("release-evidence validation expectation is invalid")]
    InvalidExpectation,
}

/// Provider-neutral manifest of exact release evidence.
///
/// Validation checks completeness and exact scope consistency only. It does
/// not choose approvers, evidence locations, retention, or a promotion
/// authority, and a valid manifest alone never enables production support.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseEvidenceManifest {
    schema_version: u16,
    candidate: Option<EvidenceReference>,
    commit: Option<EvidenceReference>,
    package: Option<EvidenceReference>,
    sbom: Option<EvidenceReference>,
    provenance: Option<EvidenceReference>,
    independent_review: Option<EvidenceReference>,
    support_decision: Option<EvidenceReference>,
}

impl ReleaseEvidenceManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema_version: u16,
        candidate: Option<EvidenceReference>,
        commit: Option<EvidenceReference>,
        package: Option<EvidenceReference>,
        sbom: Option<EvidenceReference>,
        provenance: Option<EvidenceReference>,
        independent_review: Option<EvidenceReference>,
        support_decision: Option<EvidenceReference>,
    ) -> Self {
        Self {
            schema_version,
            candidate,
            commit,
            package,
            sbom,
            provenance,
            independent_review,
            support_decision,
        }
    }

    pub fn validate(
        &self,
        expectation: &ReleaseEvidenceExpectation,
    ) -> Result<(), ReleaseEvidenceError> {
        if self.schema_version != RELEASE_EVIDENCE_SCHEMA_VERSION {
            return Err(ReleaseEvidenceError::UnknownSchema);
        }

        let references = [
            (ReleaseEvidenceKind::Candidate, self.candidate.as_ref()),
            (ReleaseEvidenceKind::Commit, self.commit.as_ref()),
            (ReleaseEvidenceKind::Package, self.package.as_ref()),
            (ReleaseEvidenceKind::Sbom, self.sbom.as_ref()),
            (ReleaseEvidenceKind::Provenance, self.provenance.as_ref()),
            (
                ReleaseEvidenceKind::IndependentReview,
                self.independent_review.as_ref(),
            ),
            (
                ReleaseEvidenceKind::SupportDecision,
                self.support_decision.as_ref(),
            ),
        ];
        for (kind, reference) in references {
            let reference = reference.ok_or(ReleaseEvidenceError::Missing(kind))?;
            if !reference.is_well_formed() {
                return Err(ReleaseEvidenceError::Malformed);
            }
        }

        let candidate = self
            .candidate
            .as_ref()
            .ok_or(ReleaseEvidenceError::Missing(
                ReleaseEvidenceKind::Candidate,
            ))?;
        if candidate.digest != expectation.candidate_digest {
            return Err(ReleaseEvidenceError::CandidateMismatch);
        }
        if candidate.scope_digest != expectation.candidate_digest {
            return Err(ReleaseEvidenceError::InconsistentScope);
        }

        let commit = self
            .commit
            .as_ref()
            .ok_or(ReleaseEvidenceError::Missing(ReleaseEvidenceKind::Commit))?;
        if commit.digest != expectation.commit_digest {
            return Err(ReleaseEvidenceError::CommitMismatch);
        }
        let package = self
            .package
            .as_ref()
            .ok_or(ReleaseEvidenceError::Missing(ReleaseEvidenceKind::Package))?;
        if package.digest != expectation.package_digest {
            return Err(ReleaseEvidenceError::PackageMismatch);
        }

        for (_, reference) in references {
            let reference = reference.ok_or(ReleaseEvidenceError::Malformed)?;
            if reference.scope_digest != expectation.candidate_digest {
                return Err(ReleaseEvidenceError::InconsistentScope);
            }
        }
        Ok(())
    }

    /// Returns a deterministic digest of the manifest's exact references and
    /// digests. This is an evidence binding, not a promotion decision.
    pub fn manifest_digest(&self) -> Result<TrustDigest, ReleaseEvidenceError> {
        let mut canonical = Vec::new();
        append_len_prefixed(&mut canonical, RELEASE_EVIDENCE_DOMAIN.as_bytes())
            .ok_or(ReleaseEvidenceError::Malformed)?;
        canonical.extend_from_slice(&self.schema_version.to_be_bytes());
        for (kind, reference) in [
            (ReleaseEvidenceKind::Candidate, self.candidate.as_ref()),
            (ReleaseEvidenceKind::Commit, self.commit.as_ref()),
            (ReleaseEvidenceKind::Package, self.package.as_ref()),
            (ReleaseEvidenceKind::Sbom, self.sbom.as_ref()),
            (ReleaseEvidenceKind::Provenance, self.provenance.as_ref()),
            (
                ReleaseEvidenceKind::IndependentReview,
                self.independent_review.as_ref(),
            ),
            (
                ReleaseEvidenceKind::SupportDecision,
                self.support_decision.as_ref(),
            ),
        ] {
            canonical.push(kind.canonical_tag());
            match reference {
                Some(reference) => {
                    canonical.push(1);
                    append_len_prefixed(&mut canonical, reference.reference.as_bytes())
                        .ok_or(ReleaseEvidenceError::Malformed)?;
                    canonical.extend_from_slice(&reference.digest);
                    canonical.extend_from_slice(&reference.scope_digest);
                }
                None => canonical.push(0),
            }
        }
        Ok(digest_bytes(&canonical))
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn candidate(&self) -> Option<&EvidenceReference> {
        self.candidate.as_ref()
    }

    pub fn commit(&self) -> Option<&EvidenceReference> {
        self.commit.as_ref()
    }

    pub fn package(&self) -> Option<&EvidenceReference> {
        self.package.as_ref()
    }

    pub fn sbom(&self) -> Option<&EvidenceReference> {
        self.sbom.as_ref()
    }

    pub fn provenance(&self) -> Option<&EvidenceReference> {
        self.provenance.as_ref()
    }

    pub fn independent_review(&self) -> Option<&EvidenceReference> {
        self.independent_review.as_ref()
    }

    pub fn support_decision(&self) -> Option<&EvidenceReference> {
        self.support_decision.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::to_string;

    fn digest(byte: u8) -> TrustDigest {
        [byte; TRUST_DIGEST_BYTES]
    }

    fn metadata(now_secs: u64) -> CollateralMetadata {
        CollateralMetadata::try_new(
            AttestationProvider::AwsNitroEnclave,
            "nitro-collateral",
            3,
            digest(1),
            digest(2),
            now_secs.saturating_sub(10),
            now_secs.saturating_add(100),
            7,
            COLLATERAL_VERIFIER_VERSION,
            COLLATERAL_SCHEMA_VERSION,
            digest(3),
            digest(4),
            digest(5),
        )
        .expect("valid collateral metadata")
    }

    fn collateral_context(
        now_secs: u64,
        observed_epoch: u64,
        minimum_epoch: u64,
    ) -> CollateralValidationContext {
        CollateralValidationContext::strict_for(
            AttestationProvider::AwsNitroEnclave,
            digest(1),
            now_secs,
            observed_epoch,
            minimum_epoch,
        )
        .expect("valid collateral context")
    }

    #[test]
    fn provider_identity_only_maps_from_specific_existing_levels() {
        assert_eq!(
            AttestationProvider::from_attestation_level(AttestationLevel::StrongBox),
            Some(AttestationProvider::AndroidKeyMintStrongBox)
        );
        assert_eq!(
            AttestationProvider::from_attestation_level(AttestationLevel::CloudTEE),
            None
        );
        assert_eq!(
            AttestationProvider::AwsNitroEnclave.attestation_level(),
            AttestationLevel::CloudTEE
        );
        assert_eq!(
            "not-a-provider".parse::<AttestationProvider>(),
            Err(CollateralValidationError::UnknownProvider)
        );
    }

    #[test]
    fn collateral_metadata_validates_without_raw_roots() {
        let now_secs = 1_000;
        let metadata = metadata(now_secs);
        assert_eq!(
            metadata.validate(&collateral_context(now_secs, 7, 7)),
            Ok(())
        );
        let serialized = to_string(&metadata).expect("metadata serializes");
        assert!(serialized.contains("root_set_digest"));
        assert!(!serialized.contains("root-ca"));
        assert!(metadata.canonical_digest().is_ok());
    }

    #[test]
    fn collateral_expiry_is_strict_without_stale_grace() {
        let now_secs = 1_000;
        let mut expired = metadata(now_secs);
        expired.expires_at = now_secs;
        assert_eq!(
            expired.validate(&collateral_context(now_secs, 7, 7)),
            Err(CollateralValidationError::Expired)
        );
    }

    #[test]
    fn collateral_future_and_revocation_states_fail_closed() {
        let now_secs = 1_000;
        let mut future = metadata(now_secs);
        future.issued_at = now_secs + 1;
        assert_eq!(
            future.validate(&collateral_context(now_secs, 7, 7)),
            Err(CollateralValidationError::NotYetValid)
        );

        let mut rollback = metadata(now_secs);
        rollback.revocation_epoch = 6;
        assert_eq!(
            rollback.validate(&collateral_context(now_secs, 7, 7)),
            Err(CollateralValidationError::RevocationRollback)
        );

        let mut stale = metadata(now_secs);
        stale.revocation_epoch = 7;
        assert_eq!(
            stale.validate(&collateral_context(now_secs, 6, 8)),
            Err(CollateralValidationError::StaleRevocation)
        );
    }

    #[test]
    fn unknown_collateral_schema_and_root_mismatch_fail_closed() {
        let now_secs = 1_000;
        let mut unknown_schema = metadata(now_secs);
        unknown_schema.schema_version = COLLATERAL_SCHEMA_VERSION + 1;
        assert_eq!(
            unknown_schema.validate(&collateral_context(now_secs, 7, 7)),
            Err(CollateralValidationError::UnknownSchema)
        );

        let mut wrong_root = metadata(now_secs);
        wrong_root.root_set_digest = digest(9);
        assert_eq!(
            wrong_root.validate(&collateral_context(now_secs, 7, 7)),
            Err(CollateralValidationError::RootSetMismatch)
        );
    }

    #[test]
    fn authenticated_collateral_requires_an_unimplemented_authority_verifier() {
        let metadata = metadata(1_000);
        let bundle = AuthenticatedCollateralMetadata::try_new(metadata, digest(6), digest(7))
            .expect("valid digest-only collateral bundle");
        assert_eq!(
            bundle.validate(&collateral_context(1_000, 7, 7)),
            Err(CollateralValidationError::AuthenticationUnavailable)
        );
        assert!(bundle.binding_digest().is_ok());
    }

    fn deterministic_fixture_input(seed: u8) -> Vec<u8> {
        (0u8..32)
            .map(|offset| seed.wrapping_mul(29).wrapping_add(offset).wrapping_add(1))
            .collect()
    }

    struct ReplayBindingFixture {
        provider: AttestationProvider,
        subject: ReplayProofSubject,
        mechanism: ReplayProofMechanism,
        nonce: Vec<u8>,
        operation: ReplayOperation,
        purpose: ReplayPurpose,
        policy_digest: TrustDigest,
        key_identity: Vec<u8>,
        evidence: Vec<u8>,
    }

    impl Default for ReplayBindingFixture {
        fn default() -> Self {
            Self {
                provider: AttestationProvider::AwsNitroEnclave,
                subject: ReplayProofSubject::Device,
                mechanism: ReplayProofMechanism::AwsNitroAttestationDocument,
                nonce: deterministic_fixture_input(1),
                operation: ReplayOperation::ValueBearingSigning,
                purpose: ReplayPurpose::Sign,
                policy_digest: digest(10),
                key_identity: deterministic_fixture_input(2),
                evidence: deterministic_fixture_input(3),
            }
        }
    }

    impl ReplayBindingFixture {
        fn with_provider(mut self, provider: AttestationProvider) -> Self {
            self.provider = provider;
            self
        }

        fn with_subject(mut self, subject: ReplayProofSubject) -> Self {
            self.subject = subject;
            self
        }

        fn with_mechanism(mut self, mechanism: ReplayProofMechanism) -> Self {
            self.mechanism = mechanism;
            self
        }

        fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
            self.nonce = nonce;
            self
        }

        fn with_operation(mut self, operation: ReplayOperation) -> Self {
            self.operation = operation;
            self
        }

        fn with_purpose(mut self, purpose: ReplayPurpose) -> Self {
            self.purpose = purpose;
            self
        }

        fn with_policy_digest(mut self, policy_digest: TrustDigest) -> Self {
            self.policy_digest = policy_digest;
            self
        }

        fn with_key_identity(mut self, key_identity: Vec<u8>) -> Self {
            self.key_identity = key_identity;
            self
        }

        fn with_evidence(mut self, evidence: Vec<u8>) -> Self {
            self.evidence = evidence;
            self
        }

        fn build(self) -> ReplayBinding {
            ReplayBinding::try_new(
                self.provider,
                self.subject,
                self.mechanism,
                &self.nonce,
                self.operation,
                self.purpose,
                self.policy_digest,
                &self.key_identity,
                &self.evidence,
            )
            .expect("valid replay binding")
        }
    }

    fn base_replay_binding() -> ReplayBinding {
        ReplayBindingFixture::default().build()
    }

    #[test]
    fn every_replay_binding_field_changes_the_digest() {
        let base = base_replay_binding().digest();
        let cases = [
            ReplayBindingFixture::default()
                .with_provider(AttestationProvider::AndroidKeyMintStrongBox)
                .build(),
            ReplayBindingFixture::default()
                .with_subject(ReplayProofSubject::Workload)
                .build(),
            ReplayBindingFixture::default()
                .with_mechanism(ReplayProofMechanism::TpmQuote)
                .build(),
            ReplayBindingFixture::default()
                .with_nonce(deterministic_fixture_input(4))
                .build(),
            ReplayBindingFixture::default()
                .with_operation(ReplayOperation::SettlementDispatch)
                .build(),
            ReplayBindingFixture::default()
                .with_purpose(ReplayPurpose::Authorize)
                .build(),
            ReplayBindingFixture::default()
                .with_policy_digest(digest(11))
                .build(),
            ReplayBindingFixture::default()
                .with_key_identity(deterministic_fixture_input(5))
                .build(),
            ReplayBindingFixture::default()
                .with_evidence(deterministic_fixture_input(6))
                .build(),
        ];
        for binding in cases {
            assert_ne!(base, binding.digest());
        }
    }

    #[test]
    fn replay_binding_debug_and_serialization_exclude_raw_sensitive_values() {
        let binding = base_replay_binding();
        let debug = format!("{binding:?}");
        let serialized = to_string(&binding).expect("replay binding serializes");
        let raw_markers = [
            hex::encode(deterministic_fixture_input(1)),
            hex::encode(deterministic_fixture_input(2)),
            hex::encode(deterministic_fixture_input(3)),
        ];
        for marker in raw_markers {
            assert!(!debug.contains(&marker));
            assert!(!serialized.contains(&marker));
        }
        assert!(debug.contains("nonce_digest"));
        assert!(serialized.contains("evidence_digest"));
    }

    #[test]
    fn replay_reservations_and_in_memory_store_are_atomic_and_non_production() {
        let store = NonProductionInMemoryReplayStore::new();
        let first = ReplayReservation::from_binding(&base_replay_binding(), 200)
            .expect("valid replay reservation");
        assert_eq!(store.consume_once(&first, 100), Ok(()));
        assert_eq!(
            store.consume_once(&first, 101),
            Err(DurableReplayError::Duplicate)
        );

        let second = ReplayReservation::from_binding(
            &ReplayBindingFixture::default()
                .with_subject(ReplayProofSubject::Workload)
                .with_nonce(deterministic_fixture_input(7))
                .with_key_identity(deterministic_fixture_input(8))
                .with_evidence(deterministic_fixture_input(9))
                .build(),
            200,
        )
        .expect("valid second reservation");
        assert_eq!(
            store.consume_once_batch(&[second, first], 102),
            Err(DurableReplayError::Duplicate)
        );
        assert_eq!(store.consume_once(&second, 103), Ok(()));
    }

    #[test]
    fn in_memory_store_retains_consumed_identity_after_reservation_expiry() {
        let store = NonProductionInMemoryReplayStore::new();
        let original = ReplayReservation::from_binding(&base_replay_binding(), 100)
            .expect("valid original replay reservation");
        assert_eq!(store.consume_once(&original, 10), Ok(()));
        assert!(original.expires_at() < 200);

        let extended = ReplayReservation::from_binding(&base_replay_binding(), 300)
            .expect("valid extended replay reservation");
        assert_eq!(
            store.consume_once(&extended, 200),
            Err(DurableReplayError::Duplicate)
        );
        assert_eq!(
            store.consume_once(&extended, 199),
            Err(DurableReplayError::ClockRollback)
        );
    }

    #[test]
    fn in_memory_store_rejects_expiry_ambiguity_and_clock_rollback() {
        let store = NonProductionInMemoryReplayStore::new();
        let reservation = ReplayReservation::from_binding(&base_replay_binding(), 100)
            .expect("valid replay reservation");
        assert_eq!(
            store.consume_once(&reservation, 100),
            Err(DurableReplayError::ExpiryAmbiguous)
        );
        assert_eq!(store.consume_once(&reservation, 99), Ok(()));
        assert_eq!(
            store.consume_once(&reservation, 98),
            Err(DurableReplayError::ClockRollback)
        );
    }

    struct FailureStore(DurableReplayError);

    impl DurableReplayStore for FailureStore {
        fn consume_once_batch(
            &self,
            _reservations: &[ReplayReservation],
            _now_secs: u64,
        ) -> Result<(), DurableReplayError> {
            Err(self.0)
        }
    }

    #[test]
    fn durable_backend_uncertainty_and_recovery_errors_are_typed() {
        let reservation = ReplayReservation::from_binding(&base_replay_binding(), 200)
            .expect("valid replay reservation");
        for error in [
            DurableReplayError::Unavailable,
            DurableReplayError::Uncertain,
            DurableReplayError::BackendRollback,
            DurableReplayError::RecoveryRequired,
        ] {
            let store = FailureStore(error);
            assert_eq!(store.consume_once(&reservation, 100), Err(error));
        }
    }

    fn evidence_reference(label: &str, value: u8, scope: TrustDigest) -> EvidenceReference {
        EvidenceReference::new(label, digest(value), scope).expect("valid evidence reference")
    }

    fn evidence_manifest() -> (ReleaseEvidenceManifest, ReleaseEvidenceExpectation) {
        let candidate = digest(20);
        let expectation = ReleaseEvidenceExpectation::new(candidate, digest(21), digest(22))
            .expect("valid release expectation");
        let manifest = ReleaseEvidenceManifest::new(
            RELEASE_EVIDENCE_SCHEMA_VERSION,
            Some(evidence_reference("candidate", 20, candidate)),
            Some(evidence_reference("commit", 21, candidate)),
            Some(evidence_reference("package", 22, candidate)),
            Some(evidence_reference("sbom", 23, candidate)),
            Some(evidence_reference("provenance", 24, candidate)),
            Some(evidence_reference("independent-review", 25, candidate)),
            Some(evidence_reference("support-decision", 26, candidate)),
        );
        (manifest, expectation)
    }

    #[test]
    fn release_evidence_requires_exact_complete_consistent_scope() {
        let (manifest, expectation) = evidence_manifest();
        assert_eq!(manifest.validate(&expectation), Ok(()));
        assert!(manifest.manifest_digest().is_ok());

        let missing_review = ReleaseEvidenceManifest::new(
            manifest.schema_version,
            manifest.candidate.clone(),
            manifest.commit.clone(),
            manifest.package.clone(),
            manifest.sbom.clone(),
            manifest.provenance.clone(),
            None,
            manifest.support_decision.clone(),
        );
        assert_eq!(
            missing_review.validate(&expectation),
            Err(ReleaseEvidenceError::Missing(
                ReleaseEvidenceKind::IndependentReview
            ))
        );

        let inconsistent = ReleaseEvidenceManifest::new(
            manifest.schema_version,
            manifest.candidate.clone(),
            manifest.commit.clone(),
            manifest.package.clone(),
            Some(evidence_reference("sbom", 23, digest(99))),
            manifest.provenance.clone(),
            manifest.independent_review.clone(),
            manifest.support_decision.clone(),
        );
        assert_eq!(
            inconsistent.validate(&expectation),
            Err(ReleaseEvidenceError::InconsistentScope)
        );
    }

    #[test]
    fn release_evidence_schema_and_digest_mismatches_fail_closed() {
        let (manifest, expectation) = evidence_manifest();
        let unknown_schema = ReleaseEvidenceManifest::new(
            RELEASE_EVIDENCE_SCHEMA_VERSION + 1,
            manifest.candidate.clone(),
            manifest.commit.clone(),
            manifest.package.clone(),
            manifest.sbom.clone(),
            manifest.provenance.clone(),
            manifest.independent_review.clone(),
            manifest.support_decision.clone(),
        );
        assert_eq!(
            unknown_schema.validate(&expectation),
            Err(ReleaseEvidenceError::UnknownSchema)
        );

        let wrong_package = ReleaseEvidenceManifest::new(
            manifest.schema_version,
            manifest.candidate.clone(),
            manifest.commit.clone(),
            Some(evidence_reference("package", 98, digest(20))),
            manifest.sbom.clone(),
            manifest.provenance.clone(),
            manifest.independent_review.clone(),
            manifest.support_decision.clone(),
        );
        assert_eq!(
            wrong_package.validate(&expectation),
            Err(ReleaseEvidenceError::PackageMismatch)
        );
    }
}
