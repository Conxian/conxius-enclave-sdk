//! Backend-neutral durable replay and idempotency contracts.
//!
//! This module does not implement persistence or distributed coordination. It
//! defines the identity, request, outcome, and fail-closed authorization
//! boundary that a later reviewed backend must implement. The existing
//! process-local `ProofReplayKey` and `ReplayGuard` are intentionally
//! unchanged and are not used here.

use crate::enclave::proofs::ProofKind;
use crate::enclave::trust::{AttestationResult, TrustError, TrustedClock};
use serde::Serialize;
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::collections::{HashMap, VecDeque};
use std::fmt;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;

pub const DURABLE_REPLAY_CONTRACT_VERSION: u16 = 1;
pub const DURABLE_REPLAY_IDENTITY_DOMAIN: &str = "CONXIAN-DURABLE-REPLAY-IDENTITY/v1";
pub const DURABLE_REPLAY_REQUEST_DOMAIN: &str = "CONXIAN-DURABLE-REPLAY-REQUEST/v1";
pub const IDEMPOTENCY_KEY_DOMAIN: &str = "CONXIAN-IDEMPOTENCY-KEY/v1";
pub const MAX_DURABLE_REPLAY_IDENTIFIER_BYTES: usize = 256;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DurableReplayError {
    #[error("durable replay input is invalid")]
    InvalidPayload,
    #[error("durable replay request has expired")]
    Expired,
    #[error("durable replay clock is unavailable")]
    ClockUnavailable,
    #[error("durable replay clock moved backwards")]
    ClockRollback,
    #[error("durable replay store is unavailable")]
    StoreUnavailable,
    #[error("durable replay commit outcome is uncertain")]
    UncertainCommit,
    #[error("durable replay request conflicts with a consumed request")]
    ConflictingRequest,
    #[error("durable replay authorization is not available")]
    NotAuthorizable,
    #[error("durable replay contract is unsupported")]
    Unsupported,
}

pub type DurableReplayResult<T> = Result<T, DurableReplayError>;

fn validate_identifier(value: &str) -> DurableReplayResult<()> {
    if value.is_empty()
        || value.len() > MAX_DURABLE_REPLAY_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(DurableReplayError::InvalidPayload);
    }
    Ok(())
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) -> DurableReplayResult<()> {
    let length = u32::try_from(value.len()).map_err(|_| DurableReplayError::InvalidPayload)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn append_identifier(output: &mut Vec<u8>, value: &str) -> DurableReplayResult<()> {
    validate_identifier(value)?;
    append_len_prefixed(output, value.as_bytes())
}

fn append_digest(output: &mut Vec<u8>, value: &[u8; 32]) -> DurableReplayResult<()> {
    append_len_prefixed(output, value)
}

/// A versioned identity for durable consume-once semantics. Raw evidence and
/// secrets never enter the identity; provider/profile/mechanism names and
/// purpose/audience are bounded contract labels, while subject/key/nonce and
/// all material references are digests.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DurableReplayIdentity {
    version: u16,
    provider: String,
    profile: String,
    mechanism: ProofKind,
    verifier_id: String,
    subject_digest: [u8; 32],
    key_identity_digest: [u8; 32],
    operation_digest: [u8; 32],
    nonce_digest: [u8; 32],
    purpose: String,
    audience: String,
    policy_digest: [u8; 32],
    evidence_digest: [u8; 32],
    trust_bundle_digest: [u8; 32],
    collateral_digest: [u8; 32],
    expires_at: u64,
}

impl fmt::Debug for DurableReplayIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableReplayIdentity")
            .field("version", &self.version)
            .field("provider", &self.provider)
            .field("profile", &self.profile)
            .field("mechanism", &self.mechanism)
            .field("verifier_id", &self.verifier_id)
            .field("subject_digest", &self.subject_digest)
            .field("key_identity_digest", &self.key_identity_digest)
            .field("operation_digest", &self.operation_digest)
            .field("nonce_digest", &self.nonce_digest)
            .field("purpose", &self.purpose)
            .field("audience", &self.audience)
            .field("policy_digest", &self.policy_digest)
            .field("evidence_digest", &self.evidence_digest)
            .field("trust_bundle_digest", &self.trust_bundle_digest)
            .field("collateral_digest", &self.collateral_digest)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl DurableReplayIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: impl Into<String>,
        profile: impl Into<String>,
        mechanism: ProofKind,
        subject_digest: [u8; 32],
        key_identity_digest: [u8; 32],
        operation_digest: [u8; 32],
        nonce_digest: [u8; 32],
        purpose: impl Into<String>,
        audience: impl Into<String>,
        policy_digest: [u8; 32],
        evidence_digest: [u8; 32],
        trust_bundle_digest: [u8; 32],
        collateral_digest: [u8; 32],
        expires_at: u64,
    ) -> DurableReplayResult<Self> {
        Self::new_with_verifier(
            provider,
            profile,
            mechanism,
            mechanism.production_verifier_id(),
            subject_digest,
            key_identity_digest,
            operation_digest,
            nonce_digest,
            purpose,
            audience,
            policy_digest,
            evidence_digest,
            trust_bundle_digest,
            collateral_digest,
            expires_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_verifier(
        provider: impl Into<String>,
        profile: impl Into<String>,
        mechanism: ProofKind,
        verifier_id: impl Into<String>,
        subject_digest: [u8; 32],
        key_identity_digest: [u8; 32],
        operation_digest: [u8; 32],
        nonce_digest: [u8; 32],
        purpose: impl Into<String>,
        audience: impl Into<String>,
        policy_digest: [u8; 32],
        evidence_digest: [u8; 32],
        trust_bundle_digest: [u8; 32],
        collateral_digest: [u8; 32],
        expires_at: u64,
    ) -> DurableReplayResult<Self> {
        let identity = Self {
            version: DURABLE_REPLAY_CONTRACT_VERSION,
            provider: provider.into(),
            profile: profile.into(),
            mechanism,
            verifier_id: verifier_id.into(),
            subject_digest,
            key_identity_digest,
            operation_digest,
            nonce_digest,
            purpose: purpose.into(),
            audience: audience.into(),
            policy_digest,
            evidence_digest,
            trust_bundle_digest,
            collateral_digest,
            expires_at,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn from_attestation_result(result: &AttestationResult) -> DurableReplayResult<Self> {
        Self::new_with_verifier(
            result.provider(),
            result.profile(),
            result.mechanism(),
            result.verifier_id(),
            result.subject_digest(),
            result.key_identity_digest(),
            result.operation_digest(),
            result.nonce_digest(),
            result.purpose(),
            result.audience(),
            result.policy_digest(),
            result.evidence_digest(),
            result.trust_bundle_digest(),
            result.collateral_digest(),
            result.expires_at(),
        )
    }

    pub fn validate(&self) -> DurableReplayResult<()> {
        if self.version != DURABLE_REPLAY_CONTRACT_VERSION {
            return Err(DurableReplayError::Unsupported);
        }
        validate_identifier(&self.provider)?;
        validate_identifier(&self.profile)?;
        validate_identifier(&self.verifier_id)?;
        validate_identifier(&self.purpose)?;
        validate_identifier(&self.audience)?;
        if self.verifier_id != self.mechanism.production_verifier_id() {
            return Err(DurableReplayError::InvalidPayload);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> DurableReplayResult<Vec<u8>> {
        self.validate()?;
        let mut output = Vec::new();
        append_len_prefixed(&mut output, DURABLE_REPLAY_IDENTITY_DOMAIN.as_bytes())?;
        output.extend_from_slice(&self.version.to_be_bytes());
        append_identifier(&mut output, &self.provider)?;
        append_identifier(&mut output, &self.profile)?;
        output.push(self.mechanism.canonical_tag());
        append_identifier(&mut output, &self.verifier_id)?;
        append_digest(&mut output, &self.subject_digest)?;
        append_digest(&mut output, &self.key_identity_digest)?;
        append_digest(&mut output, &self.operation_digest)?;
        append_digest(&mut output, &self.nonce_digest)?;
        append_identifier(&mut output, &self.purpose)?;
        append_identifier(&mut output, &self.audience)?;
        append_digest(&mut output, &self.policy_digest)?;
        append_digest(&mut output, &self.evidence_digest)?;
        append_digest(&mut output, &self.trust_bundle_digest)?;
        append_digest(&mut output, &self.collateral_digest)?;
        output.extend_from_slice(&self.expires_at.to_be_bytes());
        Ok(output)
    }

    pub fn digest(&self) -> DurableReplayResult<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
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

    pub fn verifier_id(&self) -> &str {
        &self.verifier_id
    }

    pub fn subject_digest(&self) -> [u8; 32] {
        self.subject_digest
    }

    pub fn key_identity_digest(&self) -> [u8; 32] {
        self.key_identity_digest
    }

    pub fn operation_digest(&self) -> [u8; 32] {
        self.operation_digest
    }

    pub fn nonce_digest(&self) -> [u8; 32] {
        self.nonce_digest
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    pub fn audience(&self) -> &str {
        &self.audience
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

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// An idempotency key is deliberately separate from subject and key identity.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey {
    bytes: Vec<u8>,
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdempotencyKey")
            .field("digest", &self.digest())
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl IdempotencyKey {
    pub fn new(bytes: Vec<u8>) -> DurableReplayResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(DurableReplayError::InvalidPayload);
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(&(IDEMPOTENCY_KEY_DOMAIN.len() as u32).to_be_bytes());
        canonical.extend_from_slice(IDEMPOTENCY_KEY_DOMAIN.as_bytes());
        canonical.extend_from_slice(&DURABLE_REPLAY_CONTRACT_VERSION.to_be_bytes());
        canonical.extend_from_slice(&(self.bytes.len() as u32).to_be_bytes());
        canonical.extend_from_slice(&self.bytes);
        Sha256::digest(canonical).into()
    }
}

/// One exact request to the durable store.
#[derive(Clone, PartialEq, Eq)]
pub struct DurableReplayRequest {
    identity: DurableReplayIdentity,
    idempotency_key: IdempotencyKey,
    request_digest: [u8; 32],
}

impl fmt::Debug for DurableReplayRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableReplayRequest")
            .field("identity_digest", &self.identity.digest())
            .field("idempotency_key", &self.idempotency_key)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl DurableReplayRequest {
    pub fn new(
        identity: DurableReplayIdentity,
        idempotency_key: IdempotencyKey,
    ) -> DurableReplayResult<Self> {
        identity.validate()?;
        let identity_digest = identity.digest()?;
        let idempotency_digest = idempotency_key.digest();
        let mut canonical = Vec::new();
        append_len_prefixed(&mut canonical, DURABLE_REPLAY_REQUEST_DOMAIN.as_bytes())?;
        canonical.extend_from_slice(&DURABLE_REPLAY_CONTRACT_VERSION.to_be_bytes());
        append_digest(&mut canonical, &identity_digest)?;
        append_digest(&mut canonical, &idempotency_digest)?;
        let request_digest = Sha256::digest(canonical).into();
        Ok(Self {
            identity,
            idempotency_key,
            request_digest,
        })
    }

    pub fn identity(&self) -> &DurableReplayIdentity {
        &self.identity
    }

    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    pub fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
}

/// Store result. Only the first two outcomes can authorize through the
/// wrapper; every other outcome is fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DurableReplayOutcome {
    Consumed,
    AlreadyConsumedSameRequest,
    ConflictingRequest,
    Unavailable,
    UncertainCommit,
}

/// Synchronous, object-safe atomic consume-once boundary. A production
/// implementation must define durability, replica/restart behavior, and
/// uncertain-commit semantics outside this crate.
pub trait DurableReplayStore: Send + Sync {
    fn consume_once(
        &self,
        request: &DurableReplayRequest,
        now_secs: u64,
    ) -> DurableReplayResult<DurableReplayOutcome>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableDurableReplayStore;

impl DurableReplayStore for UnavailableDurableReplayStore {
    fn consume_once(
        &self,
        _request: &DurableReplayRequest,
        _now_secs: u64,
    ) -> DurableReplayResult<DurableReplayOutcome> {
        Ok(DurableReplayOutcome::Unavailable)
    }
}

/// Authorization returned only for a consumed request or a backend-confirmed
/// same-request idempotent retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableReplayAuthorization {
    identity_digest: [u8; 32],
    idempotency_key_digest: [u8; 32],
    outcome: DurableReplayOutcome,
    expires_at: u64,
}

impl DurableReplayAuthorization {
    pub fn identity_digest(&self) -> [u8; 32] {
        self.identity_digest
    }

    pub fn idempotency_key_digest(&self) -> [u8; 32] {
        self.idempotency_key_digest
    }

    pub fn outcome(&self) -> DurableReplayOutcome {
        self.outcome
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn is_idempotent_retry(&self) -> bool {
        matches!(
            self.outcome,
            DurableReplayOutcome::AlreadyConsumedSameRequest
        )
    }
}

/// Contract-only wrapper from a normalized result to durable replay. It does
/// not call signing, settlement, `EnclaveManager`, `RailProxy`, or `ReplayGuard`.
pub struct DurableReplayAuthorizer {
    store: Arc<dyn DurableReplayStore>,
    clock: Arc<dyn TrustedClock>,
    last_observed_secs: AtomicU64,
}

impl fmt::Debug for DurableReplayAuthorizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableReplayAuthorizer")
            .field("store", &"configured")
            .field("clock", &"configured")
            .finish()
    }
}

impl DurableReplayAuthorizer {
    pub(crate) fn new(store: Arc<dyn DurableReplayStore>, clock: Arc<dyn TrustedClock>) -> Self {
        Self {
            store,
            clock,
            last_observed_secs: AtomicU64::new(0),
        }
    }

    pub fn production() -> Self {
        Self::new(
            Arc::new(UnavailableDurableReplayStore),
            Arc::new(crate::enclave::trust::SystemTrustedClock),
        )
    }

    pub fn identity_for(
        &self,
        result: &AttestationResult,
    ) -> DurableReplayResult<DurableReplayIdentity> {
        result
            .validate_for_authorization()
            .map_err(|_| DurableReplayError::NotAuthorizable)?;
        if !result.revocation_status().is_authorizable() || !result.tcb_status().is_authorizable() {
            return Err(DurableReplayError::NotAuthorizable);
        }
        DurableReplayIdentity::from_attestation_result(result)
    }

    pub fn consume_once(
        &self,
        result: &AttestationResult,
        idempotency_key: IdempotencyKey,
    ) -> DurableReplayResult<DurableReplayAuthorization> {
        let observed_secs = self.clock.now_secs().map_err(map_clock_error)?;
        let now_secs = self.observe_monotonic_time(observed_secs)?;
        if !result.is_authorizable_at(now_secs) {
            return Err(DurableReplayError::NotAuthorizable);
        }
        let identity = self.identity_for(result)?;
        if identity.expires_at() < now_secs {
            return Err(DurableReplayError::Expired);
        }
        let request = DurableReplayRequest::new(identity, idempotency_key)?;
        let outcome = self.store.consume_once(&request, now_secs)?;
        match outcome {
            DurableReplayOutcome::Consumed | DurableReplayOutcome::AlreadyConsumedSameRequest => {
                Ok(DurableReplayAuthorization {
                    identity_digest: request.identity.digest()?,
                    idempotency_key_digest: request.idempotency_key.digest(),
                    outcome,
                    expires_at: request.identity.expires_at(),
                })
            }
            DurableReplayOutcome::ConflictingRequest => Err(DurableReplayError::ConflictingRequest),
            DurableReplayOutcome::Unavailable => Err(DurableReplayError::StoreUnavailable),
            DurableReplayOutcome::UncertainCommit => Err(DurableReplayError::UncertainCommit),
        }
    }

    fn observe_monotonic_time(&self, observed_secs: u64) -> DurableReplayResult<u64> {
        let mut previous = self.last_observed_secs.load(Ordering::Acquire);
        loop {
            if observed_secs < previous {
                return Err(DurableReplayError::ClockRollback);
            }
            if observed_secs == previous {
                return Ok(observed_secs);
            }
            match self.last_observed_secs.compare_exchange_weak(
                previous,
                observed_secs,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(observed_secs),
                Err(actual) => previous = actual,
            }
        }
    }
}

fn map_clock_error(error: TrustError) -> DurableReplayError {
    match error {
        TrustError::ClockRollback => DurableReplayError::ClockRollback,
        TrustError::ClockUnavailable => DurableReplayError::ClockUnavailable,
        _ => DurableReplayError::ClockUnavailable,
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct InMemoryDurableReplayStore {
    state: Mutex<InMemoryReplayState>,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct InMemoryReplayState {
    entries: HashMap<[u8; 32], ([u8; 32], u64)>,
    last_observed_secs: Option<u64>,
}

#[cfg(test)]
impl DurableReplayStore for InMemoryDurableReplayStore {
    fn consume_once(
        &self,
        request: &DurableReplayRequest,
        now_secs: u64,
    ) -> DurableReplayResult<DurableReplayOutcome> {
        if request.identity.expires_at() < now_secs {
            return Err(DurableReplayError::Expired);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| DurableReplayError::StoreUnavailable)?;
        if state.last_observed_secs.is_some_and(|last| now_secs < last) {
            return Err(DurableReplayError::ClockRollback);
        }
        state.last_observed_secs = Some(now_secs);
        state
            .entries
            .retain(|_, (_, expires_at)| *expires_at >= now_secs);
        let identity_digest = request.identity.digest()?;
        if let Some((request_digest, _expires_at)) = state.entries.get(&identity_digest) {
            if *request_digest == request.request_digest() {
                return Ok(DurableReplayOutcome::AlreadyConsumedSameRequest);
            }
            return Ok(DurableReplayOutcome::ConflictingRequest);
        }
        state.entries.insert(
            identity_digest,
            (request.request_digest(), request.identity.expires_at()),
        );
        Ok(DurableReplayOutcome::Consumed)
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
struct FixtureClock {
    now_secs: u64,
}

#[cfg(test)]
impl TrustedClock for FixtureClock {
    fn now_secs(&self) -> Result<u64, TrustError> {
        Ok(self.now_secs)
    }
}

#[cfg(test)]
struct SequenceClock {
    observations: Mutex<VecDeque<Result<u64, TrustError>>>,
}

#[cfg(test)]
impl SequenceClock {
    fn new(observations: impl IntoIterator<Item = Result<u64, TrustError>>) -> Self {
        Self {
            observations: Mutex::new(observations.into_iter().collect()),
        }
    }
}

#[cfg(test)]
impl TrustedClock for SequenceClock {
    fn now_secs(&self) -> Result<u64, TrustError> {
        self.observations
            .lock()
            .map_err(|_| TrustError::ClockUnavailable)?
            .pop_front()
            .unwrap_or(Err(TrustError::ClockUnavailable))
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
struct CountingStore {
    calls: AtomicUsize,
}

#[cfg(test)]
impl DurableReplayStore for CountingStore {
    fn consume_once(
        &self,
        _request: &DurableReplayRequest,
        _now_secs: u64,
    ) -> DurableReplayResult<DurableReplayOutcome> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(DurableReplayOutcome::Consumed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::trust::{
        test_fixture_attestation_result, test_fixture_attestation_result_with_window,
        RevocationStatus, TcbStatus,
    };
    use std::thread;

    fn identity() -> DurableReplayIdentity {
        DurableReplayIdentity::new(
            "provider",
            "profile",
            ProofKind::Tee,
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            "SIGN",
            "audience",
            [5; 32],
            [6; 32],
            [7; 32],
            [8; 32],
            200,
        )
        .expect("identity")
    }

    #[test]
    fn identity_canonical_encoding_binds_every_field() {
        let base = identity();
        let base_digest = base.digest().expect("digest");
        let variants = [
            DurableReplayIdentity::new(
                "other",
                "profile",
                ProofKind::Tee,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                "SIGN",
                "audience",
                [5; 32],
                [6; 32],
                [7; 32],
                [8; 32],
                200,
            ),
            DurableReplayIdentity::new(
                "provider",
                "other",
                ProofKind::Tee,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                "SIGN",
                "audience",
                [5; 32],
                [6; 32],
                [7; 32],
                [8; 32],
                200,
            ),
            DurableReplayIdentity::new(
                "provider",
                "profile",
                ProofKind::Fido,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                "SIGN",
                "audience",
                [5; 32],
                [6; 32],
                [7; 32],
                [8; 32],
                200,
            ),
            DurableReplayIdentity::new(
                "provider",
                "profile",
                ProofKind::Tee,
                [9; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                "SIGN",
                "audience",
                [5; 32],
                [6; 32],
                [7; 32],
                [8; 32],
                200,
            ),
            DurableReplayIdentity::new(
                "provider",
                "profile",
                ProofKind::Tee,
                [1; 32],
                [9; 32],
                [3; 32],
                [4; 32],
                "SIGN",
                "audience",
                [5; 32],
                [6; 32],
                [7; 32],
                [8; 32],
                200,
            ),
            DurableReplayIdentity::new(
                "provider",
                "profile",
                ProofKind::Tee,
                [1; 32],
                [2; 32],
                [9; 32],
                [4; 32],
                "SIGN",
                "audience",
                [5; 32],
                [6; 32],
                [7; 32],
                [8; 32],
                200,
            ),
            DurableReplayIdentity::new(
                "provider",
                "profile",
                ProofKind::Tee,
                [1; 32],
                [2; 32],
                [3; 32],
                [9; 32],
                "SIGN",
                "audience",
                [5; 32],
                [6; 32],
                [7; 32],
                [8; 32],
                200,
            ),
            DurableReplayIdentity::new(
                "provider",
                "profile",
                ProofKind::Tee,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                "OTHER",
                "audience",
                [5; 32],
                [6; 32],
                [7; 32],
                [8; 32],
                200,
            ),
            DurableReplayIdentity::new(
                "provider",
                "profile",
                ProofKind::Tee,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                "SIGN",
                "other",
                [5; 32],
                [6; 32],
                [7; 32],
                [8; 32],
                200,
            ),
            DurableReplayIdentity::new(
                "provider",
                "profile",
                ProofKind::Tee,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                "SIGN",
                "audience",
                [9; 32],
                [6; 32],
                [7; 32],
                [8; 32],
                200,
            ),
            DurableReplayIdentity::new(
                "provider",
                "profile",
                ProofKind::Tee,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                "SIGN",
                "audience",
                [5; 32],
                [9; 32],
                [7; 32],
                [8; 32],
                200,
            ),
            DurableReplayIdentity::new(
                "provider",
                "profile",
                ProofKind::Tee,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                "SIGN",
                "audience",
                [5; 32],
                [6; 32],
                [9; 32],
                [8; 32],
                200,
            ),
            DurableReplayIdentity::new(
                "provider",
                "profile",
                ProofKind::Tee,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                "SIGN",
                "audience",
                [5; 32],
                [6; 32],
                [7; 32],
                [9; 32],
                200,
            ),
            DurableReplayIdentity::new(
                "provider",
                "profile",
                ProofKind::Tee,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                "SIGN",
                "audience",
                [5; 32],
                [6; 32],
                [7; 32],
                [8; 32],
                201,
            ),
        ];
        for variant in variants {
            assert_ne!(
                variant.expect("identity").digest().expect("digest"),
                base_digest
            );
        }
    }

    #[test]
    fn idempotency_key_is_bounded_and_distinct_from_identity() {
        assert_eq!(
            IdempotencyKey::new(Vec::new()),
            Err(DurableReplayError::InvalidPayload)
        );
        assert_eq!(
            IdempotencyKey::new(vec![1; MAX_IDEMPOTENCY_KEY_BYTES + 1]),
            Err(DurableReplayError::InvalidPayload)
        );
        let first =
            DurableReplayRequest::new(identity(), IdempotencyKey::new(vec![1]).expect("key"))
                .expect("request");
        let second =
            DurableReplayRequest::new(identity(), IdempotencyKey::new(vec![2]).expect("key"))
                .expect("request");
        assert_ne!(first.request_digest(), second.request_digest());
        assert_ne!(
            first.identity().subject_digest(),
            first.idempotency_key().digest()
        );
    }

    #[test]
    fn fake_store_is_consumed_idempotent_conflicting_and_atomic() {
        let store = Arc::new(InMemoryDurableReplayStore::default());
        let first =
            DurableReplayRequest::new(identity(), IdempotencyKey::new(vec![1]).expect("key"))
                .expect("request");
        assert_eq!(
            store.consume_once(&first, 100),
            Ok(DurableReplayOutcome::Consumed)
        );
        assert_eq!(
            store.consume_once(&first, 100),
            Ok(DurableReplayOutcome::AlreadyConsumedSameRequest)
        );
        let conflict =
            DurableReplayRequest::new(identity(), IdempotencyKey::new(vec![2]).expect("key"))
                .expect("request");
        assert_eq!(
            store.consume_once(&conflict, 100),
            Ok(DurableReplayOutcome::ConflictingRequest)
        );

        let concurrent_store = Arc::new(InMemoryDurableReplayStore::default());
        let request = Arc::new(first);
        let mut handles = Vec::new();
        for _ in 0..16 {
            let store = Arc::clone(&concurrent_store);
            let request = Arc::clone(&request);
            handles.push(thread::spawn(move || {
                store.consume_once(&request, 100).expect("store")
            }));
        }
        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == DurableReplayOutcome::Consumed)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == DurableReplayOutcome::AlreadyConsumedSameRequest)
                .count(),
            15
        );
    }

    #[test]
    fn wrapper_authorizes_only_consumed_or_confirmed_idempotent() {
        let result = test_fixture_attestation_result(100, RevocationStatus::Good, TcbStatus::Good);
        let store = Arc::new(InMemoryDurableReplayStore::default());
        let authorizer =
            DurableReplayAuthorizer::new(store, Arc::new(FixtureClock { now_secs: 100 }));
        let first = authorizer
            .consume_once(&result, IdempotencyKey::new(vec![1]).expect("key"))
            .expect("authorization");
        assert_eq!(first.outcome(), DurableReplayOutcome::Consumed);
        let retry = authorizer
            .consume_once(&result, IdempotencyKey::new(vec![1]).expect("key"))
            .expect("retry");
        assert_eq!(
            retry.outcome(),
            DurableReplayOutcome::AlreadyConsumedSameRequest
        );
        assert!(retry.is_idempotent_retry());
        assert_eq!(
            authorizer.consume_once(&result, IdempotencyKey::new(vec![2]).expect("key")),
            Err(DurableReplayError::ConflictingRequest)
        );
    }

    #[test]
    fn unavailable_store_status_and_non_good_result_fail_closed() {
        let result = test_fixture_attestation_result(100, RevocationStatus::Good, TcbStatus::Good);
        let unavailable = DurableReplayAuthorizer::new(
            Arc::new(UnavailableDurableReplayStore),
            Arc::new(FixtureClock { now_secs: 100 }),
        );
        assert_eq!(
            unavailable.consume_once(&result, IdempotencyKey::new(vec![1]).expect("key")),
            Err(DurableReplayError::StoreUnavailable)
        );
        let revoked =
            test_fixture_attestation_result(100, RevocationStatus::Revoked, TcbStatus::Good);
        let store = Arc::new(InMemoryDurableReplayStore::default());
        let authorizer =
            DurableReplayAuthorizer::new(store, Arc::new(FixtureClock { now_secs: 100 }));
        assert_eq!(
            authorizer.consume_once(&revoked, IdempotencyKey::new(vec![1]).expect("key")),
            Err(DurableReplayError::NotAuthorizable)
        );
    }

    #[test]
    fn expiry_and_clock_rollback_fail_closed() {
        let result = test_fixture_attestation_result(100, RevocationStatus::Good, TcbStatus::Good);
        let store = Arc::new(InMemoryDurableReplayStore::default());
        let expired = DurableReplayAuthorizer::new(
            store,
            Arc::new(FixtureClock {
                now_secs: result.expires_at() + 1,
            }),
        );
        assert_eq!(
            expired.consume_once(&result, IdempotencyKey::new(vec![1]).expect("key")),
            Err(DurableReplayError::NotAuthorizable)
        );

        let store = Arc::new(InMemoryDurableReplayStore::default());
        let request =
            DurableReplayRequest::new(identity(), IdempotencyKey::new(vec![1]).expect("key"))
                .expect("request");
        assert_eq!(
            store.consume_once(&request, 100),
            Ok(DurableReplayOutcome::Consumed)
        );
        assert_eq!(
            store.consume_once(&request, 99),
            Err(DurableReplayError::ClockRollback)
        );
        assert_eq!(
            store.consume_once(&request, 201),
            Err(DurableReplayError::Expired)
        );
    }

    #[test]
    fn authorizer_rejects_expiry_and_rollback_before_store_invocation() {
        let result = test_fixture_attestation_result_with_window(100, 200, 100);
        let store = Arc::new(CountingStore::default());
        let clock = Arc::new(SequenceClock::new([Ok(199), Ok(201), Ok(150)]));
        let authorizer = DurableReplayAuthorizer::new(store.clone(), clock);
        let key = || IdempotencyKey::new(vec![1]).expect("key");

        assert_eq!(
            authorizer.consume_once(&result, key()),
            Ok(DurableReplayAuthorization {
                identity_digest: authorizer
                    .identity_for(&result)
                    .expect("identity")
                    .digest()
                    .expect("digest"),
                idempotency_key_digest: key().digest(),
                outcome: DurableReplayOutcome::Consumed,
                expires_at: 200,
            })
        );
        assert_eq!(
            authorizer.consume_once(&result, key()),
            Err(DurableReplayError::NotAuthorizable)
        );
        assert_eq!(
            authorizer.consume_once(&result, key()),
            Err(DurableReplayError::ClockRollback)
        );
        assert_eq!(store.calls.load(Ordering::Relaxed), 1);

        let future_result = test_fixture_attestation_result_with_window(201, 300, 201);
        let future_store = Arc::new(CountingStore::default());
        let future_authorizer = DurableReplayAuthorizer::new(
            future_store.clone(),
            Arc::new(FixtureClock { now_secs: 200 }),
        );
        assert_eq!(
            future_authorizer.consume_once(&future_result, key()),
            Err(DurableReplayError::NotAuthorizable)
        );
        assert_eq!(future_store.calls.load(Ordering::Relaxed), 0);

        let clock_error_store = Arc::new(CountingStore::default());
        let clock_error_authorizer = DurableReplayAuthorizer::new(
            clock_error_store.clone(),
            Arc::new(SequenceClock::new([Err(TrustError::ClockUnavailable)])),
        );
        assert_eq!(
            clock_error_authorizer.consume_once(&result, key()),
            Err(DurableReplayError::ClockUnavailable)
        );
        assert_eq!(clock_error_store.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn forward_time_recovers_after_rejected_rollback() {
        let result = test_fixture_attestation_result_with_window(100, 300, 100);
        let store = Arc::new(CountingStore::default());
        let authorizer = DurableReplayAuthorizer::new(
            store.clone(),
            Arc::new(SequenceClock::new([Ok(199), Ok(150), Ok(201)])),
        );
        let key = || IdempotencyKey::new(vec![9]).expect("key");
        assert_eq!(
            authorizer
                .consume_once(&result, key())
                .expect("first consume")
                .outcome(),
            DurableReplayOutcome::Consumed
        );
        assert_eq!(
            authorizer.consume_once(&result, key()),
            Err(DurableReplayError::ClockRollback)
        );
        assert_eq!(
            authorizer
                .consume_once(&result, key())
                .expect("forward recovery")
                .outcome(),
            DurableReplayOutcome::Consumed
        );
        assert_eq!(store.calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn no_raw_evidence_enters_identity_or_audit() {
        let result = test_fixture_attestation_result(100, RevocationStatus::Good, TcbStatus::Good);
        let identity = DurableReplayIdentity::from_attestation_result(&result).expect("identity");
        let debug = format!("{identity:?}");
        assert!(!debug.contains("fixture-attestation-evidence"));
        let audit = serde_json::to_string(&result.audit_metadata()).expect("audit");
        assert!(!audit.contains("fixture-attestation-evidence"));
        assert!(!audit.contains("fixture-audience"));
    }
}
