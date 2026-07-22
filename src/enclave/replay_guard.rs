use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

/// Maximum number of replay keys accepted by one atomic reservation.
pub const MAX_REPLAY_BATCH_KEYS: usize = 128;
/// Maximum UTF-8 byte length of one replay key.
pub const MAX_REPLAY_KEY_BYTES: usize = 512;
/// Version for the complete provider-neutral replay binding.
pub const REPLAY_BINDING_VERSION: u16 = 1;
/// Domain separator for complete replay bindings.
pub const REPLAY_BINDING_DOMAIN: &str = "CONXIAN-REPLAY-BINDING/v1";

const MAX_BINDING_IDENTIFIER_BYTES: usize = 256;
const MAX_BINDING_NONCE_BYTES: usize = 128;
const MAX_BINDING_KEY_IDENTITY_BYTES: usize = 512;

fn validate_binding_identifier(value: &str) -> Result<(), ReplayBindingError> {
    if value.is_empty()
        || value.len() > MAX_BINDING_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ReplayBindingError::InvalidIdentifier);
    }
    Ok(())
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ReplayBindingError> {
    let length = u32::try_from(value.len()).map_err(|_| ReplayBindingError::OversizedInput)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn hash_binding_component(label: &str, value: &[u8]) -> Result<[u8; 32], ReplayBindingError> {
    let mut canonical = Vec::new();
    append_len_prefixed(&mut canonical, REPLAY_BINDING_DOMAIN.as_bytes())?;
    canonical.extend_from_slice(&REPLAY_BINDING_VERSION.to_be_bytes());
    append_len_prefixed(&mut canonical, label.as_bytes())?;
    append_len_prefixed(&mut canonical, value)?;
    Ok(Sha256::digest(canonical).into())
}

/// Construction failures for the canonical replay binding. Raw nonce, key
/// identity, and evidence bytes are hashed and never retained by the binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplayBindingError {
    #[error("replay binding identifier is invalid")]
    InvalidIdentifier,
    #[error("replay binding input is empty")]
    EmptyInput,
    #[error("replay binding input exceeds its bound")]
    OversizedInput,
}

/// Complete domain-separated replay binding for provider-backed authorization.
///
/// The binding covers provider, proof subject/mechanism, nonce, operation,
/// purpose, policy digest, key identity, evidence digest, and optional proof
/// and audience identifiers. Only fixed-size digests of nonce, key identity,
/// and evidence cross the storage boundary.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ReplayBinding {
    provider: String,
    proof_subject: String,
    proof_mechanism: String,
    nonce_digest: [u8; 32],
    operation_digest: [u8; 32],
    purpose: String,
    policy_digest: [u8; 32],
    key_identity_digest: [u8; 32],
    evidence_digest: [u8; 32],
    proof_id: Option<String>,
    audience: Option<String>,
}

impl std::fmt::Debug for ReplayBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReplayBinding")
            .field("digest", &self.digest().ok())
            .field("provider", &self.provider)
            .field("proof_subject", &self.proof_subject)
            .field("proof_mechanism", &self.proof_mechanism)
            .field("nonce_digest", &self.nonce_digest)
            .field("operation_digest", &self.operation_digest)
            .field("purpose", &self.purpose)
            .field("policy_digest", &self.policy_digest)
            .field("key_identity_digest", &self.key_identity_digest)
            .field("evidence_digest", &self.evidence_digest)
            .field("proof_id", &self.proof_id)
            .field("audience", &self.audience)
            .finish()
    }
}

impl ReplayBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: impl Into<String>,
        proof_subject: impl Into<String>,
        proof_mechanism: impl Into<String>,
        nonce: &[u8],
        operation_digest: [u8; 32],
        purpose: impl Into<String>,
        policy_digest: [u8; 32],
        key_identity: &[u8],
        evidence_digest: [u8; 32],
        proof_id: Option<impl Into<String>>,
        audience: Option<impl Into<String>>,
    ) -> Result<Self, ReplayBindingError> {
        let provider = provider.into();
        let proof_subject = proof_subject.into();
        let proof_mechanism = proof_mechanism.into();
        let purpose = purpose.into();
        let proof_id = proof_id.map(Into::into);
        let audience = audience.map(Into::into);
        validate_binding_identifier(&provider)?;
        validate_binding_identifier(&proof_subject)?;
        validate_binding_identifier(&proof_mechanism)?;
        validate_binding_identifier(&purpose)?;
        if let Some(proof_id) = &proof_id {
            validate_binding_identifier(proof_id)?;
        }
        if let Some(audience) = &audience {
            validate_binding_identifier(audience)?;
        }
        if nonce.is_empty() || key_identity.is_empty() {
            return Err(ReplayBindingError::EmptyInput);
        }
        if nonce.len() > MAX_BINDING_NONCE_BYTES {
            return Err(ReplayBindingError::OversizedInput);
        }
        if key_identity.len() > MAX_BINDING_KEY_IDENTITY_BYTES {
            return Err(ReplayBindingError::OversizedInput);
        }

        Ok(Self {
            provider,
            proof_subject,
            proof_mechanism,
            nonce_digest: hash_binding_component("nonce", nonce)?,
            operation_digest,
            purpose,
            policy_digest,
            key_identity_digest: hash_binding_component("key-identity", key_identity)?,
            evidence_digest,
            proof_id,
            audience,
        })
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn proof_subject(&self) -> &str {
        &self.proof_subject
    }

    pub fn proof_mechanism(&self) -> &str {
        &self.proof_mechanism
    }

    pub fn nonce_digest(&self) -> &[u8; 32] {
        &self.nonce_digest
    }

    pub fn operation_digest(&self) -> &[u8; 32] {
        &self.operation_digest
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    pub fn policy_digest(&self) -> &[u8; 32] {
        &self.policy_digest
    }

    pub fn key_identity_digest(&self) -> &[u8; 32] {
        &self.key_identity_digest
    }

    pub fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence_digest
    }

    pub fn proof_id(&self) -> Option<&str> {
        self.proof_id.as_deref()
    }

    pub fn audience(&self) -> Option<&str> {
        self.audience.as_deref()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReplayBindingError> {
        let mut output = Vec::new();
        append_len_prefixed(&mut output, REPLAY_BINDING_DOMAIN.as_bytes())?;
        output.extend_from_slice(&REPLAY_BINDING_VERSION.to_be_bytes());
        append_len_prefixed(&mut output, self.provider.as_bytes())?;
        append_len_prefixed(&mut output, self.proof_subject.as_bytes())?;
        append_len_prefixed(&mut output, self.proof_mechanism.as_bytes())?;
        output.extend_from_slice(&self.nonce_digest);
        output.extend_from_slice(&self.operation_digest);
        append_len_prefixed(&mut output, self.purpose.as_bytes())?;
        output.extend_from_slice(&self.policy_digest);
        output.extend_from_slice(&self.key_identity_digest);
        output.extend_from_slice(&self.evidence_digest);
        match &self.proof_id {
            Some(proof_id) => {
                output.push(1);
                append_len_prefixed(&mut output, proof_id.as_bytes())?;
            }
            None => output.push(0),
        }
        match &self.audience {
            Some(audience) => {
                output.push(1);
                append_len_prefixed(&mut output, audience.as_bytes())?;
            }
            None => output.push(0),
        }
        Ok(output)
    }

    pub fn digest(&self) -> Result<[u8; 32], ReplayBindingError> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }

    pub fn as_key(&self) -> Result<String, ReplayBindingError> {
        Ok(format!(
            "{}:{}",
            REPLAY_BINDING_DOMAIN,
            hex::encode(self.digest()?)
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_component_digests(
        provider: impl Into<String>,
        proof_subject: impl Into<String>,
        proof_mechanism: impl Into<String>,
        nonce_digest: [u8; 32],
        operation_digest: [u8; 32],
        purpose: impl Into<String>,
        policy_digest: [u8; 32],
        key_identity_digest: [u8; 32],
        evidence_digest: [u8; 32],
        proof_id: Option<String>,
        audience: Option<String>,
    ) -> Result<Self, ReplayBindingError> {
        let provider = provider.into();
        let proof_subject = proof_subject.into();
        let proof_mechanism = proof_mechanism.into();
        let purpose = purpose.into();
        validate_binding_identifier(&provider)?;
        validate_binding_identifier(&proof_subject)?;
        validate_binding_identifier(&proof_mechanism)?;
        validate_binding_identifier(&purpose)?;
        if let Some(proof_id) = &proof_id {
            validate_binding_identifier(proof_id)?;
        }
        if let Some(audience) = &audience {
            validate_binding_identifier(audience)?;
        }
        Ok(Self {
            provider,
            proof_subject,
            proof_mechanism,
            nonce_digest,
            operation_digest,
            purpose,
            policy_digest,
            key_identity_digest,
            evidence_digest,
            proof_id,
            audience,
        })
    }
}

/// A retention horizon paired with one complete binding. Only the binding
/// digest is retained by the replay store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayReservation {
    binding_digest: [u8; 32],
    retain_until: u64,
}

impl ReplayReservation {
    pub fn new(binding: &ReplayBinding, retain_until: u64) -> Result<Self, ReplayBindingError> {
        Ok(Self {
            binding_digest: binding.digest()?,
            retain_until,
        })
    }

    pub fn from_digest(binding_digest: [u8; 32], retain_until: u64) -> Self {
        Self {
            binding_digest,
            retain_until,
        }
    }

    pub fn binding_digest(&self) -> &[u8; 32] {
        &self.binding_digest
    }

    pub fn retain_until(&self) -> u64 {
        self.retain_until
    }

    fn has_valid_digest(&self) -> bool {
        self.binding_digest.iter().any(|byte| *byte != 0)
    }

    fn encoded_key(&self) -> String {
        format!(
            "{}:{}",
            REPLAY_BINDING_DOMAIN,
            hex::encode(self.binding_digest)
        )
    }
}

/// Whether a replay store can support production durability requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayStoreDurability {
    ProcessLocal,
    DurableProvider,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayConsumeOutcome {
    Accepted,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayBatchOutcome {
    accepted_count: usize,
}

impl ReplayBatchOutcome {
    pub fn accepted_count(self) -> usize {
        self.accepted_count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayBatchFailure {
    Duplicate,
    InvalidKey,
    InvalidRetention,
    CapacitySaturated,
    BackendUnavailable,
    TransactionIndeterminate,
    ClockRollback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplayStoreError {
    #[error("replay key is invalid")]
    InvalidKey,
    #[error("replay retention horizon is invalid or expired")]
    InvalidRetention,
    #[error("replay backend is unavailable")]
    BackendUnavailable,
    #[error("replay transaction outcome is indeterminate")]
    TransactionIndeterminate,
    #[error("replay clock moved backwards")]
    ClockRollback,
    #[error("replay capacity is saturated")]
    CapacitySaturated,
    #[error("replay backend state is unavailable")]
    LockPoisoned,
    #[error("atomic replay batch failed: {0:?}")]
    AtomicBatchFailure(ReplayBatchFailure),
}

/// Provider-neutral consume-once contract. Implementations must make batch
/// reservations atomic and must fail closed when the transaction result is
/// uncertain.
pub trait ReplayStore: Send + Sync {
    fn durability(&self) -> ReplayStoreDurability;

    fn consume_once(
        &self,
        reservation: &ReplayReservation,
        now_secs: u64,
    ) -> Result<ReplayConsumeOutcome, ReplayStoreError>;

    fn consume_once_batch(
        &self,
        reservations: &[ReplayReservation],
        now_secs: u64,
    ) -> Result<ReplayBatchOutcome, ReplayStoreError>;
}

/// Explicit unavailable backend used by production/provider boundaries until a
/// real durable implementation is integrated.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableReplayStore;

impl ReplayStore for UnavailableReplayStore {
    fn durability(&self) -> ReplayStoreDurability {
        ReplayStoreDurability::Unavailable
    }

    fn consume_once(
        &self,
        _reservation: &ReplayReservation,
        _now_secs: u64,
    ) -> Result<ReplayConsumeOutcome, ReplayStoreError> {
        Err(ReplayStoreError::BackendUnavailable)
    }

    fn consume_once_batch(
        &self,
        _reservations: &[ReplayReservation],
        _now_secs: u64,
    ) -> Result<ReplayBatchOutcome, ReplayStoreError> {
        Err(ReplayStoreError::BackendUnavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplayGuardError {
    #[error("replay key has already been recorded")]
    Duplicate,
    #[error("replay guard capacity is saturated")]
    CapacitySaturated,
    #[error("replay guard clock moved backwards")]
    ClockRollback,
    #[error("replay guard input is invalid")]
    InvalidInput,
    #[error("replay guard state is unavailable")]
    LockPoisoned,
}

#[derive(Debug, Clone, Copy)]
struct ReplayEntry {
    retain_until: u64,
}

#[derive(Debug, Default)]
struct ReplayState {
    entries: HashMap<String, ReplayEntry>,
    last_observed_secs: Option<u64>,
}

/// Process-local replay implementation retained for compatibility and local
/// containment tests. It is explicitly not durable, restart-safe, or
/// multi-replica production replay coordination.
#[derive(Debug)]
pub struct ReplayGuard {
    state: Mutex<ReplayState>,
    ttl_secs: u64,
    max_entries: usize,
}

impl ReplayGuard {
    pub fn new(ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            state: Mutex::new(ReplayState::default()),
            ttl_secs,
            // A zero-capacity guard is intentionally unusable. Keep the zero
            // value so every insertion fails closed instead of silently
            // becoming a one-entry guard.
            max_entries,
        }
    }

    /// Checks and records a key, returning the exact fail-closed outcome.
    pub fn try_check_and_record(&self, key: &str, now_secs: u64) -> Result<(), ReplayGuardError> {
        let retain_until = now_secs
            .checked_add(self.ttl_secs)
            .ok_or(ReplayGuardError::InvalidInput)?;
        self.try_check_and_record_batch_with_horizons([(key, retain_until)], now_secs)
    }

    /// Atomically checks and records a batch of keys under one lock.
    ///
    /// The entire batch is preflighted before any new replay entry is inserted.
    /// Duplicate keys within the batch, keys already present in the guard, and
    /// capacity saturation insert no new entries. A successful monotonic time
    /// observation can still advance the high-water mark and prune expired
    /// entries before one of those failures is returned. This guard is
    /// deliberately process-local; it is not a replacement for durable or
    /// distributed replay coordination.
    pub fn try_check_and_record_batch<I, K>(
        &self,
        keys: I,
        now_secs: u64,
    ) -> Result<(), ReplayGuardError>
    where
        I: IntoIterator<Item = K>,
        K: AsRef<str>,
    {
        let retain_until = now_secs
            .checked_add(self.ttl_secs)
            .ok_or(ReplayGuardError::InvalidInput)?;
        self.try_check_and_record_batch_with_horizons(
            keys.into_iter().map(|key| (key, retain_until)),
            now_secs,
        )
    }

    /// Atomically checks and records a batch with one absolute retention
    /// horizon per key. Existing callers can continue using
    /// [`Self::try_check_and_record_batch`] for the legacy fixed-TTL behavior.
    ///
    /// All key and batch bounds are checked while iterating, before the
    /// caller-owned input is collected. No new entry is inserted until every
    /// key, horizon, duplicate, and capacity check succeeds. After a valid
    /// non-rollback observation, high-water advancement and expiry pruning may
    /// persist even when duplicate or capacity validation rejects the batch.
    pub fn try_check_and_record_batch_with_horizons<I, K>(
        &self,
        keys: I,
        now_secs: u64,
    ) -> Result<(), ReplayGuardError>
    where
        I: IntoIterator<Item = (K, u64)>,
        K: AsRef<str>,
    {
        let mut requested = Vec::new();
        for (key, retain_until) in keys {
            if requested.len() >= MAX_REPLAY_BATCH_KEYS {
                return Err(ReplayGuardError::InvalidInput);
            }

            let key = key.as_ref();
            if key.is_empty() || key.len() > MAX_REPLAY_KEY_BYTES || retain_until < now_secs {
                return Err(ReplayGuardError::InvalidInput);
            }
            requested.push((key.to_string(), retain_until));
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| ReplayGuardError::LockPoisoned)?;

        if state
            .last_observed_secs
            .is_some_and(|last_observed_secs| now_secs < last_observed_secs)
        {
            return Err(ReplayGuardError::ClockRollback);
        }

        // Record every non-rollback observation before pruning or insertion.
        // This high-water mark intentionally survives entry eviction and also
        // survives duplicate/capacity failures, because the process has still
        // observed a valid forward timestamp.
        state.last_observed_secs = Some(now_secs);
        Self::prune_expired_entries(&mut state.entries, now_secs);

        let mut new_keys = std::collections::HashSet::with_capacity(requested.len());
        for (key, _) in &requested {
            if state.entries.contains_key(key) || !new_keys.insert(key) {
                return Err(ReplayGuardError::Duplicate);
            }
        }

        let resulting_len = state
            .entries
            .len()
            .checked_add(requested.len())
            .ok_or(ReplayGuardError::CapacitySaturated)?;
        if resulting_len > self.max_entries {
            return Err(ReplayGuardError::CapacitySaturated);
        }

        for (key, retain_until) in requested {
            state.entries.insert(key, ReplayEntry { retain_until });
        }

        Ok(())
    }

    /// Compatibility wrapper for callers that only need accepted/rejected.
    ///
    /// New security-sensitive callers should use [`Self::try_check_and_record`]
    /// so duplicate and saturation failures remain distinguishable.
    pub fn check_and_record(&self, key: &str, now_secs: u64) -> bool {
        self.try_check_and_record(key, now_secs).is_ok()
    }

    fn prune_expired_entries(entries: &mut HashMap<String, ReplayEntry>, now_secs: u64) {
        entries.retain(|_, entry| {
            // Retain through the inclusive horizon. A clock rollback also
            // keeps future-dated entries live until the clock catches up.
            now_secs <= entry.retain_until
        });
    }
}

impl ReplayStore for ReplayGuard {
    fn durability(&self) -> ReplayStoreDurability {
        ReplayStoreDurability::ProcessLocal
    }

    fn consume_once(
        &self,
        reservation: &ReplayReservation,
        now_secs: u64,
    ) -> Result<ReplayConsumeOutcome, ReplayStoreError> {
        if !reservation.has_valid_digest() {
            return Err(ReplayStoreError::InvalidKey);
        }
        if reservation.retain_until < now_secs {
            return Err(ReplayStoreError::InvalidRetention);
        }
        match self.try_check_and_record_batch_with_horizons(
            [(reservation.encoded_key(), reservation.retain_until)],
            now_secs,
        ) {
            Ok(()) => Ok(ReplayConsumeOutcome::Accepted),
            Err(ReplayGuardError::Duplicate) => Ok(ReplayConsumeOutcome::Duplicate),
            Err(ReplayGuardError::CapacitySaturated) => Err(ReplayStoreError::CapacitySaturated),
            Err(ReplayGuardError::ClockRollback) => Err(ReplayStoreError::ClockRollback),
            Err(ReplayGuardError::InvalidInput) => Err(ReplayStoreError::InvalidKey),
            Err(ReplayGuardError::LockPoisoned) => Err(ReplayStoreError::LockPoisoned),
        }
    }

    fn consume_once_batch(
        &self,
        reservations: &[ReplayReservation],
        now_secs: u64,
    ) -> Result<ReplayBatchOutcome, ReplayStoreError> {
        let requested = reservations
            .iter()
            .map(|reservation| {
                if !reservation.has_valid_digest() {
                    return Err(ReplayStoreError::AtomicBatchFailure(
                        ReplayBatchFailure::InvalidKey,
                    ));
                }
                if reservation.retain_until < now_secs {
                    return Err(ReplayStoreError::AtomicBatchFailure(
                        ReplayBatchFailure::InvalidRetention,
                    ));
                }
                Ok((reservation.encoded_key(), reservation.retain_until))
            })
            .collect::<Result<Vec<_>, ReplayStoreError>>()?;

        match self.try_check_and_record_batch_with_horizons(requested, now_secs) {
            Ok(()) => Ok(ReplayBatchOutcome {
                accepted_count: reservations.len(),
            }),
            Err(ReplayGuardError::Duplicate) => Err(ReplayStoreError::AtomicBatchFailure(
                ReplayBatchFailure::Duplicate,
            )),
            Err(ReplayGuardError::CapacitySaturated) => Err(ReplayStoreError::AtomicBatchFailure(
                ReplayBatchFailure::CapacitySaturated,
            )),
            Err(ReplayGuardError::ClockRollback) => Err(ReplayStoreError::ClockRollback),
            Err(ReplayGuardError::InvalidInput) => Err(ReplayStoreError::AtomicBatchFailure(
                ReplayBatchFailure::InvalidKey,
            )),
            Err(ReplayGuardError::LockPoisoned) => Err(ReplayStoreError::BackendUnavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ReplayBatchFailure, ReplayBinding, ReplayConsumeOutcome, ReplayGuard, ReplayReservation,
        ReplayStore, ReplayStoreDurability, ReplayStoreError, UnavailableReplayStore,
    };

    #[test]
    fn accepts_new_key() {
        let guard = ReplayGuard::new(300, 128);
        assert!(guard.check_and_record("attestation-1", 100));
    }

    #[test]
    fn rejects_duplicate_key_within_window() {
        let guard = ReplayGuard::new(300, 128);

        assert!(guard.check_and_record("attestation-1", 100));
        assert!(!guard.check_and_record("attestation-1", 120));
    }

    #[test]
    fn allows_key_reuse_after_ttl_expiry() {
        let guard = ReplayGuard::new(10, 128);

        assert!(guard.check_and_record("attestation-1", 100));
        assert!(guard.check_and_record("attestation-1", 111));
    }

    #[test]
    fn rejects_new_keys_when_capacity_is_saturated() {
        let guard = ReplayGuard::new(300, 2);

        assert!(guard.check_and_record("attestation-1", 100));
        assert!(guard.check_and_record("attestation-2", 101));
        assert_eq!(
            guard.try_check_and_record("attestation-3", 102),
            Err(super::ReplayGuardError::CapacitySaturated)
        );

        // Capacity pressure must never evict a still-live key.
        assert_eq!(
            guard.try_check_and_record("attestation-1", 103),
            Err(super::ReplayGuardError::Duplicate)
        );
        assert_eq!(
            guard.try_check_and_record("attestation-2", 103),
            Err(super::ReplayGuardError::Duplicate)
        );
    }

    #[test]
    fn capacity_becomes_available_only_after_expiry() {
        let guard = ReplayGuard::new(10, 2);

        assert!(guard.check_and_record("attestation-1", 100));
        assert!(guard.check_and_record("attestation-2", 101));
        assert_eq!(
            guard.try_check_and_record("attestation-3", 102),
            Err(super::ReplayGuardError::CapacitySaturated)
        );

        // Once both entries expire, a new key can be admitted.
        assert!(guard.check_and_record("attestation-3", 112));
    }

    #[test]
    fn zero_capacity_rejects_every_new_key() {
        let guard = ReplayGuard::new(300, 0);

        assert_eq!(
            guard.try_check_and_record("attestation-1", 100),
            Err(super::ReplayGuardError::CapacitySaturated)
        );
        assert!(!guard.check_and_record("attestation-2", 101));
    }

    #[test]
    fn batch_replay_is_atomic_on_duplicate() {
        let guard = ReplayGuard::new(300, 8);
        assert!(guard.check_and_record("existing", 100));

        assert_eq!(
            guard.try_check_and_record_batch(["new-a", "existing", "new-b"], 101),
            Err(super::ReplayGuardError::Duplicate)
        );
        assert_eq!(guard.try_check_and_record("new-a", 102), Ok(()));
        assert_eq!(guard.try_check_and_record("new-b", 102), Ok(()));
    }

    #[test]
    fn duplicate_failure_can_prune_expired_entries_without_inserting_new_keys() {
        let guard = ReplayGuard::new(1, 8);
        assert_eq!(
            guard.try_check_and_record_batch_with_horizons(
                [("expired", 110), ("existing", 200)],
                100,
            ),
            Ok(())
        );

        assert_eq!(
            guard.try_check_and_record_batch_with_horizons([("existing", 250)], 111),
            Err(super::ReplayGuardError::Duplicate)
        );
        // The valid forward observation pruned the expired key, but the
        // duplicate failure inserted no replacement entry.
        assert_eq!(guard.try_check_and_record("expired", 111), Ok(()));
        assert_eq!(
            guard.try_check_and_record("existing", 111),
            Err(super::ReplayGuardError::Duplicate)
        );
    }

    #[test]
    fn batch_replay_is_atomic_on_capacity_saturation() {
        let guard = ReplayGuard::new(300, 2);
        assert!(guard.check_and_record("existing", 100));

        assert_eq!(
            guard.try_check_and_record_batch(["new-a", "new-b"], 101),
            Err(super::ReplayGuardError::CapacitySaturated)
        );
        assert_eq!(guard.try_check_and_record("new-a", 102), Ok(()));
        assert_eq!(
            guard.try_check_and_record("new-b", 102),
            Err(super::ReplayGuardError::CapacitySaturated)
        );
    }

    #[test]
    fn horizon_aware_batch_retains_key_after_legacy_ttl() {
        let guard = ReplayGuard::new(1, 8);

        assert_eq!(
            guard.try_check_and_record_batch_with_horizons([("proof", 160)], 100,),
            Ok(())
        );
        assert_eq!(
            guard.try_check_and_record("proof", 102),
            Err(super::ReplayGuardError::Duplicate)
        );
        assert_eq!(guard.try_check_and_record("proof", 161), Ok(()));
    }

    #[test]
    fn bounded_batch_rejects_oversized_keys_before_recording() {
        let guard = ReplayGuard::new(300, 8);
        let oversized = "x".repeat(super::MAX_REPLAY_KEY_BYTES + 1);

        assert_eq!(
            guard.try_check_and_record(&oversized, 100),
            Err(super::ReplayGuardError::InvalidInput)
        );
        assert_eq!(guard.try_check_and_record("valid", 100), Ok(()));
    }

    #[test]
    fn horizon_batch_failure_does_not_partially_insert_keys() {
        let guard = ReplayGuard::new(300, 2);
        assert_eq!(
            guard.try_check_and_record_batch_with_horizons([("new-a", 200), ("new-b", 99)], 100,),
            Err(super::ReplayGuardError::InvalidInput)
        );
        assert_eq!(guard.try_check_and_record("new-a", 100), Ok(()));
        assert_eq!(guard.try_check_and_record("new-b", 100), Ok(()));
    }

    #[test]
    fn rejects_clock_rollback_after_horizon_pruning_without_reinsertion() {
        let guard = ReplayGuard::new(1, 8);

        assert_eq!(
            guard.try_check_and_record_batch_with_horizons([("proof", 110)], 100),
            Ok(())
        );
        // This forward observation prunes the proof entry while retaining the
        // monotonic high-water timestamp.
        assert_eq!(guard.try_check_and_record("advance", 111), Ok(()));

        assert_eq!(
            guard.try_check_and_record("proof", 105),
            Err(super::ReplayGuardError::ClockRollback)
        );
        // Forward recovery is allowed, and the rejected rollback did not
        // reinsert the pruned key.
        assert_eq!(guard.try_check_and_record("proof", 112), Ok(()));
    }

    fn binding_with(
        provider: &str,
        subject: &str,
        mechanism: &str,
        nonce: &[u8],
        operation: [u8; 32],
        purpose: &str,
        policy: [u8; 32],
        key_identity: &[u8],
        evidence: [u8; 32],
        proof_id: Option<&str>,
        audience: Option<&str>,
    ) -> ReplayBinding {
        ReplayBinding::new(
            provider,
            subject,
            mechanism,
            nonce,
            operation,
            purpose,
            policy,
            key_identity,
            evidence,
            proof_id,
            audience,
        )
        .expect("binding should be valid")
    }

    fn binding() -> ReplayBinding {
        binding_with(
            "aws.nitro",
            "subject-1",
            "quote-v1",
            b"nonce-1",
            [1; 32],
            "SETTLEMENT",
            [2; 32],
            b"key-id|derivation|public-key",
            [3; 32],
            Some("proof-1"),
            Some("conxian/settlement/v1"),
        )
    }

    #[test]
    fn canonical_binding_changes_for_every_security_dimension() {
        let base = binding().digest().expect("base digest");
        let variants = [
            binding_with(
                "android.keymint",
                "subject-1",
                "quote-v1",
                b"nonce-1",
                [1; 32],
                "SETTLEMENT",
                [2; 32],
                b"key-id|derivation|public-key",
                [3; 32],
                Some("proof-1"),
                Some("conxian/settlement/v1"),
            ),
            binding_with(
                "aws.nitro",
                "subject-2",
                "quote-v1",
                b"nonce-1",
                [1; 32],
                "SETTLEMENT",
                [2; 32],
                b"key-id|derivation|public-key",
                [3; 32],
                Some("proof-1"),
                Some("conxian/settlement/v1"),
            ),
            binding_with(
                "aws.nitro",
                "subject-1",
                "quote-v2",
                b"nonce-1",
                [1; 32],
                "SETTLEMENT",
                [2; 32],
                b"key-id|derivation|public-key",
                [3; 32],
                Some("proof-1"),
                Some("conxian/settlement/v1"),
            ),
            binding_with(
                "aws.nitro",
                "subject-1",
                "quote-v1",
                b"nonce-2",
                [1; 32],
                "SETTLEMENT",
                [2; 32],
                b"key-id|derivation|public-key",
                [3; 32],
                Some("proof-1"),
                Some("conxian/settlement/v1"),
            ),
            binding_with(
                "aws.nitro",
                "subject-1",
                "quote-v1",
                b"nonce-1",
                [4; 32],
                "SETTLEMENT",
                [2; 32],
                b"key-id|derivation|public-key",
                [3; 32],
                Some("proof-1"),
                Some("conxian/settlement/v1"),
            ),
            binding_with(
                "aws.nitro",
                "subject-1",
                "quote-v1",
                b"nonce-1",
                [1; 32],
                "AUTHORIZATION",
                [2; 32],
                b"key-id|derivation|public-key",
                [3; 32],
                Some("proof-1"),
                Some("conxian/settlement/v1"),
            ),
            binding_with(
                "aws.nitro",
                "subject-1",
                "quote-v1",
                b"nonce-1",
                [1; 32],
                "SETTLEMENT",
                [5; 32],
                b"key-id|derivation|public-key",
                [3; 32],
                Some("proof-1"),
                Some("conxian/settlement/v1"),
            ),
            binding_with(
                "aws.nitro",
                "subject-1",
                "quote-v1",
                b"nonce-1",
                [1; 32],
                "SETTLEMENT",
                [2; 32],
                b"different-key-identity",
                [3; 32],
                Some("proof-1"),
                Some("conxian/settlement/v1"),
            ),
            binding_with(
                "aws.nitro",
                "subject-1",
                "quote-v1",
                b"nonce-1",
                [1; 32],
                "SETTLEMENT",
                [2; 32],
                b"key-id|derivation|public-key",
                [6; 32],
                Some("proof-1"),
                Some("conxian/settlement/v1"),
            ),
            binding_with(
                "aws.nitro",
                "subject-1",
                "quote-v1",
                b"nonce-1",
                [1; 32],
                "SETTLEMENT",
                [2; 32],
                b"key-id|derivation|public-key",
                [3; 32],
                Some("proof-2"),
                Some("conxian/settlement/v1"),
            ),
            binding_with(
                "aws.nitro",
                "subject-1",
                "quote-v1",
                b"nonce-1",
                [1; 32],
                "SETTLEMENT",
                [2; 32],
                b"key-id|derivation|public-key",
                [3; 32],
                Some("proof-1"),
                Some("different-audience"),
            ),
        ];

        for variant in variants {
            assert_ne!(base, variant.digest().expect("variant digest"));
        }
    }

    #[test]
    fn replay_store_contract_is_atomic_and_secret_safe() {
        let guard = ReplayGuard::new(300, 8);
        assert_eq!(guard.durability(), ReplayStoreDurability::ProcessLocal);
        let reservation = ReplayReservation::new(&binding(), 500).expect("reservation");
        assert_eq!(
            guard.consume_once(&reservation, 100),
            Ok(ReplayConsumeOutcome::Accepted)
        );
        assert_eq!(
            guard.consume_once(&reservation, 101),
            Ok(ReplayConsumeOutcome::Duplicate)
        );

        let second_binding = binding_with(
            "aws.nitro",
            "subject-2",
            "quote-v1",
            b"nonce-2",
            [4; 32],
            "SETTLEMENT",
            [2; 32],
            b"key-2",
            [5; 32],
            Some("proof-2"),
            Some("conxian/settlement/v1"),
        );
        let second = ReplayReservation::new(&second_binding, 500).expect("second reservation");
        assert_eq!(
            guard.consume_once_batch(&[reservation.clone(), second.clone()], 102),
            Err(ReplayStoreError::AtomicBatchFailure(
                ReplayBatchFailure::Duplicate
            ))
        );
        assert_eq!(
            guard.consume_once(&second, 102),
            Ok(ReplayConsumeOutcome::Accepted)
        );

        let debug = format!("{:?}", binding());
        assert!(!debug.contains("key-id|derivation|public-key"));
        assert!(!debug.contains("nonce-1"));
        assert!(!debug.contains("raw-evidence"));
        assert!(!binding().as_key().expect("key").contains("nonce-1"));
    }

    #[test]
    fn replay_store_rejects_invalid_retention_and_clock_rollback() {
        let guard = ReplayGuard::new(300, 8);
        let reservation = ReplayReservation::new(&binding(), 99).expect("reservation");
        assert_eq!(
            guard.consume_once(&reservation, 100),
            Err(ReplayStoreError::InvalidRetention)
        );
        let valid = ReplayReservation::new(&binding(), 500).expect("valid reservation");
        assert_eq!(
            guard.consume_once(&valid, 200),
            Ok(ReplayConsumeOutcome::Accepted)
        );
        assert_eq!(
            guard.consume_once(&ReplayReservation::from_digest([8; 32], 600), 199),
            Err(ReplayStoreError::ClockRollback)
        );
        assert_eq!(
            guard.consume_once(&ReplayReservation::from_digest([0; 32], 600), 201),
            Err(ReplayStoreError::InvalidKey)
        );
    }

    #[test]
    fn unavailable_backend_is_explicit() {
        let backend = UnavailableReplayStore;
        let reservation = ReplayReservation::new(&binding(), 500).expect("reservation");
        assert_eq!(backend.durability(), ReplayStoreDurability::Unavailable);
        assert_eq!(
            backend.consume_once(&reservation, 100),
            Err(ReplayStoreError::BackendUnavailable)
        );
        assert_eq!(
            backend.consume_once_batch(&[reservation], 100),
            Err(ReplayStoreError::BackendUnavailable)
        );
    }
}
