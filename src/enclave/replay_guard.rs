use std::collections::HashMap;
use std::sync::Mutex;

/// Maximum number of replay keys accepted by one atomic reservation.
pub const MAX_REPLAY_BATCH_KEYS: usize = 128;
/// Maximum UTF-8 byte length of one replay key.
pub const MAX_REPLAY_KEY_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplayGuardError {
    #[error("replay key has already been recorded")]
    Duplicate,
    #[error("replay guard capacity is saturated")]
    CapacitySaturated,
    #[error("replay guard input is invalid")]
    InvalidInput,
    #[error("replay guard state is unavailable")]
    LockPoisoned,
}

#[derive(Debug, Clone, Copy)]
struct ReplayEntry {
    retain_until: u64,
}

#[derive(Debug)]
pub struct ReplayGuard {
    entries: Mutex<HashMap<String, ReplayEntry>>,
    ttl_secs: u64,
    max_entries: usize,
}

impl ReplayGuard {
    pub fn new(ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
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
    /// The entire batch is preflighted before any entry is inserted. Duplicate
    /// keys within the batch, keys already present in the guard, lock failure,
    /// and capacity saturation all leave the guard unchanged. This guard is
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
    /// caller-owned input is collected. No entry is inserted until every key,
    /// horizon, duplicate, and capacity check succeeds.
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

        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ReplayGuardError::LockPoisoned)?;

        Self::prune_expired_entries(&mut entries, now_secs);

        let mut new_keys = std::collections::HashSet::with_capacity(requested.len());
        for (key, _) in &requested {
            if entries.contains_key(key) || !new_keys.insert(key) {
                return Err(ReplayGuardError::Duplicate);
            }
        }

        let resulting_len = entries
            .len()
            .checked_add(requested.len())
            .ok_or(ReplayGuardError::CapacitySaturated)?;
        if resulting_len > self.max_entries {
            return Err(ReplayGuardError::CapacitySaturated);
        }

        for (key, retain_until) in requested {
            entries.insert(key, ReplayEntry { retain_until });
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

#[cfg(test)]
mod tests {
    use super::ReplayGuard;

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
}
