use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplayGuardError {
    #[error("replay key has already been recorded")]
    Duplicate,
    #[error("replay guard capacity is saturated")]
    CapacitySaturated,
    #[error("replay guard state is unavailable")]
    LockPoisoned,
}

#[derive(Debug)]
pub struct ReplayGuard {
    entries: Mutex<HashMap<String, u64>>,
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
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ReplayGuardError::LockPoisoned)?;

        Self::prune_expired_entries(&mut entries, self.ttl_secs, now_secs);

        if entries.contains_key(key) {
            return Err(ReplayGuardError::Duplicate);
        }

        if entries.len() >= self.max_entries {
            return Err(ReplayGuardError::CapacitySaturated);
        }

        entries.insert(key.to_string(), now_secs);
        Ok(())
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
        let requested = keys
            .into_iter()
            .map(|key| key.as_ref().to_string())
            .collect::<Vec<_>>();

        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ReplayGuardError::LockPoisoned)?;

        Self::prune_expired_entries(&mut entries, self.ttl_secs, now_secs);

        let mut new_keys = std::collections::HashSet::with_capacity(requested.len());
        for key in &requested {
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

        for key in requested {
            entries.insert(key, now_secs);
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

    fn prune_expired_entries(entries: &mut HashMap<String, u64>, ttl_secs: u64, now_secs: u64) {
        entries.retain(|_, seen_at| {
            // Keep entries from the future until the clock catches up. A clock
            // rollback must never make a live replay key disappear.
            match now_secs.checked_sub(*seen_at) {
                Some(age_secs) => age_secs <= ttl_secs,
                None => true,
            }
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
}
