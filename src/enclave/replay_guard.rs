use std::collections::HashMap;
use std::sync::Mutex;

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
            max_entries: max_entries.max(1),
        }
    }

    /// Checks whether a replay key has already been seen in the active time window.
    /// Returns `true` if the key is accepted and recorded, `false` if rejected.
    pub fn check_and_record(&self, key: &str, now_secs: u64) -> bool {
        let mut entries = match self.entries.lock() {
            Ok(entries) => entries,
            Err(_) => return false,
        };

        Self::prune_expired_entries(&mut entries, self.ttl_secs, now_secs);

        if entries.contains_key(key) {
            return false;
        }

        entries.insert(key.to_string(), now_secs);
        Self::enforce_entry_limit(&mut entries, self.max_entries);

        true
    }

    fn prune_expired_entries(entries: &mut HashMap<String, u64>, ttl_secs: u64, now_secs: u64) {
        entries.retain(|_, seen_at| now_secs.saturating_sub(*seen_at) <= ttl_secs);
    }

    fn enforce_entry_limit(entries: &mut HashMap<String, u64>, max_entries: usize) {
        if entries.len() <= max_entries {
            return;
        }

        let mut oldest_entries: Vec<(String, u64)> = entries
            .iter()
            .map(|(key, seen_at)| (key.clone(), *seen_at))
            .collect();
        oldest_entries.sort_by_key(|(_, seen_at)| *seen_at);

        let excess_entries = entries.len() - max_entries;
        for (key, _) in oldest_entries.into_iter().take(excess_entries) {
            entries.remove(&key);
        }
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
    fn evicts_oldest_entries_when_capacity_is_exceeded() {
        let guard = ReplayGuard::new(300, 2);

        assert!(guard.check_and_record("attestation-1", 100));
        assert!(guard.check_and_record("attestation-2", 101));
        assert!(guard.check_and_record("attestation-3", 102));

        // `attestation-1` should have been evicted as the oldest key.
        assert!(guard.check_and_record("attestation-1", 103));

        // Capacity pressure keeps evicting oldest entries, so `attestation-2`
        // is eventually accepted again after being aged out.
        assert!(guard.check_and_record("attestation-2", 104));
    }
}
