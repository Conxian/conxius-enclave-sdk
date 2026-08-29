//! Durable file-backed `ReplayStore` adapter (reference implementation).
//!
//! Implements the provider-neutral consume-once contract with
//! `ReplayStoreDurability::DurableProvider`. Each consumed binding is a
//! committed, `fsync`-ed record file, and the anti-rollback high-water clock is
//! persisted, so consumption survives process restart. `O_EXCL` file creation
//! provides the atomic conditional-write primitive; a `Mutex` serializes batch
//! and single-key operations within a process for atomic all-or-nothing batch
//! semantics.
//!
//! This is a local/test reference backend. True multi-replica, multi-region
//! crash-atomic transactions remain the responsibility of a distributed backend
//! (e.g. DynamoDB `TransactWriteItems` or PostgreSQL transactions) and are
//! outside this crate.

use crate::enclave::replay_guard::{
    ReplayBatchFailure, ReplayBatchOutcome, ReplayConsumeOutcome, ReplayReservation, ReplayStore,
    ReplayStoreDurability, ReplayStoreError,
};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

const RECORD_MAGIC: [u8; 4] = *b"RPLY";
const RECORD_VERSION: u16 = 1;
const RECORD_SIZE: usize = 4 + 2 + 8;
const CLOCK_FILE_NAME: &str = ".high-water-clock";

enum RecordState {
    Absent,
    Present(u64),
    Corrupt,
}

/// A filesystem-backed durable `ReplayStore`.
pub struct DurableFileReplayStore {
    state: Mutex<FileState>,
}

struct FileState {
    dir: PathBuf,
    high_water_secs: u64,
}

fn record_path(dir: &Path, binding_digest: &[u8; 32]) -> PathBuf {
    dir.join(hex::encode(binding_digest))
}

fn encode_record(retain_until: u64) -> [u8; RECORD_SIZE] {
    let mut record = [0u8; RECORD_SIZE];
    record[0..4].copy_from_slice(&RECORD_MAGIC);
    record[4..6].copy_from_slice(&RECORD_VERSION.to_be_bytes());
    record[6..14].copy_from_slice(&retain_until.to_be_bytes());
    record
}

fn write_record(file: &mut File, retain_until: u64) -> std::io::Result<()> {
    let record = encode_record(retain_until);
    file.write_all(&record)?;
    file.sync_all()
}

fn read_record(path: &Path) -> Result<RecordState, ReplayStoreError> {
    match fs::read(path) {
        Ok(bytes) => {
            if bytes.len() == RECORD_SIZE
                && bytes[0..4] == RECORD_MAGIC
                && u16::from_be_bytes([bytes[4], bytes[5]]) == RECORD_VERSION
            {
                Ok(RecordState::Present(u64::from_be_bytes(
                    bytes[6..14].try_into().expect("length checked"),
                )))
            } else {
                Ok(RecordState::Corrupt)
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(RecordState::Absent),
        Err(_) => Err(ReplayStoreError::BackendUnavailable),
    }
}

fn read_high_water(dir: &Path) -> Result<u64, ReplayStoreError> {
    let path = dir.join(CLOCK_FILE_NAME);
    match fs::read(&path) {
        Ok(bytes) if bytes.len() == 8 => Ok(u64::from_be_bytes(
            bytes.try_into().expect("length checked"),
        )),
        Ok(_) => Err(ReplayStoreError::BackendUnavailable),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(0),
        Err(_) => Err(ReplayStoreError::BackendUnavailable),
    }
}

fn write_high_water(dir: &Path, now_secs: u64) -> Result<(), ReplayStoreError> {
    let path = dir.join(CLOCK_FILE_NAME);
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .map_err(|_| ReplayStoreError::BackendUnavailable)?;
    file.write_all(&now_secs.to_be_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|_| ReplayStoreError::TransactionIndeterminate)
}

fn invalid_key(reservation: &ReplayReservation) -> bool {
    reservation.binding_digest().iter().all(|byte| *byte == 0)
}

impl DurableFileReplayStore {
    /// Opens (creating if necessary) a durable replay store rooted at `dir`.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, ReplayStoreError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).map_err(|_| ReplayStoreError::BackendUnavailable)?;
        let high_water_secs = read_high_water(&dir)?;
        Ok(Self {
            state: Mutex::new(FileState {
                dir,
                high_water_secs,
            }),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, FileState>, ReplayStoreError> {
        self.state.lock().map_err(|_| ReplayStoreError::LockPoisoned)
    }

    fn validate(
        reservation: &ReplayReservation,
        now_secs: u64,
    ) -> Result<(), ReplayStoreError> {
        if invalid_key(reservation) {
            return Err(ReplayStoreError::InvalidKey);
        }
        if reservation.retain_until() <= now_secs {
            return Err(ReplayStoreError::InvalidRetention);
        }
        Ok(())
    }
}

impl ReplayStore for DurableFileReplayStore {
    fn durability(&self) -> ReplayStoreDurability {
        ReplayStoreDurability::DurableProvider
    }

    fn consume_once(
        &self,
        reservation: &ReplayReservation,
        now_secs: u64,
    ) -> Result<ReplayConsumeOutcome, ReplayStoreError> {
        Self::validate(reservation, now_secs)?;
        let mut state = self.lock()?;
        if now_secs < state.high_water_secs {
            return Err(ReplayStoreError::ClockRollback);
        }
        state.high_water_secs = now_secs;
        let _ = write_high_water(&state.dir, now_secs);

        let path = record_path(&state.dir, reservation.binding_digest());
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                if write_record(&mut file, reservation.retain_until()).is_err() {
                    drop(file);
                    let _ = fs::remove_file(&path);
                    return Err(ReplayStoreError::TransactionIndeterminate);
                }
                Ok(ReplayConsumeOutcome::Accepted)
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => match read_record(&path)? {
                RecordState::Present(retain_until) if retain_until > now_secs => {
                    Ok(ReplayConsumeOutcome::Duplicate)
                }
                RecordState::Present(_) => {
                    // Expired record: reclaim the key.
                    let _ = fs::remove_file(&path);
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .map_err(|_| ReplayStoreError::BackendUnavailable)?;
                    if write_record(&mut file, reservation.retain_until()).is_err() {
                        drop(file);
                        let _ = fs::remove_file(&path);
                        return Err(ReplayStoreError::TransactionIndeterminate);
                    }
                    Ok(ReplayConsumeOutcome::Accepted)
                }
                RecordState::Absent | RecordState::Corrupt => {
                    Err(ReplayStoreError::BackendUnavailable)
                }
            },
            Err(_) => Err(ReplayStoreError::BackendUnavailable),
        }
    }

    fn consume_once_batch(
        &self,
        reservations: &[ReplayReservation],
        now_secs: u64,
    ) -> Result<ReplayBatchOutcome, ReplayStoreError> {
        // Validate every reservation and detect intra-batch duplicates before
        // observing time, so invalid input never advances the high-water mark.
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for reservation in reservations {
            if invalid_key(reservation) {
                return Err(ReplayStoreError::AtomicBatchFailure(
                    ReplayBatchFailure::InvalidKey,
                ));
            }
            if reservation.retain_until() <= now_secs {
                return Err(ReplayStoreError::AtomicBatchFailure(
                    ReplayBatchFailure::InvalidRetention,
                ));
            }
            if !seen.insert(*reservation.binding_digest()) {
                return Err(ReplayStoreError::AtomicBatchFailure(
                    ReplayBatchFailure::Duplicate,
                ));
            }
        }

        let mut state = self.lock()?;
        if now_secs < state.high_water_secs {
            return Err(ReplayStoreError::ClockRollback);
        }
        state.high_water_secs = now_secs;
        let _ = write_high_water(&state.dir, now_secs);

        // All-or-nothing conflict check before any write.
        let mut claims: Vec<(PathBuf, u64)> = Vec::with_capacity(reservations.len());
        for reservation in reservations {
            let path = record_path(&state.dir, reservation.binding_digest());
            match read_record(&path)? {
                RecordState::Present(retain_until) if retain_until > now_secs => {
                    return Err(ReplayStoreError::AtomicBatchFailure(
                        ReplayBatchFailure::Duplicate,
                    ));
                }
                RecordState::Present(_) => {
                    let _ = fs::remove_file(&path);
                }
                RecordState::Corrupt => return Err(ReplayStoreError::BackendUnavailable),
                RecordState::Absent => {}
            }
            claims.push((path, reservation.retain_until()));
        }

        // Commit all claims; roll back every created record on any failure.
        let mut created: Vec<PathBuf> = Vec::with_capacity(claims.len());
        for (path, retain_until) in &claims {
            match OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(mut file) => {
                    if write_record(&mut file, *retain_until).is_err() {
                        drop(file);
                        let _ = fs::remove_file(path);
                        for created_path in &created {
                            let _ = fs::remove_file(created_path);
                        }
                        return Err(ReplayStoreError::TransactionIndeterminate);
                    }
                    created.push(path.clone());
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    for created_path in &created {
                        let _ = fs::remove_file(created_path);
                    }
                    return Err(ReplayStoreError::AtomicBatchFailure(
                        ReplayBatchFailure::Duplicate,
                    ));
                }
                Err(_) => {
                    for created_path in &created {
                        let _ = fs::remove_file(created_path);
                    }
                    return Err(ReplayStoreError::BackendUnavailable);
                }
            }
        }

        Ok(ReplayBatchOutcome::accepted_for(reservations))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::replay_guard::{ReplayReservation, ReplayStore};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "conxius-file-replay-store-{}-{}-{tag}",
            std::process::id(),
            unique
        ))
    }

    fn reservation(seed: u8, retain_until: u64) -> ReplayReservation {
        let mut digest = [seed; 32];
        if seed == 0 {
            digest = [0; 32];
        }
        ReplayReservation::from_digest(digest, retain_until)
    }

    #[test]
    fn file_store_is_durable_provider_and_accept_then_duplicate() {
        let dir = temp_dir("accept-dup");
        let store = DurableFileReplayStore::open(&dir).unwrap();
        assert_eq!(store.durability(), ReplayStoreDurability::DurableProvider);

        let candidate = reservation(1, 10_100);
        assert_eq!(
            store.consume_once(&candidate, 10_000).unwrap(),
            ReplayConsumeOutcome::Accepted
        );
        assert_eq!(
            store.consume_once(&candidate, 10_001).unwrap(),
            ReplayConsumeOutcome::Duplicate
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_store_survives_restart() {
        let dir = temp_dir("restart");
        let candidate = reservation(7, 10_100);
        {
            let store = DurableFileReplayStore::open(&dir).unwrap();
            assert_eq!(
                store.consume_once(&candidate, 10_000).unwrap(),
                ReplayConsumeOutcome::Accepted
            );
        }
        let store = DurableFileReplayStore::open(&dir).unwrap();
        assert_eq!(
            store.consume_once(&candidate, 10_001).unwrap(),
            ReplayConsumeOutcome::Duplicate
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_store_batch_is_all_or_nothing() {
        let dir = temp_dir("batch");
        let store = DurableFileReplayStore::open(&dir).unwrap();
        let first = reservation(1, 10_100);
        let second = reservation(2, 10_100);
        let third = reservation(3, 10_100);

        let outcome = store
            .consume_once_batch(&[first.clone(), second.clone()], 10_000)
            .unwrap();
        assert_eq!(outcome.accepted_count(), 2);

        // Conflict on `second` means `third` must not be written.
        let err = store
            .consume_once_batch(&[second.clone(), third.clone()], 10_001)
            .unwrap_err();
        assert_eq!(
            err,
            ReplayStoreError::AtomicBatchFailure(ReplayBatchFailure::Duplicate)
        );
        assert_eq!(
            store.consume_once(&third, 10_002).unwrap(),
            ReplayConsumeOutcome::Accepted
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_store_fails_closed_on_validation() {
        let dir = temp_dir("validation");
        let store = DurableFileReplayStore::open(&dir).unwrap();

        // All-zero digest is an invalid key.
        assert_eq!(
            store.consume_once(&reservation(0, 10_100), 10_000),
            Err(ReplayStoreError::InvalidKey)
        );
        // Retention horizon already reached.
        assert_eq!(
            store.consume_once(&reservation(1, 10_000), 10_000),
            Err(ReplayStoreError::InvalidRetention)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
