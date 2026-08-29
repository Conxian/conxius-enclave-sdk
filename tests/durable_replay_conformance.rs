mod support;

use conxius_enclave_sdk::enclave::replay_guard::{
    ReplayBatchFailure, ReplayBatchOutcome, ReplayConsumeOutcome, ReplayReservation, ReplayStore,
    ReplayStoreDurability, ReplayStoreError,
};
use conxius_enclave_sdk::enclave::DurableFileReplayStore;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use support::{reservation, run_replay_store_conformance_suite, TEST_NOW, TEST_RETAIN_UNTIL};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlannedFault {
    BeforeCommitUnavailable,
    AfterCommitResponseLoss,
}

#[derive(Debug, Clone, Default)]
struct ModelSnapshot {
    ledger: HashMap<[u8; 32], u64>,
    high_water_secs: Option<u64>,
}

#[derive(Debug, Default)]
struct ModelState {
    persisted: ModelSnapshot,
    faults: VecDeque<PlannedFault>,
}

/// Test-only reference model for the active `ReplayStore` contract.
///
/// `DurableProvider` is advertised only to exercise production-facing trait
/// gates. This mutex-backed model is not provider, restart, failover, or
/// distributed-durability evidence.
#[derive(Debug, Default)]
struct FaultInjectingReplayStore {
    state: Mutex<ModelState>,
}

impl FaultInjectingReplayStore {
    fn with_faults(faults: impl IntoIterator<Item = PlannedFault>) -> Self {
        Self {
            state: Mutex::new(ModelState {
                persisted: ModelSnapshot::default(),
                faults: faults.into_iter().collect(),
            }),
        }
    }

    fn snapshot(&self) -> ModelSnapshot {
        self.state
            .lock()
            .expect("test model mutex must remain available")
            .persisted
            .clone()
    }

    fn restore(snapshot: ModelSnapshot) -> Self {
        Self {
            state: Mutex::new(ModelState {
                persisted: snapshot,
                faults: VecDeque::new(),
            }),
        }
    }

    fn validate_time(snapshot: &ModelSnapshot, now_secs: u64) -> Result<(), ReplayStoreError> {
        if snapshot
            .high_water_secs
            .is_some_and(|high_water_secs| now_secs < high_water_secs)
        {
            return Err(ReplayStoreError::ClockRollback);
        }
        Ok(())
    }

    fn validate_reservation(
        reservation: &ReplayReservation,
        now_secs: u64,
    ) -> Result<(), ReplayStoreError> {
        if reservation.binding_digest().iter().all(|byte| *byte == 0) {
            return Err(ReplayStoreError::InvalidKey);
        }
        if reservation.retain_until() <= now_secs {
            return Err(ReplayStoreError::InvalidRetention);
        }
        Ok(())
    }

    fn prepare_observation(snapshot: &mut ModelSnapshot, now_secs: u64) {
        snapshot.high_water_secs = Some(now_secs);
        snapshot
            .ledger
            .retain(|_, retain_until| now_secs < *retain_until);
    }

    fn take_fault(state: &mut ModelState) -> Option<PlannedFault> {
        state.faults.pop_front()
    }
}

impl ReplayStore for FaultInjectingReplayStore {
    fn durability(&self) -> ReplayStoreDurability {
        ReplayStoreDurability::DurableProvider
    }

    fn consume_once(
        &self,
        reservation: &ReplayReservation,
        now_secs: u64,
    ) -> Result<ReplayConsumeOutcome, ReplayStoreError> {
        Self::validate_reservation(reservation, now_secs)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReplayStoreError::LockPoisoned)?;
        Self::validate_time(&state.persisted, now_secs)?;

        let fault = Self::take_fault(&mut state);
        if fault == Some(PlannedFault::BeforeCommitUnavailable) {
            return Err(ReplayStoreError::BackendUnavailable);
        }

        let mut next = state.persisted.clone();
        Self::prepare_observation(&mut next, now_secs);
        let digest = *reservation.binding_digest();
        if next.ledger.contains_key(&digest) {
            state.persisted = next;
            return Ok(ReplayConsumeOutcome::Duplicate);
        }
        next.ledger.insert(digest, reservation.retain_until());
        state.persisted = next;

        if fault == Some(PlannedFault::AfterCommitResponseLoss) {
            Err(ReplayStoreError::TransactionIndeterminate)
        } else {
            Ok(ReplayConsumeOutcome::Accepted)
        }
    }

    fn consume_once_batch(
        &self,
        reservations: &[ReplayReservation],
        now_secs: u64,
    ) -> Result<ReplayBatchOutcome, ReplayStoreError> {
        for reservation in reservations {
            Self::validate_reservation(reservation, now_secs).map_err(|error| {
                ReplayStoreError::AtomicBatchFailure(match error {
                    ReplayStoreError::InvalidKey => ReplayBatchFailure::InvalidKey,
                    ReplayStoreError::InvalidRetention => ReplayBatchFailure::InvalidRetention,
                    _ => ReplayBatchFailure::BackendUnavailable,
                })
            })?;
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| ReplayStoreError::BackendUnavailable)?;
        Self::validate_time(&state.persisted, now_secs)?;
        let fault = Self::take_fault(&mut state);
        if fault == Some(PlannedFault::BeforeCommitUnavailable) {
            return Err(ReplayStoreError::BackendUnavailable);
        }

        let mut next = state.persisted.clone();
        Self::prepare_observation(&mut next, now_secs);
        let mut requested = HashSet::with_capacity(reservations.len());
        for reservation in reservations {
            let digest = *reservation.binding_digest();
            if next.ledger.contains_key(&digest) || !requested.insert(digest) {
                state.persisted = next;
                return Err(ReplayStoreError::AtomicBatchFailure(
                    ReplayBatchFailure::Duplicate,
                ));
            }
        }
        for reservation in reservations {
            next.ledger
                .insert(*reservation.binding_digest(), reservation.retain_until());
        }
        state.persisted = next;

        if fault == Some(PlannedFault::AfterCommitResponseLoss) {
            Err(ReplayStoreError::TransactionIndeterminate)
        } else {
            Ok(ReplayBatchOutcome::accepted_for(reservations))
        }
    }
}

#[test]
fn reference_model_passes_complete_backend_neutral_suite() {
    run_replay_store_conformance_suite(|| Arc::new(FaultInjectingReplayStore::default()));
}

#[test]
fn single_before_commit_unavailable_has_no_mutation_and_retry_succeeds() {
    let store = FaultInjectingReplayStore::with_faults([PlannedFault::BeforeCommitUnavailable]);
    let candidate = reservation(50, TEST_RETAIN_UNTIL);
    let before = store.snapshot();

    assert_eq!(
        store.consume_once(&candidate, TEST_NOW),
        Err(ReplayStoreError::BackendUnavailable)
    );
    assert_eq!(store.snapshot().ledger, before.ledger);
    assert_eq!(store.snapshot().high_water_secs, before.high_water_secs);
    assert_eq!(
        store.consume_once(&candidate, TEST_NOW),
        Ok(ReplayConsumeOutcome::Accepted)
    );
}

#[test]
fn batch_before_commit_unavailable_has_no_mutation_and_retry_succeeds_atomically() {
    let store = FaultInjectingReplayStore::with_faults([PlannedFault::BeforeCommitUnavailable]);
    let batch = [
        reservation(51, TEST_RETAIN_UNTIL),
        reservation(52, TEST_RETAIN_UNTIL),
    ];
    let before = store.snapshot();

    assert_eq!(
        store.consume_once_batch(&batch, TEST_NOW),
        Err(ReplayStoreError::BackendUnavailable)
    );
    assert_eq!(store.snapshot().ledger, before.ledger);
    assert_eq!(store.snapshot().high_water_secs, before.high_water_secs);
    assert_eq!(
        store
            .consume_once_batch(&batch, TEST_NOW)
            .expect("retry must commit the complete batch")
            .accepted_count(),
        batch.len()
    );
    for member in &batch {
        assert_eq!(
            store.consume_once(member, TEST_NOW + 1),
            Ok(ReplayConsumeOutcome::Duplicate)
        );
    }
}

#[test]
fn single_after_commit_response_loss_restores_as_duplicate() {
    let store = FaultInjectingReplayStore::with_faults([PlannedFault::AfterCommitResponseLoss]);
    let candidate = reservation(60, TEST_RETAIN_UNTIL);

    assert_eq!(
        store.consume_once(&candidate, TEST_NOW),
        Err(ReplayStoreError::TransactionIndeterminate)
    );
    let restored = FaultInjectingReplayStore::restore(store.snapshot());
    assert_eq!(
        restored.consume_once(&candidate, TEST_NOW + 1),
        Ok(ReplayConsumeOutcome::Duplicate)
    );
}

#[test]
fn batch_after_commit_response_loss_restores_as_all_or_nothing_duplicate() {
    let store = FaultInjectingReplayStore::with_faults([PlannedFault::AfterCommitResponseLoss]);
    let batch = [
        reservation(61, TEST_RETAIN_UNTIL),
        reservation(62, TEST_RETAIN_UNTIL),
    ];

    assert_eq!(
        store.consume_once_batch(&batch, TEST_NOW),
        Err(ReplayStoreError::TransactionIndeterminate)
    );
    let restored = FaultInjectingReplayStore::restore(store.snapshot());
    assert_eq!(
        restored.consume_once_batch(&batch, TEST_NOW + 1),
        Err(ReplayStoreError::AtomicBatchFailure(
            ReplayBatchFailure::Duplicate
        ))
    );
    for member in &batch {
        assert_eq!(
            restored.consume_once(member, TEST_NOW + 1),
            Ok(ReplayConsumeOutcome::Duplicate)
        );
    }
}

#[test]
fn forward_duplicate_advances_and_persists_high_water() {
    let store = FaultInjectingReplayStore::default();
    let candidate = reservation(70, 10_300);
    assert_eq!(
        store.consume_once(&candidate, 10_100),
        Ok(ReplayConsumeOutcome::Accepted)
    );
    assert_eq!(
        store.consume_once(&candidate, 10_200),
        Ok(ReplayConsumeOutcome::Duplicate)
    );
    let restored = FaultInjectingReplayStore::restore(store.snapshot());
    assert_eq!(
        restored.consume_once(&reservation(71, 10_300), 10_199),
        Err(ReplayStoreError::ClockRollback)
    );
}

#[test]
fn forward_failed_batch_persists_high_water_without_fresh_member() {
    let store = FaultInjectingReplayStore::default();
    let existing = reservation(72, 10_300);
    let fresh = reservation(73, 10_300);
    assert_eq!(
        store.consume_once(&existing, 10_100),
        Ok(ReplayConsumeOutcome::Accepted)
    );
    assert_eq!(
        store.consume_once_batch(&[existing, fresh.clone()], 10_200),
        Err(ReplayStoreError::AtomicBatchFailure(
            ReplayBatchFailure::Duplicate
        ))
    );
    let restored = FaultInjectingReplayStore::restore(store.snapshot());
    assert_eq!(
        restored.consume_once(&reservation(74, 10_300), 10_199),
        Err(ReplayStoreError::ClockRollback)
    );
    assert_eq!(
        restored.consume_once(&fresh, 10_201),
        Ok(ReplayConsumeOutcome::Accepted),
        "the failed batch must not persist its fresh member"
    );
}

#[test]
fn invalid_reservations_precede_fault_consumption_and_high_water_mutation() {
    let single = FaultInjectingReplayStore::with_faults([PlannedFault::BeforeCommitUnavailable]);
    let before_single = single.snapshot();
    assert_eq!(
        single.consume_once(&ReplayReservation::from_digest([0; 32], 10_300), 10_200),
        Err(ReplayStoreError::InvalidKey)
    );
    assert_eq!(single.snapshot().ledger, before_single.ledger);
    assert_eq!(
        single.snapshot().high_water_secs,
        before_single.high_water_secs
    );
    let valid_single = reservation(80, 10_300);
    assert_eq!(
        single.consume_once(&valid_single, 10_199),
        Err(ReplayStoreError::BackendUnavailable),
        "invalid input must not consume the queued fault"
    );
    assert_eq!(single.snapshot().ledger, before_single.ledger);
    assert_eq!(
        single.snapshot().high_water_secs,
        before_single.high_water_secs
    );
    assert_eq!(
        single.consume_once(&valid_single, 10_199),
        Ok(ReplayConsumeOutcome::Accepted)
    );

    let batch = FaultInjectingReplayStore::with_faults([PlannedFault::BeforeCommitUnavailable]);
    let before_batch = batch.snapshot();
    assert_eq!(
        batch.consume_once_batch(&[reservation(81, 10_200)], 10_200),
        Err(ReplayStoreError::AtomicBatchFailure(
            ReplayBatchFailure::InvalidRetention
        ))
    );
    assert_eq!(batch.snapshot().ledger, before_batch.ledger);
    assert_eq!(
        batch.snapshot().high_water_secs,
        before_batch.high_water_secs
    );
    let valid_batch = [reservation(82, 10_300), reservation(83, 10_300)];
    assert_eq!(
        batch.consume_once_batch(&valid_batch, 10_199),
        Err(ReplayStoreError::BackendUnavailable),
        "invalid batch must not consume the queued fault"
    );
    assert_eq!(batch.snapshot().ledger, before_batch.ledger);
    assert_eq!(
        batch.snapshot().high_water_secs,
        before_batch.high_water_secs
    );
    assert_eq!(
        batch
            .consume_once_batch(&valid_batch, 10_199)
            .expect("valid retry must commit atomically")
            .accepted_count(),
        valid_batch.len()
    );
}

#[test]
fn clock_rollback_is_detected_before_pruning_or_admission() {
    let store = FaultInjectingReplayStore::default();
    assert_eq!(
        store.consume_once(&reservation(90, 10_110), 10_100),
        Ok(ReplayConsumeOutcome::Accepted)
    );
    assert_eq!(
        store.consume_once(&reservation(91, 10_300), 10_200),
        Ok(ReplayConsumeOutcome::Accepted)
    );
    let before = store.snapshot();
    assert_eq!(
        store.consume_once(&reservation(92, 10_300), 10_150),
        Err(ReplayStoreError::ClockRollback)
    );
    let after = store.snapshot();
    assert_eq!(after.ledger, before.ledger, "rollback must not prune");
    assert_eq!(
        after.high_water_secs, before.high_water_secs,
        "rollback must not change high water or admit a key"
    );
}

#[test]
fn file_backed_store_passes_complete_backend_neutral_suite() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    let parent = std::env::temp_dir().join(format!(
        "conxius-replay-conformance-file-{}",
        std::process::id()
    ));
    let cleanup = parent.clone();
    let _ = std::fs::remove_dir_all(&parent);

    run_replay_store_conformance_suite(move || {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = parent.join(format!("store-{unique}"));
        Arc::new(
            DurableFileReplayStore::open(dir).expect("durable file store must open"),
        )
    });

    let _ = std::fs::remove_dir_all(&cleanup);
}

