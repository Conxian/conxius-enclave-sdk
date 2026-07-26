use conxius_enclave_sdk::enclave::replay_guard::{
    ReplayBatchFailure, ReplayBinding, ReplayConsumeOutcome, ReplayReservation, ReplayStore,
    ReplayStoreDurability, ReplayStoreError,
};
use std::collections::HashSet;
use std::sync::{Arc, Barrier};
use std::thread;

pub const TEST_NOW: u64 = 10_000;
pub const TEST_RETAIN_UNTIL: u64 = 10_100;

/// Deterministic, secret-free builder for replay conformance fixtures.
#[derive(Clone)]
pub struct ReplayBindingFixture {
    pub domain: String,
    pub provider: String,
    pub proof_subject: String,
    pub proof_mechanism: String,
    pub nonce: Vec<u8>,
    pub operation_digest: [u8; 32],
    pub purpose: String,
    pub policy_digest: [u8; 32],
    pub key_identity: Vec<u8>,
    pub evidence_digest: [u8; 32],
    pub proof_id: String,
    pub audience: String,
}

impl ReplayBindingFixture {
    pub fn seeded(seed: u8) -> Self {
        Self {
            domain: "CONXIAN-REPLAY-CONFORMANCE/v1".to_string(),
            provider: format!("fixture-provider-{seed}"),
            proof_subject: "fixture-subject".to_string(),
            proof_mechanism: "fixture-mechanism".to_string(),
            nonce: vec![seed; 16],
            operation_digest: [seed.wrapping_add(1); 32],
            purpose: "fixture-purpose".to_string(),
            policy_digest: [seed.wrapping_add(2); 32],
            key_identity: vec![seed.wrapping_add(3); 24],
            evidence_digest: [seed.wrapping_add(4); 32],
            proof_id: format!("fixture-proof-{seed}"),
            audience: "fixture-audience".to_string(),
        }
    }

    pub fn build(&self) -> ReplayBinding {
        ReplayBinding::builder()
            .domain(self.domain.clone())
            .provider(self.provider.clone())
            .proof_subject(self.proof_subject.clone())
            .proof_mechanism(self.proof_mechanism.clone())
            .nonce(&self.nonce)
            .operation_digest(self.operation_digest)
            .purpose(self.purpose.clone())
            .policy_digest(self.policy_digest)
            .key_identity(&self.key_identity)
            .evidence_digest(self.evidence_digest)
            .proof_id(self.proof_id.clone())
            .audience(self.audience.clone())
            .build()
            .expect("deterministic replay fixture must be valid")
    }
}

pub fn reservation(seed: u8, retain_until: u64) -> ReplayReservation {
    ReplayReservation::new(&ReplayBindingFixture::seeded(seed).build(), retain_until)
        .expect("deterministic replay reservation must be valid")
}

/// Runs every backend-neutral `ReplayStore` contract case against fresh stores.
///
/// A backend adapter can call this suite with its own factory without copying
/// the cases. Snapshot/restore and deterministic fault injection remain the
/// responsibility of adapter-specific tests because they require backend
/// lifecycle hooks that are not part of `ReplayStore`.
pub fn run_replay_store_conformance_suite<F>(factory: F)
where
    F: Fn() -> Arc<dyn ReplayStore>,
{
    assert_accept_then_duplicate(factory(), 1);
    assert_atomic_batch_success_and_conflict(factory(), 10);
    assert_duplicate_inside_batch_has_no_writes(factory(), 20);
    assert_same_key_contention_accepts_exactly_once(factory(), 30);
    assert_overlapping_batch_contention_has_no_partial_loser_write(factory(), 40);
    assert_forward_duplicate_advances_high_water(factory(), 50);
    assert_forward_failed_batch_advances_high_water_without_partial_write(factory(), 60);
    assert_retention_boundary_and_post_horizon_reuse(factory(), 70);
    assert_validation_precedes_time_observation(factory(), 80);
    assert_full_binding_dimension_isolation(factory(), 90);
}

fn assert_durable_adapter(store: &dyn ReplayStore) {
    assert_eq!(
        store.durability(),
        ReplayStoreDurability::DurableProvider,
        "the durable adapter suite must target a store claiming the durable contract"
    );
}

pub fn assert_accept_then_duplicate(store: Arc<dyn ReplayStore>, seed: u8) {
    assert_durable_adapter(store.as_ref());
    let candidate = reservation(seed, TEST_RETAIN_UNTIL);
    assert_eq!(
        store.consume_once(&candidate, TEST_NOW),
        Ok(ReplayConsumeOutcome::Accepted)
    );
    assert_eq!(
        store.consume_once(&candidate, TEST_NOW + 1),
        Ok(ReplayConsumeOutcome::Duplicate)
    );
}

pub fn assert_atomic_batch_success_and_conflict(store: Arc<dyn ReplayStore>, seed: u8) {
    let first = reservation(seed, TEST_RETAIN_UNTIL);
    let second = reservation(seed.wrapping_add(1), TEST_RETAIN_UNTIL);
    let third = reservation(seed.wrapping_add(2), TEST_RETAIN_UNTIL);

    let outcome = store
        .consume_once_batch(&[first.clone(), second.clone()], TEST_NOW)
        .expect("fresh conformance batch must commit");
    assert_eq!(outcome.accepted_count(), 2);
    assert_eq!(
        store.consume_once_batch(&[second, third.clone()], TEST_NOW + 1),
        Err(ReplayStoreError::AtomicBatchFailure(
            ReplayBatchFailure::Duplicate
        ))
    );
    assert_eq!(
        store.consume_once(&third, TEST_NOW + 2),
        Ok(ReplayConsumeOutcome::Accepted),
        "a failed atomic batch must not retain its non-conflicting key"
    );
}

pub fn assert_duplicate_inside_batch_has_no_writes(store: Arc<dyn ReplayStore>, seed: u8) {
    let duplicate = reservation(seed, TEST_RETAIN_UNTIL);
    assert_eq!(
        store.consume_once_batch(&[duplicate.clone(), duplicate.clone()], TEST_NOW),
        Err(ReplayStoreError::AtomicBatchFailure(
            ReplayBatchFailure::Duplicate
        ))
    );
    assert_eq!(
        store.consume_once(&duplicate, TEST_NOW + 1),
        Ok(ReplayConsumeOutcome::Accepted)
    );
}

pub fn assert_same_key_contention_accepts_exactly_once(store: Arc<dyn ReplayStore>, seed: u8) {
    const THREADS: usize = 32;
    let barrier = Arc::new(Barrier::new(THREADS));
    let candidate = reservation(seed, TEST_RETAIN_UNTIL);
    let mut handles = Vec::with_capacity(THREADS);

    for _ in 0..THREADS {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let candidate = candidate.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            store.consume_once(&candidate, TEST_NOW)
        }));
    }

    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("contention worker must not panic"))
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Ok(ReplayConsumeOutcome::Accepted))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Ok(ReplayConsumeOutcome::Duplicate))
            .count(),
        THREADS - 1
    );
}

pub fn assert_overlapping_batch_contention_has_no_partial_loser_write(
    store: Arc<dyn ReplayStore>,
    seed: u8,
) {
    let barrier = Arc::new(Barrier::new(2));
    let left_only = reservation(seed, TEST_RETAIN_UNTIL);
    let overlap = reservation(seed.wrapping_add(1), TEST_RETAIN_UNTIL);
    let right_only = reservation(seed.wrapping_add(2), TEST_RETAIN_UNTIL);

    let run_batch = |batch: Vec<ReplayReservation>| {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            store.consume_once_batch(&batch, TEST_NOW)
        })
    };
    let left = run_batch(vec![left_only.clone(), overlap.clone()]);
    let right = run_batch(vec![overlap, right_only.clone()]);
    let left_outcome = left.join().expect("left batch worker must not panic");
    let right_outcome = right.join().expect("right batch worker must not panic");

    assert_eq!(
        [&left_outcome, &right_outcome]
            .into_iter()
            .filter(|outcome| outcome.is_ok())
            .count(),
        1
    );
    let conflict = Err(ReplayStoreError::AtomicBatchFailure(
        ReplayBatchFailure::Duplicate,
    ));
    if left_outcome.is_ok() {
        assert_eq!(right_outcome, conflict);
        assert_eq!(
            store.consume_once(&right_only, TEST_NOW + 1),
            Ok(ReplayConsumeOutcome::Accepted)
        );
    } else {
        assert_eq!(left_outcome, conflict);
        assert_eq!(
            store.consume_once(&left_only, TEST_NOW + 1),
            Ok(ReplayConsumeOutcome::Accepted)
        );
    }
}

pub fn assert_forward_duplicate_advances_high_water(store: Arc<dyn ReplayStore>, seed: u8) {
    let candidate = reservation(seed, TEST_RETAIN_UNTIL + 100);
    assert_eq!(
        store.consume_once(&candidate, TEST_NOW),
        Ok(ReplayConsumeOutcome::Accepted)
    );
    assert_eq!(
        store.consume_once(&candidate, TEST_NOW + 20),
        Ok(ReplayConsumeOutcome::Duplicate)
    );
    assert_eq!(
        store.consume_once(
            &reservation(seed.wrapping_add(1), TEST_RETAIN_UNTIL + 100),
            TEST_NOW + 19,
        ),
        Err(ReplayStoreError::ClockRollback)
    );
}

pub fn assert_forward_failed_batch_advances_high_water_without_partial_write(
    store: Arc<dyn ReplayStore>,
    seed: u8,
) {
    let existing = reservation(seed, TEST_RETAIN_UNTIL + 100);
    let fresh = reservation(seed.wrapping_add(1), TEST_RETAIN_UNTIL + 100);
    assert_eq!(
        store.consume_once(&existing, TEST_NOW),
        Ok(ReplayConsumeOutcome::Accepted)
    );
    assert_eq!(
        store.consume_once_batch(&[existing, fresh.clone()], TEST_NOW + 20),
        Err(ReplayStoreError::AtomicBatchFailure(
            ReplayBatchFailure::Duplicate
        ))
    );
    assert_eq!(
        store.consume_once(
            &reservation(seed.wrapping_add(2), TEST_RETAIN_UNTIL + 100),
            TEST_NOW + 19,
        ),
        Err(ReplayStoreError::ClockRollback)
    );
    assert_eq!(
        store.consume_once(&fresh, TEST_NOW + 21),
        Ok(ReplayConsumeOutcome::Accepted),
        "the failed batch must not retain its fresh member"
    );
}

pub fn assert_retention_boundary_and_post_horizon_reuse(store: Arc<dyn ReplayStore>, seed: u8) {
    let candidate = reservation(seed, TEST_RETAIN_UNTIL);
    assert_eq!(
        store.consume_once(&candidate, TEST_NOW),
        Ok(ReplayConsumeOutcome::Accepted)
    );
    assert_eq!(
        store.consume_once(&candidate, TEST_RETAIN_UNTIL),
        Err(ReplayStoreError::InvalidRetention)
    );
    assert_eq!(
        store.consume_once(
            &reservation(seed, TEST_RETAIN_UNTIL + 100),
            TEST_RETAIN_UNTIL,
        ),
        Ok(ReplayConsumeOutcome::Accepted)
    );
}

pub fn assert_validation_precedes_time_observation(store: Arc<dyn ReplayStore>, seed: u8) {
    assert_eq!(
        store.consume_once(
            &ReplayReservation::from_digest([0; 32], TEST_RETAIN_UNTIL + 100),
            TEST_NOW + 20,
        ),
        Err(ReplayStoreError::InvalidKey)
    );
    assert_eq!(
        store.consume_once(&reservation(seed, TEST_RETAIN_UNTIL + 100), TEST_NOW + 19,),
        Ok(ReplayConsumeOutcome::Accepted),
        "invalid single reservation must not advance high water"
    );

    let invalid = reservation(seed.wrapping_add(1), TEST_NOW + 20);
    assert_eq!(
        store.consume_once_batch(&[invalid], TEST_NOW + 20),
        Err(ReplayStoreError::AtomicBatchFailure(
            ReplayBatchFailure::InvalidRetention
        ))
    );
    assert_eq!(
        store.consume_once(
            &reservation(seed.wrapping_add(2), TEST_RETAIN_UNTIL + 100),
            TEST_NOW + 19,
        ),
        Ok(ReplayConsumeOutcome::Accepted),
        "invalid batch must not advance high water"
    );
}

pub fn assert_full_binding_dimension_isolation(store: Arc<dyn ReplayStore>, seed: u8) {
    let base = ReplayBindingFixture::seeded(seed);
    let mut variants = Vec::new();

    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut fixture = base.clone();
            fixture.$field = $value;
            variants.push(fixture);
        }};
    }

    changed!(domain, "CONXIAN-REPLAY-CONFORMANCE-OTHER/v1".to_string());
    changed!(provider, "other-provider".to_string());
    changed!(proof_subject, "other-subject".to_string());
    changed!(proof_mechanism, "other-mechanism".to_string());
    changed!(nonce, vec![0x91; 16]);
    changed!(operation_digest, [0x92; 32]);
    changed!(purpose, "other-purpose".to_string());
    changed!(policy_digest, [0x93; 32]);
    changed!(key_identity, vec![0x94; 24]);
    changed!(evidence_digest, [0x95; 32]);
    changed!(proof_id, "other-proof".to_string());
    changed!(audience, "other-audience".to_string());

    let mut digests = HashSet::new();
    for fixture in std::iter::once(base).chain(variants) {
        let candidate = ReplayReservation::new(&fixture.build(), TEST_RETAIN_UNTIL)
            .expect("binding variant must produce a reservation");
        assert!(digests.insert(*candidate.binding_digest()));
        assert_eq!(
            store.consume_once(&candidate, TEST_NOW),
            Ok(ReplayConsumeOutcome::Accepted)
        );
    }
    assert_eq!(digests.len(), 13);
}
