use conxius_enclave_sdk::enclave::replay_guard::{
    ReplayBatchOutcome, ReplayConsumeOutcome, ReplayGuard, ReplayReservation, ReplayStore,
    ReplayStoreDurability, ReplayStoreError,
};
use conxius_enclave_sdk::enclave::{
    ProofBundle, ProofEnvelope, ProofKind, ProofPolicy, ProofReplayBindingContext,
    ProofVerificationContext, ProofVerifierRegistry, ProofVerifierStatus,
    ANDROID_KEYMINT_PROOF_VERIFIER_ID, PHONE_PROOF_VERIFIER_ID, PROOF_ENVELOPE_VERSION,
};
use conxius_enclave_sdk::ConclaveError;

const NOW: u64 = 2_000_000;

/// Test-only replay contract fixture. This is not distributed durability or
/// production replay evidence.
struct DurableTestStore {
    guard: ReplayGuard,
}

impl DurableTestStore {
    fn new(max_entries: usize) -> Self {
        Self {
            guard: ReplayGuard::new(300, max_entries),
        }
    }
}

impl ReplayStore for DurableTestStore {
    fn durability(&self) -> ReplayStoreDurability {
        ReplayStoreDurability::DurableProvider
    }

    fn consume_once(
        &self,
        reservation: &ReplayReservation,
        now_secs: u64,
    ) -> Result<ReplayConsumeOutcome, ReplayStoreError> {
        self.guard.consume_once(reservation, now_secs)
    }

    fn consume_once_batch(
        &self,
        reservations: &[ReplayReservation],
        now_secs: u64,
    ) -> Result<ReplayBatchOutcome, ReplayStoreError> {
        self.guard.consume_once_batch(reservations, now_secs)
    }
}

fn context() -> ProofVerificationContext {
    ProofVerificationContext::new(
        [3; 32],
        "SETTLEMENT",
        "conxian/settlement/v1",
        vec![5; 16],
        NOW,
    )
    .expect("context should be valid")
}

fn proof(kind: ProofKind, proof_id: &str) -> ProofEnvelope {
    let context = context();
    ProofEnvelope::new(
        kind,
        proof_id,
        kind.production_verifier_id(),
        context.operation_digest,
        context.purpose,
        context.audience,
        context.nonce,
        NOW - 1,
        NOW + 30,
        b"well-shaped-but-unverified".to_vec(),
    )
    .expect("proof shape should be valid")
}

#[test]
fn production_registry_exposes_only_unavailable_exact_routes() {
    let registry = ProofVerifierRegistry::production();
    assert_eq!(registry.route_count(), 7);
    for kind in ProofKind::all() {
        assert_eq!(
            registry.verifier_status(kind, kind.production_verifier_id()),
            ProofVerifierStatus::Unavailable
        );
    }
    assert_eq!(
        ProofKind::Phone.production_verifier_id(),
        PHONE_PROOF_VERIFIER_ID
    );
    assert_eq!(
        PHONE_PROOF_VERIFIER_ID,
        "conxian.proof.phone.unavailable.v1"
    );
    assert_eq!(
        ProofPolicy::production()
            .required
            .iter()
            .find(|requirement| requirement.kind == ProofKind::Phone)
            .expect("production phone requirement")
            .verifier_id,
        PHONE_PROOF_VERIFIER_ID
    );
    assert_eq!(
        registry.verifier_status(ProofKind::Phone, ANDROID_KEYMINT_PROOF_VERIFIER_ID),
        ProofVerifierStatus::Unavailable
    );
}

#[test]
fn well_shaped_production_bundle_is_not_structural_success() {
    let context = context();
    let bundle = ProofBundle::new(
        ProofKind::all()
            .into_iter()
            .enumerate()
            .map(|(index, kind)| proof(kind, &format!("proof-{index}")))
            .collect(),
    )
    .expect("bundle shape should be valid");
    let binding_context = ProofReplayBindingContext::new("integration-test", b"integration-key")
        .expect("binding context should be valid");
    let store = DurableTestStore::new(32);

    assert!(matches!(
        ProofVerifierRegistry::production().verify_bundle_with_durable_store(
            &bundle,
            &ProofPolicy::production(),
            &context,
            &binding_context,
            &store,
        ),
        Err(ConclaveError::Unsupported(_))
    ));
}

#[test]
fn duplicate_kind_and_proof_id_are_rejected_before_verification() {
    assert!(ProofBundle::new(vec![
        proof(ProofKind::Server, "server-a"),
        proof(ProofKind::Server, "server-b"),
    ])
    .is_err());
    assert!(ProofBundle::new(vec![
        proof(ProofKind::Server, "same-id"),
        proof(ProofKind::User, "same-id"),
    ])
    .is_err());
}

#[test]
fn exact_context_binding_rejects_wrong_digest_without_fallback() {
    let mut wrong_digest = proof(ProofKind::Server, "wrong-digest");
    wrong_digest.operation_digest = [4; 32];
    let bundle = ProofBundle {
        proofs: vec![wrong_digest],
    };
    let policy = ProofPolicy::new(
        vec![conxius_enclave_sdk::enclave::ProofRequirement::new(
            ProofKind::Server,
            ProofKind::Server.production_verifier_id(),
        )
        .expect("requirement should be valid")],
        false,
    )
    .expect("policy should be valid");
    let binding_context = ProofReplayBindingContext::new("integration-test", b"integration-key")
        .expect("binding context should be valid");
    let store = DurableTestStore::new(32);

    assert!(ProofVerifierRegistry::production()
        .verify_bundle_with_durable_store(&bundle, &policy, &context(), &binding_context, &store,)
        .is_err());
}

#[test]
fn replay_batch_capacity_failure_does_not_partially_insert_keys() {
    let first = proof(ProofKind::Server, "batch-a")
        .replay_key()
        .expect("replay key should be valid");
    let second = proof(ProofKind::User, "batch-b")
        .replay_key()
        .expect("replay key should be valid");
    let guard = ReplayGuard::new(300, 1);

    assert!(guard
        .try_check_and_record_batch([first.as_str(), second.as_str()], NOW)
        .is_err());
    assert!(guard.try_check_and_record(first.as_str(), NOW).is_ok());
}

#[test]
fn serialized_unknown_fields_are_rejected_and_debug_redacts_evidence() {
    let mut value = serde_json::to_value(proof(ProofKind::Server, "serde-proof"))
        .expect("proof should serialize");
    value["unexpected"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<ProofEnvelope>(value).is_err());

    let mut invalid_version = proof(ProofKind::Server, "version-proof");
    invalid_version.version = PROOF_ENVELOPE_VERSION + 1;
    assert!(invalid_version.validate_shape().is_err());

    let mut secret = proof(ProofKind::Server, "redacted-proof");
    secret.evidence = b"raw-sensitive-evidence".to_vec();
    let debug = format!("{secret:?}");
    assert!(!debug.contains("raw-sensitive-evidence"));
    assert!(debug.contains("evidence_len"));
}
