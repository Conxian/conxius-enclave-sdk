//! Public negative-path coverage for Issue #240 Phase A.
//!
//! Phase A is a provider-neutral contract, not a provider implementation or a
//! durable replay backend. These tests keep the unavailable boundaries visible
//! through the public API while unit tests exercise test-only positive routes.

use conxius_enclave_sdk::enclave::{
    deserialize_attestation_evidence_json, deserialize_collateral_snapshot_json,
    deserialize_trust_bundle_json, DurableReplayIdentity, DurableReplayOutcome,
    DurableReplayRequest, DurableReplayStore, IdempotencyKey, ProofKind, RevocationStatus,
    TcbStatus, TrustAnchor, TrustAuthenticator, TrustBundle, TrustError, TrustSignatureAlgorithm,
    TrustVerificationRequest, TrustVerifier, UnavailableDurableReplayStore,
    UnavailableTrustAuthenticator, UnavailableTrustVerifier, MAX_TRUST_IDENTIFIER_BYTES,
    TRUST_CONTRACT_VERSION,
};

fn transport_bundle() -> TrustBundle {
    TrustBundle {
        version: TRUST_CONTRACT_VERSION,
        bundle_id: "bundle".to_string(),
        provider: "provider".to_string(),
        profile: "profile".to_string(),
        signer_anchor_id: "anchor".to_string(),
        signature_algorithm: TrustSignatureAlgorithm::Ed25519,
        revision: 1,
        rollback_floor: 1,
        issued_at: 1,
        expires_at: 2,
        anchors: vec![TrustAnchor {
            version: TRUST_CONTRACT_VERSION,
            anchor_id: "anchor".to_string(),
            provider: "provider".to_string(),
            profile: "profile".to_string(),
            signature_algorithm: TrustSignatureAlgorithm::Ed25519,
            public_key: vec![0; 32],
            constraints: Vec::new(),
            not_before: 1,
            not_after: 2,
            revision: 1,
            revocation_status: RevocationStatus::Good,
            tcb_status: TcbStatus::Good,
        }],
        payload_digest: [0; 32],
        signature: vec![0; 64],
    }
}

fn replay_request() -> DurableReplayRequest {
    let identity = DurableReplayIdentity::new(
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
    .expect("identity shape should be valid");
    DurableReplayRequest::new(
        identity,
        IdempotencyKey::new(vec![1, 2, 3]).expect("idempotency key should be valid"),
    )
    .expect("request shape should be valid")
}

#[test]
fn production_trust_routes_are_explicitly_unavailable() {
    let request = TrustVerificationRequest::new("provider", "profile", ProofKind::Tee, 1)
        .expect("request shape should be valid");
    let bundle = transport_bundle();
    let authenticator = UnavailableTrustAuthenticator;
    let verifier = UnavailableTrustVerifier;

    assert!(matches!(
        authenticator.authenticate(&bundle, &request, 1),
        Err(TrustError::AuthenticatorUnavailable)
    ));
    assert_eq!(
        authenticator.status(),
        conxius_enclave_sdk::enclave::TrustAuthenticatorStatus::Unavailable
    );
    assert_eq!(
        verifier.status(),
        conxius_enclave_sdk::enclave::TrustVerifierStatus::Unavailable
    );
}

#[test]
fn trust_transport_denies_unknown_fields_and_unbounded_identifiers() {
    let mut bundle = serde_json::to_value(transport_bundle()).expect("bundle should serialize");
    bundle["unexpected"] = serde_json::Value::Bool(true);
    assert_eq!(
        deserialize_trust_bundle_json(&serde_json::to_vec(&bundle).expect("json")),
        Err(TrustError::InvalidPayload)
    );

    let oversized = serde_json::json!({
        "bundle_id": "x".repeat(MAX_TRUST_IDENTIFIER_BYTES + 1)
    });
    let oversized_bytes = serde_json::to_vec(&oversized).expect("json");
    assert_eq!(
        deserialize_trust_bundle_json(&oversized_bytes),
        Err(TrustError::InvalidPayload)
    );
    assert_eq!(
        deserialize_collateral_snapshot_json(&oversized_bytes),
        Err(TrustError::InvalidPayload)
    );
    assert_eq!(
        deserialize_attestation_evidence_json(&oversized_bytes),
        Err(TrustError::InvalidPayload)
    );
}

#[test]
fn all_non_good_statuses_are_fail_closed() {
    for status in [
        RevocationStatus::Revoked,
        RevocationStatus::Unknown,
        RevocationStatus::Unavailable,
        RevocationStatus::Expired,
        RevocationStatus::NotYetValid,
        RevocationStatus::Unsupported,
    ] {
        assert!(!status.is_authorizable());
    }
    for status in [
        TcbStatus::Revoked,
        TcbStatus::Unknown,
        TcbStatus::Unavailable,
        TcbStatus::Expired,
        TcbStatus::NotYetValid,
        TcbStatus::Unsupported,
    ] {
        assert!(!status.is_authorizable());
    }
}

#[test]
fn unavailable_durable_store_never_authorizes() {
    let request = replay_request();
    let store: Box<dyn DurableReplayStore> = Box::new(UnavailableDurableReplayStore);

    assert_eq!(
        store.consume_once(&request, 100),
        Ok(DurableReplayOutcome::Unavailable)
    );
    assert!(format!("{request:?}").contains("identity_digest"));
    assert!(!format!("{request:?}").contains("SIGN"));
}
