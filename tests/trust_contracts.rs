use conxius_enclave_sdk::enclave::attestation::{
    AttestationLevel, AttestationPolicy, ProviderVerifierStatus,
};
use conxius_enclave_sdk::enclave::{
    AttestationProvider, CollateralMetadata, CollateralValidationContext,
    CollateralValidationError, EvidenceReference, ReleaseEvidenceError, ReleaseEvidenceExpectation,
    ReleaseEvidenceKind, ReleaseEvidenceManifest, ReplayOperation, TrustReplayBinding,
    ReplayProofMechanism, ReplayProofSubject, ReplayPurpose, TrustDigest,
};
use conxius_enclave_sdk::ConclaveError;

fn digest(byte: u8) -> TrustDigest {
    [byte; 32]
}

fn deterministic_fixture_input(seed: u8) -> Vec<u8> {
    (0u8..32)
        .map(|offset| seed.wrapping_mul(29).wrapping_add(offset).wrapping_add(1))
        .collect()
}

#[test]
fn production_attestation_policy_and_provider_status_remain_unavailable() {
    let policy = AttestationPolicy::production();
    assert_eq!(
        policy.provider_verifier_status(),
        ProviderVerifierStatus::Unavailable
    );
    assert_eq!(
        AttestationProvider::from_attestation_level(AttestationLevel::CloudTEE),
        None
    );
}

#[test]
#[allow(deprecated)]
fn deprecated_string_root_builder_remains_unavailable_in_public_builds() {
    let result =
        AttestationPolicy::production().with_trusted_roots(vec!["fixture-root".to_string()]);
    assert!(matches!(result, Err(ConclaveError::Unsupported(_))));

    let production = AttestationPolicy::production();
    assert_eq!(
        production.provider_verifier_status(),
        ProviderVerifierStatus::Unavailable
    );
}

#[test]
fn public_collateral_contract_fails_closed_on_expiry_and_root_mismatch() {
    let metadata = CollateralMetadata::try_new(
        AttestationProvider::AwsNitroEnclave,
        "nitro-bundle",
        1,
        digest(1),
        digest(2),
        90,
        100,
        4,
        1,
        1,
        digest(3),
        digest(4),
        digest(5),
    )
    .expect("valid collateral metadata");
    let context = CollateralValidationContext::strict_for(
        AttestationProvider::AwsNitroEnclave,
        digest(9),
        100,
        4,
        4,
    )
    .expect("valid collateral context");

    assert_eq!(
        metadata.validate(&context),
        Err(CollateralValidationError::RootSetMismatch)
    );

    let context = CollateralValidationContext::strict_for(
        AttestationProvider::AwsNitroEnclave,
        digest(1),
        100,
        4,
        4,
    )
    .expect("valid collateral context");
    assert_eq!(
        metadata.validate(&context),
        Err(CollateralValidationError::Expired)
    );
}

#[test]
fn public_replay_binding_serializes_only_digests() {
    let raw_nonce = deterministic_fixture_input(1);
    let binding = TrustReplayBinding::try_new(
        AttestationProvider::AndroidKeyMintStrongBox,
        ReplayProofSubject::SignerKey,
        ReplayProofMechanism::AndroidKeyMintAuthorization,
        &raw_nonce,
        ReplayOperation::ValueBearingSigning,
        ReplayPurpose::Sign,
        digest(6),
        b"raw-key-marker",
        b"raw-evidence-marker",
    )
    .expect("valid replay binding");
    let debug = format!("{binding:?}");
    let serialized = serde_json::to_string(&binding).expect("replay binding serializes");
    let raw_nonce_marker = hex::encode(raw_nonce);
    for marker in [
        raw_nonce_marker.as_str(),
        "raw-key-marker",
        "raw-evidence-marker",
    ] {
        assert!(!debug.contains(marker));
        assert!(!serialized.contains(marker));
    }
    assert_ne!(binding.digest(), [0; 32]);
}

#[test]
fn public_release_manifest_rejects_missing_independent_review() {
    let candidate = digest(10);
    let expectation = ReleaseEvidenceExpectation::new(candidate, digest(11), digest(12))
        .expect("valid evidence expectation");
    let evidence = |name: &str, value: u8| {
        EvidenceReference::new(name, digest(value), candidate).expect("valid evidence reference")
    };
    let manifest = ReleaseEvidenceManifest::new(
        1,
        Some(evidence("candidate", 10)),
        Some(evidence("commit", 11)),
        Some(evidence("package", 12)),
        Some(evidence("sbom", 13)),
        Some(evidence("provenance", 14)),
        None,
        Some(evidence("support-decision", 16)),
    );

    assert_eq!(
        manifest.validate(&expectation),
        Err(ReleaseEvidenceError::Missing(
            ReleaseEvidenceKind::IndependentReview
        ))
    );
}
