use conxius_enclave_sdk::enclave::attestation::{
    AttestationLevel, AttestationPolicy, ProviderVerifierStatus,
};
use conxius_enclave_sdk::protocol::asset::{AssetIdentifier, AssetRegistry, Chain};
use conxius_enclave_sdk::protocol::business::BusinessRegistry;
use conxius_enclave_sdk::protocol::intent::SwapRequest;
use conxius_enclave_sdk::protocol::rails::{RailProxy, SovereignHandshake, TrustTier};
use conxius_enclave_sdk::{ConclaveError, ConclaveResult};
use std::sync::Arc;

fn proxy() -> RailProxy {
    RailProxy::new(
        "http://127.0.0.1:9".to_string(),
        reqwest::Client::new(),
        Arc::new(AssetRegistry::new()),
        Arc::new(BusinessRegistry::new()),
    )
}

fn request() -> SwapRequest {
    SwapRequest {
        from_asset: AssetIdentifier {
            chain: Chain::BITCOIN,
            symbol: "BTC".to_string(),
        },
        to_asset: AssetIdentifier {
            chain: Chain::ETHEREUM,
            symbol: "ETH".to_string(),
        },
        amount: 100,
        recipient_address: "merchant".to_string(),
        attribution: None,
    }
}

#[test]
fn production_default_policy_is_hardware_only_and_provider_unavailable() {
    let policy = AttestationPolicy::production();
    assert_eq!(
        policy.provider_verifier_status(),
        ProviderVerifierStatus::Unavailable
    );
    assert_eq!(
        policy.allowed_levels(),
        &[AttestationLevel::StrongBox, AttestationLevel::CloudTEE]
    );

    let rail_proxy = proxy();
    assert_eq!(rail_proxy.min_trust_tier(), TrustTier::T4);
    assert_eq!(
        rail_proxy.attestation_policy().provider_verifier_status(),
        ProviderVerifierStatus::Unavailable
    );
}

#[test]
fn prepare_intent_commits_to_the_complete_security_context() -> ConclaveResult<()> {
    let intent = proxy().prepare_intent("x402", request(), None)?;
    assert_eq!(intent.signable_hash, intent.canonical_hash());
    Ok(())
}

#[tokio::test]
async fn production_raw_broadcast_is_rejected_before_any_network_dispatch() {
    let rail_proxy = proxy();
    let intent = rail_proxy
        .prepare_intent("x402", request(), None)
        .expect("x402 request should prepare");

    let result = rail_proxy
        .broadcast_signed_intent(intent, "opaque-signature".to_string(), None)
        .await;

    assert!(matches!(
        result,
        Err(ConclaveError::Unsupported(message))
            if message.contains("Typed operation-signature envelope required")
    ));
}

#[test]
fn production_verification_rejects_legacy_request_only_hashes() {
    let rail_proxy = proxy();
    let mut intent = rail_proxy
        .prepare_intent("x402", request(), None)
        .expect("x402 request should prepare");
    intent.signable_hash = intent.request.get_hash_bytes();

    let result = rail_proxy.verify_hardware_integrity_with_attestation_policy(
        &intent,
        &None,
        &AttestationPolicy::production(),
    );

    assert!(matches!(
        result,
        Err(ConclaveError::EnclaveFailure(message))
            if message.contains("legacy request-only hashes are rejected")
    ));
}
