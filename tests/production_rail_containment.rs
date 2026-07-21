use conxius_enclave_sdk::enclave::attestation::{
    AttestationLevel, AttestationPolicy, ProviderVerifierStatus,
};
#[cfg(feature = "development-simulators")]
use conxius_enclave_sdk::enclave::cloud::CloudEnclave;
use conxius_enclave_sdk::enclave::{
    EnclaveManager, SignRequest, SignResponse, ValueBearingSignRequest,
};
use conxius_enclave_sdk::protocol::asset::{AssetIdentifier, AssetRegistry, Chain};
use conxius_enclave_sdk::protocol::business::BusinessRegistry;
#[cfg(feature = "development-simulators")]
use conxius_enclave_sdk::protocol::ethereum::EthereumManager;
use conxius_enclave_sdk::protocol::intent::SwapRequest;
use conxius_enclave_sdk::protocol::opportunity::{OpportunityDispatcher, OpportunityPayload};
use conxius_enclave_sdk::protocol::rails::{RailProxy, SovereignHandshake, TrustTier};
use conxius_enclave_sdk::{ConclaveError, ConclaveResult};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

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

struct CountingEnclave {
    provider_calls: AtomicUsize,
}

impl CountingEnclave {
    fn new() -> Self {
        Self {
            provider_calls: AtomicUsize::new(0),
        }
    }
}

impl EnclaveManager for CountingEnclave {
    fn initialize(&self) -> ConclaveResult<()> {
        Ok(())
    }

    fn generate_key(&self, _key_id: &str) -> ConclaveResult<String> {
        Err(ConclaveError::Unsupported(
            "counting enclave does not generate keys".to_string(),
        ))
    }

    fn get_public_key(&self, _derivation_path: &str) -> ConclaveResult<String> {
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        Err(ConclaveError::EnclaveFailure(
            "typed opportunity reached provider key boundary".to_string(),
        ))
    }

    fn sign(&self, _request: SignRequest) -> ConclaveResult<SignResponse> {
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        Err(ConclaveError::EnclaveFailure(
            "provider signing should not be reached".to_string(),
        ))
    }

    fn sign_value_bearing_provider(
        &self,
        _request: &ValueBearingSignRequest,
    ) -> ConclaveResult<SignResponse> {
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        Err(ConclaveError::EnclaveFailure(
            "typed provider signing boundary reached".to_string(),
        ))
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
fn every_builtin_adapter_is_gated_before_http_dispatch() {
    let adapters = [
        ("bisq", include_str!("../src/protocol/rails/bisq.rs")),
        ("boltz", include_str!("../src/protocol/rails/boltz.rs")),
        (
            "changelly",
            include_str!("../src/protocol/rails/changelly.rs"),
        ),
        ("ntt", include_str!("../src/protocol/rails/ntt.rs")),
        (
            "wormhole",
            include_str!("../src/protocol/rails/wormhole.rs"),
        ),
        ("x402", include_str!("../src/protocol/rails/x402.rs")),
    ];

    for (name, source) in adapters {
        let gate = source
            .find("super::reject_builtin_adapter_dispatch()?;")
            .unwrap_or_else(|| panic!("{name} must call the shared containment gate"));
        let network_dispatch = source
            .find(".post(")
            .unwrap_or_else(|| panic!("{name} must retain an explicit network boundary"));
        assert!(
            gate < network_dispatch,
            "{name} must reject before constructing or sending an HTTP request"
        );
    }
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

    #[allow(deprecated)]
    let result = rail_proxy
        .broadcast_signed_intent(intent, "opaque-signature".to_string(), None)
        .await;

    assert!(matches!(
        result,
        Err(ConclaveError::Unsupported(message))
            if message.contains("Typed operation-signature envelope required")
    ));
}

#[tokio::test]
async fn production_opportunity_dispatch_reaches_provider_boundary() {
    let enclave = CountingEnclave::new();
    let dispatcher = OpportunityDispatcher::new(&enclave, Arc::new(proxy()));
    let payload = OpportunityPayload::Swap {
        from_chain: Chain::BITCOIN,
        from_symbol: "BTC".to_string(),
        to_chain: Chain::ETHEREUM,
        to_symbol: "ETH".to_string(),
        amount: 100,
        recipient: "merchant".to_string(),
        rail: Some("x402".to_string()),
    };

    let result = dispatcher.execute(payload).await;

    assert!(matches!(
        result,
        Err(ConclaveError::EnclaveFailure(message))
            if message.contains("typed opportunity reached provider key boundary")
    ));
    // The default integration fixture remains software/unverified, so the
    // provider signing callback is intentionally still fail-closed. Reaching
    // key lookup proves the non-test preflight no longer rejects the typed path.
    assert_eq!(enclave.provider_calls.load(Ordering::Relaxed), 1);
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

#[cfg(feature = "development-simulators")]
#[test]
fn development_cloud_cannot_sign_through_production_protocol_boundary() {
    let enclave = CloudEnclave::new_for_development("http://127.0.0.1:9".to_string())
        .expect("development simulator should construct explicitly");
    let ethereum = EthereumManager::new(&enclave);

    let result = ethereum.sign_transaction_hash([0xA5; 32], "m/44'/60'/0'/0/0", "dev-key");

    assert!(matches!(
        result,
        Err(ConclaveError::Unsupported(message))
            if message.contains("software-only")
    ));
}
