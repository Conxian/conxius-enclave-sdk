use conxius_enclave_sdk::protocol::account_abstraction::{
    ModularAccountManager, ModuleConfig, ModuleType, SmartAccountAction,
};
use conxius_enclave_sdk::protocol::asset::{AssetIdentifier, AssetMetadata, AssetRegistry, Chain};
use conxius_enclave_sdk::protocol::business::BusinessRegistry;
use conxius_enclave_sdk::protocol::cctp::{CctpAttestation, CctpManager, CctpTransferIntent};
use conxius_enclave_sdk::protocol::intent::SwapRequest;
use conxius_enclave_sdk::protocol::rails::{RailProxy, TrustTier};
use conxius_enclave_sdk::ConclaveError;
use std::sync::Arc;

fn test_evm_address() -> String {
    format!("0x{}", "11".repeat(20))
}

fn cctp_recipient() -> String {
    format!("0x{:0>64}", test_evm_address().trim_start_matches("0x"))
}

fn valid_cctp_intent() -> CctpTransferIntent {
    CctpTransferIntent {
        amount: 1_000_000,
        source_chain: 0,
        destination_chain: 6,
        mint_recipient: cctp_recipient(),
        burn_token: test_evm_address(),
    }
}

fn valid_account_action() -> SmartAccountAction {
    SmartAccountAction {
        target: test_evm_address(),
        value: "1".to_string(),
        call_data: vec![0xa9, 0x05, 0x9c, 0xbb],
    }
}

fn rail_proxy(registry: Arc<AssetRegistry>) -> RailProxy {
    RailProxy::new(
        "http://127.0.0.1:9".to_string(),
        reqwest::Client::new(),
        registry,
        Arc::new(BusinessRegistry::new()),
    )
    .with_min_trust_tier(TrustTier::T3)
}

fn swap_request(from_asset: AssetIdentifier, to_asset: AssetIdentifier) -> SwapRequest {
    SwapRequest {
        from_asset,
        to_asset,
        amount: 100,
        recipient_address: "merchant".to_string(),
        attribution: None,
    }
}

#[test]
fn valid_looking_cctp_inputs_cannot_produce_calldata_or_validate_iris_attestation() {
    let manager = CctpManager::new();
    let intent = valid_cctp_intent();

    assert!(manager.validate_intent(&intent).is_ok());
    assert!(matches!(
        manager.prepare_burn_payload(intent.clone()),
        Err(ConclaveError::Unsupported(message))
            if message.contains("CCTP burn encoding is disabled")
    ));

    let attestation = CctpAttestation {
        signature: vec![],
        message_hash: [0x01; 32],
        source_domain: 0,
        destination_domain: 6,
        nonce: 1,
    };
    // Attestation with bogus hash returns Ok(false) — hash mismatch detected
    assert!(matches!(
        manager.verify_attestation(&intent, &attestation),
        Ok(false)
    ));
}

#[test]
fn valid_looking_erc7579_inputs_cannot_execute_or_claim_module_provenance() {
    let manager = ModularAccountManager::new();
    let action = valid_account_action();
    let module = ModuleConfig {
        module_type: ModuleType::Validator,
        module_address: test_evm_address(),
        init_data: vec![0x01, 0x02, 0x03, 0x04],
    };

    assert!(manager
        .validate_actions(std::slice::from_ref(&action))
        .is_ok());
    assert!(matches!(
        manager.prepare_execution(vec![action]),
        Err(ConclaveError::Unsupported(message))
            if message.contains("network-bound account, entry-point, and module registry")
    ));

    assert!(manager.validate_module_config(&module).is_ok());
    assert!(matches!(
        manager.validate_module_setup_on_network(&module, 1),
        Err(ConclaveError::Unsupported(message))
            if message.contains("compatibility and provenance require on-chain verification")
    ));
}

#[test]
fn conflicting_metadata_cannot_replace_canonical_state_or_change_rail_selection() {
    let registry = Arc::new(AssetRegistry::new());
    let bitcoin = AssetIdentifier {
        chain: Chain::BITCOIN,
        symbol: "BTC".to_string(),
    };
    let ethereum = AssetIdentifier {
        chain: Chain::ETHEREUM,
        symbol: "ETH".to_string(),
    };
    let canonical = registry
        .get_asset(&bitcoin)
        .expect("canonical Bitcoin metadata must exist");

    let conflicting = AssetMetadata {
        name: "Conflicting Bitcoin".to_string(),
        decimals: 18,
        contract_address: Some(test_evm_address()),
        active: true,
    };
    assert!(matches!(
        registry.register_asset(bitcoin.clone(), conflicting),
        Err(ConclaveError::InvalidConfiguration(_))
    ));
    assert_eq!(registry.get_asset(&bitcoin), Some(canonical));

    let selected = rail_proxy(registry)
        .discover_best_rail(&swap_request(bitcoin, ethereum))
        .expect("rejected metadata must not alter canonical rail selection");
    assert_eq!(selected, "x402");
}

#[test]
fn quarantined_unknown_metadata_cannot_enter_rail_selection() {
    let registry = Arc::new(AssetRegistry::new());
    let unknown = AssetIdentifier {
        chain: Chain::ETHEREUM,
        symbol: "UNPROVEN".to_string(),
    };
    registry
        .register_asset(
            unknown.clone(),
            AssetMetadata {
                name: "Unproven Token".to_string(),
                decimals: 18,
                contract_address: Some(test_evm_address()),
                active: false,
            },
        )
        .expect("inactive catalog metadata may remain quarantined");

    let ethereum = AssetIdentifier {
        chain: Chain::ETHEREUM,
        symbol: "ETH".to_string(),
    };
    assert!(matches!(
        rail_proxy(registry).discover_best_rail(&swap_request(unknown, ethereum)),
        Err(ConclaveError::Unsupported(message)) if message.contains("is quarantined")
    ));
}
