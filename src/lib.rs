pub mod enclave;
pub mod protocol;
pub mod telemetry;

#[cfg(target_arch = "wasm32")]
pub mod wasm_bindings;

pub type ConclaveResult<T> = Result<T, ConclaveError>;

#[derive(Debug, thiserror::Error)]
pub enum ConclaveError {
    #[error("Hardware Enclave Error: {0}")]
    EnclaveFailure(String),
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
    #[error("Invalid Payload provided")]
    InvalidPayload,
}

#[cfg(test)]
mod tests {
    use crate::enclave::android_strongbox::CoreEnclaveManager;
    use crate::enclave::{EnclaveManager, SignRequest};
    use crate::enclave::attestation::DeviceIntegrityReport;
    use crate::protocol::stacks::StacksManager;
    use crate::protocol::rails::{RailProxy, SwapRequest, SovereignHandshake, ChangellyRail, BisqRail};
    use crate::protocol::business::{BusinessManager, BusinessRegistry, BusinessProfile};
    use crate::protocol::asset::{AssetRegistry, AssetIdentifier};
    use crate::protocol::bitcoin::TaprootManager;
    use std::sync::Arc;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_sovereign_rail_swap_btc() {
        let manager = CoreEnclaveManager::new();
        manager.derive_session_key("1234", b"salt").unwrap();

        let asset_registry = Arc::new(AssetRegistry::new());
        let mut proxy = RailProxy::new("https://api.gateway.com".to_string(), None, asset_registry);
        proxy.register_rail(Box::new(ChangellyRail));

        let req = SwapRequest {
            from_asset: AssetIdentifier { chain: "BTC".to_string(), symbol: "BTC".to_string() },
            to_asset: AssetIdentifier { chain: "ETH".to_string(), symbol: "ETH".to_string() },
            amount: 1000,
            recipient_address: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh".to_string(),
            attribution: None,
        };

        // 1. Prepare intent
        let intent = proxy.prepare_intent("Changelly", req).unwrap();

        // 2. Sign in enclave
        let sig_resp = manager.sign(SignRequest {
            message_hash: intent.signable_hash.clone(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            key_id: "test".to_string(),
            taproot_tweak: None,
        }).unwrap();

        // 3. Broadcast
        let response = proxy.broadcast_signed_intent(
            intent,
            sig_resp.signature_hex,
            sig_resp.device_attestation
        ).await.unwrap();

        assert!(response.transaction_id.starts_with("CHG-PX-"));
    }

    #[tokio::test]
    async fn test_bisq_rail_minimum_amount() {
        let asset_registry = Arc::new(AssetRegistry::new());
        let mut proxy = RailProxy::new("https://api.gateway.com".to_string(), None, asset_registry);
        proxy.register_rail(Box::new(BisqRail));

        let req = SwapRequest {
            from_asset: AssetIdentifier { chain: "BTC".to_string(), symbol: "BTC".to_string() },
            to_asset: AssetIdentifier { chain: "ETH".to_string(), symbol: "ETH".to_string() },
            amount: 1000, // Below minimum for Bisq
            recipient_address: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh".to_string(),
            attribution: None,
        };

        let result = proxy.prepare_intent("Bisq", req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("minimum amount"));
    }

    #[test]
    fn test_business_attribution_flow() {
        let manager = CoreEnclaveManager::new();
        manager.derive_session_key("1234", b"salt").unwrap();

        let mut registry = BusinessRegistry::new();
        registry.register_business(BusinessProfile {
            id: "partner_01".to_string(),
            name: "Test Partner".to_string(),
            public_key: "0x123...".to_string(),
            active: true,
        });

        let business_manager = BusinessManager::new(&manager, registry);
        let attribution = business_manager.generate_attribution(
            "partner_01",
            "user_42",
            HashMap::new()
        ).unwrap();

        assert_eq!(attribution.business_id, "partner_01");
        assert!(!attribution.signature.is_empty());
    }

    #[test]
    fn test_bitcoin_taproot_signing() {
        let manager = CoreEnclaveManager::new();
        manager.derive_session_key("1234", b"salt").unwrap();
        let btc = TaprootManager::new(&manager);

        let sighash = [0u8; 32];
        let sig = btc.sign_taproot_sighash(sighash, "m/86'/0'/0'/0/0", "btc_test").unwrap();
        assert!(!sig.is_empty());
        assert_eq!(sig.len(), 128);
    }

    #[test]
    fn test_enclave_signing_and_attestation() {
        let manager = CoreEnclaveManager::new();
        manager.derive_session_key("1234", b"salt").unwrap();

        let message_hash = vec![0u8; 32];
        let request = SignRequest {
            message_hash: message_hash.clone(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            key_id: "test".to_string(),
            taproot_tweak: None,
        };

        let response = manager.sign(request).unwrap();
        let attestation_json = response.device_attestation.unwrap();
        let attestation: DeviceIntegrityReport = serde_json::from_str(&attestation_json).unwrap();
        assert!(attestation.verify(&message_hash));
    }
}
