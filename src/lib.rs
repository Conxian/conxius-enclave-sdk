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
    use crate::protocol::rails::{RailProxy, SwapRequest, SovereignHandshake, ChangellyRail, BisqRail, BoltzRail};
    use crate::protocol::business::{BusinessManager, BusinessRegistry, BusinessProfile};
    use crate::protocol::asset::{AssetRegistry, Asset, AssetIdentifier};
    use crate::protocol::bitcoin::TaprootManager;
    use std::sync::Arc;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_sovereign_rail_swap_btc() {
        let manager = CoreEnclaveManager::new();
        manager.derive_session_key("1234", b"salt").unwrap();

        let asset_registry = Arc::new(AssetRegistry::new());
        let business_registry = Arc::new(BusinessRegistry::new());
        let mut proxy = RailProxy::new("https://api.gateway.com".to_string(), None, asset_registry, business_registry);
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
    async fn test_boltz_rail_fast_swap() {
        let manager = CoreEnclaveManager::new();
        manager.derive_session_key("1234", b"salt").unwrap();

        let asset_registry = Arc::new(AssetRegistry::new());
        let business_registry = Arc::new(BusinessRegistry::new());
        let mut proxy = RailProxy::new("https://api.gateway.com".to_string(), None, asset_registry, business_registry);
        proxy.register_rail(Box::new(BoltzRail));

        let req = SwapRequest {
            from_asset: AssetIdentifier { chain: "BTC".to_string(), symbol: "BTC".to_string() },
            to_asset: AssetIdentifier { chain: "LIGHTNING".to_string(), symbol: "BTC".to_string() },
            amount: 60_000,
            recipient_address: "lnbc1...".to_string(),
            attribution: None,
        };

        let intent = proxy.prepare_intent("Boltz", req).unwrap();
        assert_eq!(intent.chain_context.as_ref().unwrap(), "BOLTZ_SUBMARINE_SWAP_v1");

        let response = proxy.broadcast_signed_intent(
            intent,
            "mock_sig".to_string(),
            None
        ).await;

        assert!(response.is_err());
    }

    #[tokio::test]
    async fn test_bisq_rail_minimum_amount() {
        let asset_registry = Arc::new(AssetRegistry::new());
        let business_registry = Arc::new(BusinessRegistry::new());
        let mut proxy = RailProxy::new("https://api.gateway.com".to_string(), None, asset_registry, business_registry);
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

    #[tokio::test]
    async fn test_cloud_enclave_signing() {
        use crate::enclave::cloud::CloudEnclave;
        let enclave = CloudEnclave::new("https://kms.conclave.io".to_string());

        let message_hash = vec![0xaa; 32];
        let request = SignRequest {
            message_hash: message_hash.clone(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            key_id: "cloud_test".to_string(),
            taproot_tweak: None,
        };

        let response = enclave.sign(request).unwrap();
        assert!(!response.signature_hex.is_empty());

        let attestation_json = response.device_attestation.unwrap();
        let attestation: DeviceIntegrityReport = serde_json::from_str(&attestation_json).unwrap();
        assert!(attestation.verify(&message_hash));
        assert_eq!(attestation.level, crate::enclave::attestation::AttestationLevel::CloudTEE);
    }

    #[tokio::test]
    async fn test_rail_proxy_with_attribution() {
        let manager = CoreEnclaveManager::new();
        manager.derive_session_key("1234", b"salt").unwrap();

        let asset_registry = Arc::new(AssetRegistry::new());
        let mut business_registry = BusinessRegistry::new();
        business_registry.register_business(BusinessProfile {
            id: "partner_01".to_string(),
            name: "Partner".to_string(),
            public_key: "pubkey".to_string(),
            active: true,
        });
        let business_registry = Arc::new(business_registry);

        let mut proxy = RailProxy::new("https://api.gateway.com".to_string(), None, asset_registry, business_registry.clone());
        proxy.register_rail(Box::new(ChangellyRail));

        let business_manager = BusinessManager::new(&manager, (*business_registry).clone());
        let attribution = business_manager.generate_attribution("partner_01", "user_1", HashMap::new()).unwrap();

        let req = SwapRequest {
            from_asset: AssetIdentifier { chain: "BTC".to_string(), symbol: "BTC".to_string() },
            to_asset: AssetIdentifier { chain: "ETH".to_string(), symbol: "ETH".to_string() },
            amount: 5000,
            recipient_address: "0x123...".to_string(),
            attribution: Some(attribution),
        };

        let intent = proxy.prepare_intent("Changelly", req).unwrap();
        let sig_resp = manager.sign(SignRequest {
            message_hash: intent.signable_hash.clone(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            key_id: "test".to_string(),
            taproot_tweak: None,
        }).unwrap();

        let response = proxy.broadcast_signed_intent(
            intent,
            sig_resp.signature_hex,
            sig_resp.device_attestation
        ).await.unwrap();

        assert!(response.transaction_id.contains("CHG-PX-"));
    }

    #[tokio::test]
    async fn test_dynamic_asset_registration() {
        let asset_registry = Arc::new(AssetRegistry::new());
        let business_registry = Arc::new(BusinessRegistry::new());
        let mut proxy = RailProxy::new("https://api.gateway.com".to_string(), None, asset_registry.clone(), business_registry);

        // Register a new rail that supports the new asset
        proxy.register_rail(Box::new(ChangellyRail));

        let new_asset = Asset {
            identifier: AssetIdentifier { chain: "SOL".to_string(), symbol: "SOL".to_string() },
            name: "Solana".to_string(),
            decimals: 9,
            contract_address: None,
            active: true,
        };

        // Initially SOL should fail
        let req = SwapRequest {
            from_asset: AssetIdentifier { chain: "BTC".to_string(), symbol: "BTC".to_string() },
            to_asset: AssetIdentifier { chain: "SOL".to_string(), symbol: "SOL".to_string() },
            amount: 1000,
            recipient_address: "sol_address".to_string(),
            attribution: None,
        };
        assert!(proxy.prepare_intent("Changelly", req.clone()).is_err());

        // Register asset
        let mut registry = (*asset_registry).clone();
        registry.register_asset(new_asset);
        let asset_registry = Arc::new(registry);

        let mut proxy = RailProxy::new("https://api.gateway.com".to_string(), None, asset_registry, Arc::new(BusinessRegistry::new()));
        proxy.register_rail(Box::new(ChangellyRail));

        // Now SOL should pass
        assert!(proxy.prepare_intent("Changelly", req).is_ok());
    }

    #[test]
    fn test_business_identity_generation() {
        let manager = CoreEnclaveManager::new();
        manager.derive_session_key("1234", b"salt").unwrap();
        let business_mgr = BusinessManager::new(&manager, BusinessRegistry::new());

        let profile = business_mgr.generate_business_identity("new_partner", "New Partner Name").unwrap();
        assert_eq!(profile.id, "new_partner");
        assert_eq!(profile.name, "New Partner Name");
        assert!(!profile.public_key.is_empty());
    }
}
