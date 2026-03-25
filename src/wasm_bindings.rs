use wasm_bindgen::prelude::*;
use crate::enclave::{SignRequest, EnclaveManager};
use crate::enclave::android_strongbox::CoreEnclaveManager;
use crate::protocol::business::{BusinessManager, BusinessRegistry, BusinessProfile};
use crate::protocol::asset::{AssetRegistry, Asset, AssetIdentifier};
use crate::protocol::rails::{RailProxy, SwapRequest, SovereignHandshake, ChangellyRail, BisqRail, WormholeRail};
use crate::protocol::stacks::StacksManager;
use crate::protocol::bitcoin::TaprootManager;
use crate::protocol::fiat::{FiatRouterService, FiatOnRampRequest};
use crate::protocol::a2p::{A2pRouterService, OtpRequest, OtpVerificationRequest};
use std::collections::HashMap;
use std::sync::Arc;

#[wasm_bindgen]
pub struct ConclaveWasmClient {
    manager: CoreEnclaveManager,
    business_registry: Arc<BusinessRegistry>,
    asset_registry: Arc<AssetRegistry>,
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        ConclaveWasmClient {
            manager: CoreEnclaveManager::new(),
            business_registry: Arc::new(BusinessRegistry::new()),
            asset_registry: Arc::new(AssetRegistry::new()),
        }
    }

    /// Derives the session key from a PIN and salt
    #[wasm_bindgen]
    pub fn set_session_key(&self, pin: &str, salt_hex: &str) -> Result<(), JsValue> {
        let salt = hex::decode(salt_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid salt hex: {}", e)))?;

        self.manager.derive_session_key(pin, &salt)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Registers a business profile for attribution
    #[wasm_bindgen]
    pub fn register_business(&mut self, id: &str, name: &str, public_key: &str) {
        let profile = BusinessProfile {
            id: id.to_string(),
            name: name.to_string(),
            public_key: public_key.to_string(),
            active: true,
        };
        let mut registry = (*self.business_registry).clone();
        registry.register_business(profile);
        self.business_registry = Arc::new(registry);
    }

    /// Registers a custom asset in the registry
    #[wasm_bindgen]
    pub fn register_asset(&mut self, chain: &str, symbol: &str, name: &str, decimals: u8, contract_address: Option<String>) {
        let asset = Asset {
            identifier: AssetIdentifier { chain: chain.to_string(), symbol: symbol.to_string() },
            name: name.to_string(),
            decimals,
            contract_address,
            active: true,
        };
        let mut registry = (*self.asset_registry).clone();
        registry.register_asset(asset);
        self.asset_registry = Arc::new(registry);
    }

    /// Generates a new hardware-backed business identity
    #[wasm_bindgen]
    pub fn generate_business_identity(&self, business_id: &str, name: &str) -> Result<JsValue, JsValue> {
        let business_mgr = BusinessManager::new(&self.manager, (*self.business_registry).clone());
        let profile = business_mgr.generate_business_identity(business_id, name)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        serde_wasm_bindgen::to_value(&profile)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Securely generates a business attribution proof
    #[wasm_bindgen]
    pub fn generate_attribution(&self, business_id: &str, user_id: &str) -> Result<JsValue, JsValue> {
        let business_mgr = BusinessManager::new(&self.manager, (*self.business_registry).clone());
        let attribution = business_mgr.generate_attribution(business_id, user_id, HashMap::new())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        serde_wasm_bindgen::to_value(&attribution)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// High-level helper to execute a sovereign swap
    #[wasm_bindgen]
    pub async fn execute_swap(
        &self,
        rail_name: &str,
        from_chain: &str,
        from_symbol: &str,
        to_chain: &str,
        to_symbol: &str,
        amount: u64,
        recipient: &str,
        business_id: Option<String>
    ) -> Result<JsValue, JsValue> {
        let mut proxy = RailProxy::new(
            "https://api.conxian.io".to_string(),
            None,
            self.asset_registry.clone(),
            self.business_registry.clone()
        );
        proxy.register_rail(Box::new(ChangellyRail));
        proxy.register_rail(Box::new(BisqRail));
        proxy.register_rail(Box::new(WormholeRail));

        let attribution = if let Some(bid) = business_id {
            let business_mgr = BusinessManager::new(&self.manager, (*self.business_registry).clone());
            Some(business_mgr.generate_attribution(&bid, "user_default", HashMap::new())
                .map_err(|e| JsValue::from_str(&e.to_string()))?)
        } else {
            None
        };

        let request = SwapRequest {
            from_asset: AssetIdentifier { chain: from_chain.to_string(), symbol: from_symbol.to_string() },
            to_asset: AssetIdentifier { chain: to_chain.to_string(), symbol: to_symbol.to_string() },
            amount,
            recipient_address: recipient.to_string(),
            attribution,
        };

        let intent = proxy.prepare_intent(rail_name, request)
            .map_err(|e| JsValue::from_str(&e))?;

        let sig_resp = self.manager.sign(SignRequest {
            message_hash: intent.signable_hash.clone(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            key_id: "swap_key".to_string(),
            taproot_tweak: None,
        }).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let response = proxy.broadcast_signed_intent(
            intent,
            sig_resp.signature_hex,
            sig_resp.device_attestation
        ).await.map_err(|e| JsValue::from_str(&e))?;

        serde_wasm_bindgen::to_value(&response)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Create a stateless fiat on-ramp session
    #[wasm_bindgen]
    pub async fn create_fiat_session(
        &self,
        fiat_currency: &str,
        to_chain: &str,
        to_symbol: &str,
        amount: f64,
        wallet_address: &str,
        provider: &str,
        business_id: Option<String>
    ) -> Result<JsValue, JsValue> {
        let fiat_service = FiatRouterService::new("https://api.conxian.io".to_string());

        let attribution = if let Some(bid) = business_id {
            let business_mgr = BusinessManager::new(&self.manager, (*self.business_registry).clone());
            Some(business_mgr.generate_attribution(&bid, "user_default", HashMap::new())
                .map_err(|e| JsValue::from_str(&e.to_string()))?)
        } else {
            None
        };

        let request = FiatOnRampRequest {
            fiat_currency: fiat_currency.to_string(),
            crypto_asset: AssetIdentifier { chain: to_chain.to_string(), symbol: to_symbol.to_string() },
            amount,
            wallet_address: wallet_address.to_string(),
            provider: provider.to_string(),
            attribution,
        };

        let intent = fiat_service.prepare_session(request);

        let sig_resp = self.manager.sign(SignRequest {
            message_hash: intent.signable_hash.clone(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            key_id: "fiat_key".to_string(),
            taproot_tweak: None,
        }).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let response = fiat_service.create_session(intent, sig_resp.signature_hex)
            .await.map_err(|e| JsValue::from_str(&e))?;

        serde_wasm_bindgen::to_value(&response)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Initiate stateless phone verification
    #[wasm_bindgen]
    pub async fn initiate_phone_verification(
        &self,
        phone_number: &str,
        channel: &str,
        business_id: Option<String>
    ) -> Result<JsValue, JsValue> {
        let a2p_service = A2pRouterService::new("https://api.conxian.io".to_string());

        let attribution = if let Some(bid) = business_id {
            let business_mgr = BusinessManager::new(&self.manager, (*self.business_registry).clone());
            Some(business_mgr.generate_attribution(&bid, "user_default", HashMap::new())
                .map_err(|e| JsValue::from_str(&e.to_string()))?)
        } else {
            None
        };

        let request = OtpRequest {
            phone_number: phone_number.to_string(),
            channel: channel.to_string(),
            attribution,
        };

        let intent = a2p_service.prepare_otp(request);

        let _sig_resp = self.manager.sign(SignRequest {
            message_hash: intent.signable_hash.clone(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            key_id: "a2p_key".to_string(),
            taproot_tweak: None,
        }).map_err(|e| JsValue::from_str(&e.to_string()))?;

        // In a real implementation, we would broadcast the signed intent to the gateway
        Ok(serde_wasm_bindgen::to_value(&format!("OTP sent to {}", phone_number)).unwrap())
    }

    /// Sign a Stacks transaction payload
    #[wasm_bindgen]
    pub fn sign_stacks_transaction(&self, payload_hex: &str) -> Result<String, JsValue> {
        let payload = hex::decode(payload_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid payload hex: {}", e)))?;

        let stacks_mgr = StacksManager::new(&self.manager);
        let intent = stacks_mgr.prepare_transaction(&payload)
            .map_err(|e| JsValue::from_str(&e))?;

        let signature = stacks_mgr.sign_prepared_transaction(intent, "stacks_key")
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(signature)
    }

    /// Sign a Bitcoin Taproot (BIP341) sighash
    #[wasm_bindgen]
    pub fn sign_bitcoin_taproot(&self, sighash_hex: &str, merkle_root_hex: Option<String>) -> Result<String, JsValue> {
        let mut sighash = [0u8; 32];
        let decoded_sighash = hex::decode(sighash_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid sighash hex: {}", e)))?;
        sighash.copy_from_slice(&decoded_sighash);

        let merkle_root = if let Some(mr_hex) = merkle_root_hex {
            let mut mr = [0u8; 32];
            let decoded_mr = hex::decode(mr_hex)
                .map_err(|e| JsValue::from_str(&format!("Invalid merkle root hex: {}", e)))?;
            mr.copy_from_slice(&decoded_mr);
            Some(mr)
        } else {
            None
        };

        let btc_mgr = TaprootManager::new(&self.manager);
        let signature = btc_mgr.sign_taproot_v1(
            sighash,
            "m/86'/0'/0'/0/0",
            "btc_key",
            merkle_root
        ).map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(signature)
    }
}
