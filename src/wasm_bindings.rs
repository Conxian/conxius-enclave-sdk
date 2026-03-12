use wasm_bindgen::prelude::*;
use crate::enclave::{SignRequest, EnclaveManager};
use crate::enclave::android_strongbox::CoreEnclaveManager;
use crate::protocol::business::{BusinessManager, BusinessRegistry, BusinessProfile};
use std::collections::HashMap;

#[wasm_bindgen]
pub struct ConclaveWasmClient {
    manager: CoreEnclaveManager,
    registry: BusinessRegistry,
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        ConclaveWasmClient {
            manager: CoreEnclaveManager::new(),
            registry: BusinessRegistry::new(),
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
        self.registry.register_business(profile);
    }

    /// Exposes a flat JS/TS interface for the headless enclave sign method
    #[wasm_bindgen]
    pub fn sign_payload(&self, hex_payload: &str, derivation_path: &str, key_id: &str) -> Result<JsValue, JsValue> {
        let request = SignRequest {
            message_hash: hex::decode(hex_payload)
                .map_err(|e| JsValue::from_str(&format!("Invalid payload hex: {}", e)))?,
            derivation_path: derivation_path.to_string(),
            key_id: key_id.to_string(),
            taproot_tweak: None,
        };

        let response = self.manager.sign(request)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        serde_wasm_bindgen::to_value(&response)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Securely generates a business attribution proof
    #[wasm_bindgen]
    pub fn generate_attribution(&self, business_id: &str, user_id: &str) -> Result<JsValue, JsValue> {
        // BusinessRegistry is not Clone, but BusinessManager takes ownership of a registry.
        // This is a bit awkward for a persistent client.
        // Let's modify BusinessManager to take a reference if possible,
        // but for now I'll hack it by creating a temporary registry with only the target business.

        let profile = self.registry.get_business(business_id)
            .ok_or_else(|| JsValue::from_str("Business not found"))?;

        let mut temp_registry = BusinessRegistry::new();
        temp_registry.register_business(profile.clone());

        let business_mgr = BusinessManager::new(&self.manager, temp_registry);
        let attribution = business_mgr.generate_attribution(business_id, user_id, HashMap::new())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        serde_wasm_bindgen::to_value(&attribution)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
