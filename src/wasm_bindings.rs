use wasm_bindgen::prelude::*;
use crate::enclave::{SignRequest, HeadlessEnclave};
use crate::enclave::android_strongbox::CoreEnclaveManager;

#[wasm_bindgen]
pub struct ConclaveWasmClient {
    manager: CoreEnclaveManager,
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        ConclaveWasmClient {
            manager: CoreEnclaveManager::new(),
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

    /// Exposes a flat JS/TS interface for the headless enclave sign method
    #[wasm_bindgen]
    pub fn sign_payload(&self, hex_payload: &str, derivation_path: &str, key_id: &str) -> Result<JsValue, JsValue> {
        let request = SignRequest {
            message_hash: hex::decode(hex_payload)
                .map_err(|e| JsValue::from_str(&format!("Invalid payload hex: {}", e)))?,
            derivation_path: derivation_path.to_string(),
            key_id: key_id.to_string(),
        };

        let response = self.manager.sign(request)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        serde_wasm_bindgen::to_value(&response)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
