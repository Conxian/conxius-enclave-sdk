pub mod config;
pub mod enclave;
pub mod protocol;
pub mod state;
pub mod telemetry;
pub mod wasm_support;

#[cfg(target_arch = "wasm32")]
pub mod wasm_bindings;

pub type ConclaveResult<T> = Result<T, ConclaveError>;

#[derive(Debug, serde::Serialize, serde::Deserialize, thiserror::Error)]
pub enum ConclaveError {
    #[error("Hardware Enclave Error: {0}")]
    EnclaveFailure(String),
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
    #[error("Invalid Payload provided")]
    InvalidPayload,
    #[error("ISO 20022 Error: {0}")]
    IsoError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Rail Error: {0}")]
    RailError(String),
    #[error("Unsupported Chain or Feature: {0}")]
    Unsupported(String),
    #[error("Unsupported WASM runtime: {0}")]
    UnsupportedRuntime(String),
    #[error("Unsupported WASM provider: {0}")]
    UnsupportedProvider(String),
    #[error("WASM secret export is forbidden")]
    SecretExportForbidden,
}

#[cfg(target_arch = "wasm32")]
impl From<ConclaveError> for wasm_bindgen::JsValue {
    fn from(err: ConclaveError) -> Self {
        wasm_bindgen::JsValue::from_str(&err.to_string())
    }
}
