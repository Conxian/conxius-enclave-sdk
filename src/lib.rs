pub mod enclave;
pub mod protocol;
pub mod state;
pub mod telemetry;

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
}
