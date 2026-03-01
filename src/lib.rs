pub mod enclave;
pub mod protocol;

// Re-export core WebAssembly bindings if the target is WASM
#[cfg(target_arch = "wasm32")]
pub mod wasm_bindings;

/// The core Conclave SDK result type
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
