pub mod config;
pub mod enclave;
pub mod protocol;
pub mod state;
pub mod telemetry;

#[cfg(target_arch = "wasm32")]
pub mod wasm_bindings;

pub type ConclaveResult<T> = Result<T, ConclaveError>;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, thiserror::Error,
)]
pub enum UnsupportedProtocol {
    #[error("FROST")]
    Frost,
    #[error("Fedimint")]
    Fedimint,
    #[error("Ark")]
    Ark,
    #[error("BitVM2")]
    BitVm2,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, thiserror::Error,
)]
pub enum UnsupportedOperation {
    #[error("key package generation")]
    KeyPackageGeneration,
    #[error("DKG")]
    Dkg,
    #[error("threshold signing")]
    ThresholdSigning,
    #[error("federation registration or joining")]
    FederationMembership,
    #[error("minting")]
    Minting,
    #[error("note verification")]
    NoteVerification,
    #[error("DLEQ proof generation or verification")]
    DleqProof,
    #[error("threshold signature aggregation or validation")]
    ThresholdAggregation,
    #[error("V-UTXO key derivation")]
    VutxoKeyDerivation,
    #[error("V-UTXO recovery scan")]
    RecoveryScan,
    #[error("vTXO tree construction")]
    VtxoTreeConstruction,
    #[error("forfeit construction")]
    ForfeitConstruction,
    #[error("forfeit signing")]
    ForfeitSigning,
    #[error("commitment posting")]
    CommitmentPosting,
    #[error("challenge submission")]
    ChallengeSubmission,
    #[error("challenge resolution")]
    ChallengeResolution,
    #[error("challenge status")]
    ChallengeStatus,
    #[error("challenge-window evaluation")]
    ChallengeWindow,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, thiserror::Error,
)]
pub enum UnsupportedReason {
    #[error("no audited implementation is available")]
    NoAuditedImplementation,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, thiserror::Error)]
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
    #[error("{protocol} {operation} is unsupported: {reason}")]
    ProtocolUnsupported {
        protocol: UnsupportedProtocol,
        operation: UnsupportedOperation,
        reason: UnsupportedReason,
    },
}

pub(crate) fn protocol_unsupported(
    protocol: UnsupportedProtocol,
    operation: UnsupportedOperation,
) -> ConclaveError {
    ConclaveError::ProtocolUnsupported {
        protocol,
        operation,
        reason: UnsupportedReason::NoAuditedImplementation,
    }
}

#[cfg(target_arch = "wasm32")]
impl From<ConclaveError> for wasm_bindgen::JsValue {
    fn from(err: ConclaveError) -> Self {
        wasm_bindgen::JsValue::from_str(&err.to_string())
    }
}
