pub mod config;
pub mod enclave;
pub mod protocol;
pub mod state;
pub mod telemetry;
pub mod wasm_support;

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

/// Secret-safe validation failures shared by the protocol boundary models.
///
/// These variants intentionally carry no caller-provided payload. That keeps
/// `Debug`, `Display`, and serde output safe when a boundary rejects malformed
/// or replayed protocol data.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, thiserror::Error,
)]
pub enum BoundaryValidationError {
    #[error("threshold is out of bounds")]
    InvalidThreshold,
    #[error("identifier is invalid")]
    InvalidIdentifier,
    #[error("identifier is duplicated")]
    DuplicateIdentifier,
    #[error("encoding version is unsupported")]
    InvalidEncodingVersion,
    #[error("opaque envelope is invalid")]
    InvalidEnvelope,
    #[error("submission is duplicated")]
    DuplicateSubmission,
    #[error("session owner is not authorized")]
    SessionOwnershipViolation,
    #[error("replayed observation conflicts with the recorded observation")]
    ReplayConflict,
    #[error("state transition is invalid")]
    InvalidStateTransition,
    #[error("external observation is invalid")]
    InvalidObservation,
    #[error("challenge window is invalid")]
    InvalidChallengeWindow,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, thiserror::Error)]
pub enum ConclaveError {
    #[error("Hardware Enclave Error: {0}")]
    EnclaveFailure(String),
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
    #[error("Invalid Payload provided")]
    InvalidPayload,
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("ISO 20022 Error: {0}")]
    IsoError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Rail Error: {0}")]
    RailError(String),
    #[error("BIP-322 error: {0}")]
    Bip322(#[from] protocol::bip322::Bip322Error),
    #[error("Unsupported Chain or Feature: {0}")]
    Unsupported(String),
    #[error("{protocol} {operation} is unsupported: {reason}")]
    ProtocolUnsupported {
        protocol: UnsupportedProtocol,
        operation: UnsupportedOperation,
        reason: UnsupportedReason,
    },
    #[error("protocol boundary validation failed: {0}")]
    BoundaryValidation(BoundaryValidationError),
    #[error("Unsupported WASM runtime: {0}")]
    UnsupportedRuntime(String),
    #[error("Unsupported WASM provider: {0}")]
    UnsupportedProvider(String),
    #[error("WASM secret export is forbidden")]
    SecretExportForbidden,
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
