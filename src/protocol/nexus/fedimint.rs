//! Fedimint Nexus protocol boundary.
//!
//! The adapter exposes typed federation, provider, persistence, operation,
//! and note contracts while keeping value-bearing federation, minting, note,
//! TBS/DLEQ, and threshold operations explicitly unsupported. No network
//! client, cryptographic implementation, or serialized note secret lives in
//! this module.

use crate::{
    protocol_unsupported, BoundaryValidationError, ConclaveError, ConclaveResult,
    UnsupportedOperation, UnsupportedProtocol,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
};

pub const FEDIMINT_ENCODING_VERSION: u16 = 1;

fn boundary_error(kind: BoundaryValidationError) -> ConclaveError {
    ConclaveError::BoundaryValidation(kind)
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedimintEncodingVersion(u16);

impl FedimintEncodingVersion {
    pub fn new(version: u16) -> ConclaveResult<Self> {
        if version == FEDIMINT_ENCODING_VERSION {
            Ok(Self(version))
        } else {
            Err(boundary_error(
                BoundaryValidationError::InvalidEncodingVersion,
            ))
        }
    }

    pub const fn current() -> Self {
        Self(FEDIMINT_ENCODING_VERSION)
    }

    pub fn validate(self) -> ConclaveResult<()> {
        Self::new(self.0).map(|_| ())
    }
}

impl fmt::Debug for FedimintEncodingVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FedimintEncodingVersion")
            .field(&self.0)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FederationId(String);

impl FederationId {
    pub fn new(value: impl Into<String>) -> ConclaveResult<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 || !value.is_ascii() {
            return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FedimintProviderId(String);

impl FedimintProviderId {
    pub fn new(value: impl Into<String>) -> ConclaveResult<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 || !value.is_ascii() {
            return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

/// An invite reference contains only a provider-safe fingerprint. Raw invite
/// URLs/codes remain outside the SDK's serializable model.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedimintInviteRef {
    pub encoding_version: FedimintEncodingVersion,
    pub fingerprint: [u8; 16],
}

impl FedimintInviteRef {
    pub fn new(fingerprint: [u8; 16]) -> ConclaveResult<Self> {
        if fingerprint == [0; 16] {
            return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
        }
        Ok(Self {
            encoding_version: FedimintEncodingVersion::current(),
            fingerprint,
        })
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        if self.fingerprint == [0; 16] {
            return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
        }
        Ok(())
    }
}

impl fmt::Debug for FedimintInviteRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FedimintInviteRef")
            .field("encoding_version", &self.encoding_version)
            .field("fingerprint", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FedimintEnvelopeKind {
    GuardianPublicKey,
    BlindedMessage,
    DleqProof,
    SignatureShare,
    AggregatedSignature,
    NoteSignature,
}

/// Opaque provider/external-protocol material. It carries no raw scalar,
/// blinding factor, note secret, or private key bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedimintOpaqueEnvelope {
    pub encoding_version: FedimintEncodingVersion,
    pub kind: FedimintEnvelopeKind,
    pub digest: [u8; 32],
    pub payload_len: u32,
}

impl FedimintOpaqueEnvelope {
    pub fn new(
        kind: FedimintEnvelopeKind,
        digest: [u8; 32],
        payload_len: u32,
    ) -> ConclaveResult<Self> {
        let envelope = Self {
            encoding_version: FedimintEncodingVersion::current(),
            kind,
            digest,
            payload_len,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        if self.digest == [0; 32] || self.payload_len == 0 {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        Ok(())
    }
}

impl fmt::Debug for FedimintOpaqueEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FedimintOpaqueEnvelope")
            .field("encoding_version", &self.encoding_version)
            .field("kind", &self.kind)
            .field("digest", &"<redacted>")
            .field("payload_len", &self.payload_len)
            .finish()
    }
}

/// Provider-owned handle for a note secret, blinding factor, or other private
/// material. Only a non-secret correlation handle is serialized.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderOwnedHandle {
    pub encoding_version: FedimintEncodingVersion,
    pub handle_id: [u8; 16],
}

impl ProviderOwnedHandle {
    pub fn new(handle_id: [u8; 16]) -> ConclaveResult<Self> {
        if handle_id == [0; 16] {
            return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
        }
        Ok(Self {
            encoding_version: FedimintEncodingVersion::current(),
            handle_id,
        })
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        if self.handle_id == [0; 16] {
            return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
        }
        Ok(())
    }
}

impl fmt::Debug for ProviderOwnedHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderOwnedHandle")
            .field("encoding_version", &self.encoding_version)
            .field("handle_id", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianThreshold {
    pub total_guardians: u16,
    pub threshold: u16,
    pub guardian_keys: Vec<FedimintOpaqueEnvelope>,
}

impl GuardianThreshold {
    pub fn new(
        total: u16,
        threshold: u16,
        keys: Vec<FedimintOpaqueEnvelope>,
    ) -> ConclaveResult<Self> {
        if total == 0 || threshold == 0 || threshold > total || keys.len() != total as usize {
            return Err(boundary_error(BoundaryValidationError::InvalidThreshold));
        }
        let mut unique = BTreeSet::new();
        for key in &keys {
            key.validate()?;
            if key.kind != FedimintEnvelopeKind::GuardianPublicKey || !unique.insert(key.digest) {
                return Err(boundary_error(BoundaryValidationError::DuplicateIdentifier));
            }
        }
        Ok(Self {
            total_guardians: total,
            threshold,
            guardian_keys: keys,
        })
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        Self::new(
            self.total_guardians,
            self.threshold,
            self.guardian_keys.clone(),
        )
        .map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationConfig {
    pub encoding_version: FedimintEncodingVersion,
    pub federation_id: FederationId,
    pub guardian_threshold: GuardianThreshold,
    pub provider_id: FedimintProviderId,
}

impl FederationConfig {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        self.federation_id.validate()?;
        self.provider_id.validate()?;
        self.guardian_threshold.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FedimintBackend {
    Unconfigured,
    ProviderOwned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FedimintOperationState {
    Created,
    Observed,
    Completed,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FedimintOperationId([u8; 16]);

impl FedimintOperationId {
    pub fn new(value: [u8; 16]) -> ConclaveResult<Self> {
        if value == [0; 16] {
            Err(boundary_error(BoundaryValidationError::InvalidIdentifier))
        } else {
            Ok(Self(value))
        }
    }

    pub fn validate(self) -> ConclaveResult<()> {
        Self::new(self.0).map(|_| ())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FedimintOperationOutcome {
    Recorded,
    AlreadyKnown,
}

/// Small persistence/idempotency contract. It records only operation IDs and
/// request digests; it does not persist notes, secrets, or network responses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedimintOperationLedger {
    records: BTreeMap<FedimintOperationId, FedimintOperationRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedimintOperationRecord {
    pub state: FedimintOperationState,
    pub request_digest: [u8; 32],
}

impl FedimintOperationLedger {
    pub fn record(
        &mut self,
        operation_id: FedimintOperationId,
        request_digest: [u8; 32],
    ) -> ConclaveResult<FedimintOperationOutcome> {
        operation_id.validate()?;
        if request_digest == [0; 32] {
            return Err(boundary_error(BoundaryValidationError::InvalidObservation));
        }
        match self.records.get(&operation_id) {
            Some(existing) if existing.request_digest == request_digest => {
                Ok(FedimintOperationOutcome::AlreadyKnown)
            }
            Some(_) => Err(boundary_error(BoundaryValidationError::ReplayConflict)),
            None => {
                self.records.insert(
                    operation_id,
                    FedimintOperationRecord {
                        state: FedimintOperationState::Created,
                        request_digest,
                    },
                );
                Ok(FedimintOperationOutcome::Recorded)
            }
        }
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn state(&self, operation_id: FedimintOperationId) -> Option<FedimintOperationState> {
        self.records.get(&operation_id).map(|record| record.state)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DleqProof {
    pub encoding_version: FedimintEncodingVersion,
    pub challenge: FedimintOpaqueEnvelope,
    pub response: FedimintOpaqueEnvelope,
    pub public_key: FedimintOpaqueEnvelope,
    pub commitment_a: FedimintOpaqueEnvelope,
    pub commitment_b: FedimintOpaqueEnvelope,
}

impl DleqProof {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        for envelope in [
            &self.challenge,
            &self.response,
            &self.public_key,
            &self.commitment_a,
            &self.commitment_b,
        ] {
            envelope.validate()?;
            if envelope.kind != FedimintEnvelopeKind::DleqProof
                && envelope.kind != FedimintEnvelopeKind::GuardianPublicKey
            {
                return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
            }
        }
        Ok(())
    }

    pub fn verify(&self) -> ConclaveResult<bool> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Fedimint,
            UnsupportedOperation::DleqProof,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindSignatureRequest {
    pub encoding_version: FedimintEncodingVersion,
    pub blinded_message: FedimintOpaqueEnvelope,
    pub amount_sats: u64,
    pub dleq_proof: DleqProof,
    pub request_id: FedimintOperationId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialBlindSignature {
    pub guardian_id: u16,
    pub signature_share: FedimintOpaqueEnvelope,
    pub public_key: FedimintOpaqueEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdBlindSignature {
    pub encoding_version: FedimintEncodingVersion,
    pub aggregated_signature: FedimintOpaqueEnvelope,
    pub signature_count: u16,
    pub threshold: u16,
    pub federation_id: FederationId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedimintMintIntent {
    pub encoding_version: FedimintEncodingVersion,
    pub amount_sats: u64,
    pub federation_id: FederationId,
    pub blinded_messages: Vec<FedimintOpaqueEnvelope>,
    pub operation_id: FedimintOperationId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedimintEcash {
    pub notes: Vec<EcashNote>,
    pub total_amount: u64,
    pub proof_of_reserve: Option<FedimintOpaqueEnvelope>,
}

/// An e-cash note never contains the note secret. The provider-owned handle is
/// a correlation token only and its debug representation is redacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcashNote {
    pub federation_id: FederationId,
    pub amount: u64,
    pub provider_handle: ProviderOwnedHandle,
    pub signature: FedimintOpaqueEnvelope,
}

impl EcashNote {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.federation_id.validate()?;
        if self.amount == 0 {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        self.provider_handle.validate()?;
        self.signature.validate()?;
        if self.signature.kind != FedimintEnvelopeKind::NoteSignature {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        Ok(())
    }
}

/// Fedimint adapter boundary. The registry stores only validated public
/// configuration; unsupported operations leave it and the operation ledger
/// unchanged.
pub struct FedimintAdapter {
    pub federations: HashMap<FederationId, FederationConfig>,
    backend: FedimintBackend,
    operation_ledger: FedimintOperationLedger,
}

impl Default for FedimintAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl FedimintAdapter {
    pub fn new() -> Self {
        Self {
            federations: HashMap::new(),
            backend: FedimintBackend::Unconfigured,
            operation_ledger: FedimintOperationLedger::default(),
        }
    }

    pub fn backend(&self) -> FedimintBackend {
        self.backend
    }

    pub fn operation_count(&self) -> usize {
        self.operation_ledger.len()
    }

    pub fn validate_federation_config(config: &FederationConfig) -> ConclaveResult<()> {
        config.validate()
    }

    pub fn record_operation(
        &mut self,
        operation_id: FedimintOperationId,
        request_digest: [u8; 32],
    ) -> ConclaveResult<FedimintOperationOutcome> {
        self.operation_ledger.record(operation_id, request_digest)
    }

    pub fn register_federation(&mut self, _federation_id: &str) -> ConclaveResult<()> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Fedimint,
            UnsupportedOperation::FederationMembership,
        ))
    }

    pub fn join_federation(&mut self, _invite_code: &str) -> ConclaveResult<String> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Fedimint,
            UnsupportedOperation::FederationMembership,
        ))
    }

    pub fn prepare_mint_intent(
        &self,
        _federation_id: &str,
        _amount_sats: u64,
        _provider_handles: Vec<ProviderOwnedHandle>,
    ) -> ConclaveResult<(FedimintMintIntent, Vec<ProviderOwnedHandle>)> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Fedimint,
            UnsupportedOperation::Minting,
        ))
    }

    pub fn issue_ecash(
        &self,
        _intent: FedimintMintIntent,
        _blinding_handles: Vec<ProviderOwnedHandle>,
        _note_handles: Vec<ProviderOwnedHandle>,
    ) -> ConclaveResult<FedimintEcash> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Fedimint,
            UnsupportedOperation::Minting,
        ))
    }

    pub fn verify_note(&self, _note: &EcashNote) -> ConclaveResult<bool> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Fedimint,
            UnsupportedOperation::NoteVerification,
        ))
    }

    pub fn create_dleq_proof(
        &self,
        _provider_handle: ProviderOwnedHandle,
        _public_key: FedimintOpaqueEnvelope,
        _commitment_a: FedimintOpaqueEnvelope,
        _commitment_b: FedimintOpaqueEnvelope,
    ) -> ConclaveResult<DleqProof> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Fedimint,
            UnsupportedOperation::DleqProof,
        ))
    }

    pub fn create_blind_signature_request(
        &self,
        _blinded_message: FedimintOpaqueEnvelope,
        _amount_sats: u64,
        _dleq_proof: DleqProof,
    ) -> ConclaveResult<BlindSignatureRequest> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Fedimint,
            UnsupportedOperation::DleqProof,
        ))
    }

    pub fn aggregate_threshold_signatures(
        &self,
        _partial_signatures: Vec<PartialBlindSignature>,
        _threshold: u16,
        _federation_id: &FederationId,
    ) -> ConclaveResult<ThresholdBlindSignature> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Fedimint,
            UnsupportedOperation::ThresholdAggregation,
        ))
    }

    pub fn validate_threshold_signature(
        &self,
        _signature: &ThresholdBlindSignature,
    ) -> ConclaveResult<bool> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Fedimint,
            UnsupportedOperation::ThresholdAggregation,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UnsupportedReason;

    fn envelope(kind: FedimintEnvelopeKind) -> FedimintOpaqueEnvelope {
        FedimintOpaqueEnvelope::new(kind, [9; 32], 32).expect("valid envelope")
    }

    fn handle() -> ProviderOwnedHandle {
        ProviderOwnedHandle::new([4; 16]).expect("valid provider handle")
    }

    fn federation_id() -> FederationId {
        FederationId::new("fed-1").expect("valid federation id")
    }

    #[test]
    fn validates_thresholds_identifiers_and_versions() {
        assert!(matches!(
            GuardianThreshold::new(0, 0, Vec::new()),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidThreshold
            ))
        ));
        assert!(matches!(
            FederationId::new(""),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidIdentifier
            ))
        ));
        assert!(matches!(
            FedimintEncodingVersion::new(2),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidEncodingVersion
            ))
        ));
        assert!(matches!(
            ProviderOwnedHandle::new([0; 16]),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidIdentifier
            ))
        ));
    }

    #[test]
    fn operation_ledger_is_idempotent_and_rejects_conflicting_replay() {
        let mut ledger = FedimintOperationLedger::default();
        let operation = FedimintOperationId::new([1; 16]).expect("valid operation id");
        assert_eq!(
            ledger
                .record(operation, [2; 32])
                .expect("records operation"),
            FedimintOperationOutcome::Recorded
        );
        assert_eq!(
            ledger.state(operation),
            Some(FedimintOperationState::Created)
        );
        assert_eq!(
            ledger
                .record(operation, [2; 32])
                .expect("duplicate is idempotent"),
            FedimintOperationOutcome::AlreadyKnown
        );
        assert!(matches!(
            ledger.record(operation, [3; 32]),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::ReplayConflict
            ))
        ));
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn note_serialization_and_debug_do_not_expose_a_secret() {
        let note = EcashNote {
            federation_id: federation_id(),
            amount: 1000,
            provider_handle: handle(),
            signature: envelope(FedimintEnvelopeKind::NoteSignature),
        };
        let json = serde_json::to_string(&note).expect("note metadata serializes");
        let debug = format!("{note:?}");
        assert!(!json.contains("secret-value"));
        assert!(!debug.contains("secret-value"));
        assert!(!debug.contains("[4, 4, 4"));
        assert_ne!(note.provider_handle.handle_id, [0; 16]);
    }

    #[test]
    fn unsupported_operations_do_not_mutate_adapter_state() {
        let mut adapter = FedimintAdapter::new();
        let before_federations = adapter.federations.len();
        let before_operations = adapter.operation_count();
        let operation = FedimintOperationId::new([1; 16]).expect("valid operation id");
        let intent = FedimintMintIntent {
            encoding_version: FedimintEncodingVersion::current(),
            amount_sats: 1000,
            federation_id: federation_id(),
            blinded_messages: vec![envelope(FedimintEnvelopeKind::BlindedMessage)],
            operation_id: operation,
        };
        let note = EcashNote {
            federation_id: federation_id(),
            amount: 1000,
            provider_handle: handle(),
            signature: envelope(FedimintEnvelopeKind::NoteSignature),
        };

        assert_unsupported(
            adapter.register_federation("fed-1"),
            UnsupportedOperation::FederationMembership,
        );
        assert_unsupported(
            adapter.join_federation("invite"),
            UnsupportedOperation::FederationMembership,
        );
        assert_unsupported(
            adapter.prepare_mint_intent("fed-1", 1000, vec![handle()]),
            UnsupportedOperation::Minting,
        );
        assert_unsupported(
            adapter.issue_ecash(intent, vec![handle()], vec![handle()]),
            UnsupportedOperation::Minting,
        );
        assert_unsupported(
            adapter.verify_note(&note),
            UnsupportedOperation::NoteVerification,
        );
        assert_eq!(adapter.federations.len(), before_federations);
        assert_eq!(adapter.operation_count(), before_operations);
        assert_eq!(adapter.backend(), FedimintBackend::Unconfigured);
    }

    fn assert_unsupported<T>(result: ConclaveResult<T>, operation: UnsupportedOperation) {
        match result {
            Err(ConclaveError::ProtocolUnsupported {
                protocol: UnsupportedProtocol::Fedimint,
                operation: actual_operation,
                reason: UnsupportedReason::NoAuditedImplementation,
            }) => assert_eq!(actual_operation, operation),
            _ => panic!("expected typed Fedimint unsupported error"),
        }
    }
}
