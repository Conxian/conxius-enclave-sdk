//! BitVM2 protocol boundary.
//!
//! This module models roles, instances, commitments, chain observations,
//! challenge windows, transaction templates, disprove envelopes, backends,
//! and monitoring state. It does not post commitments, construct or sign
//! transactions, verify proofs, resolve challenges, or access a network.

use crate::protocol::ark::{ArkTransactionId, VUtxoDescriptor};
use crate::protocol::bitvm::BitVmManager;
use crate::{
    protocol_unsupported, BoundaryValidationError, ConclaveError, ConclaveResult,
    UnsupportedOperation, UnsupportedProtocol,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

pub const BITVM2_ENCODING_VERSION: u16 = 1;

fn boundary_error(kind: BoundaryValidationError) -> ConclaveError {
    ConclaveError::BoundaryValidation(kind)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2EncodingVersion(u16);

impl BitVm2EncodingVersion {
    pub fn new(version: u16) -> ConclaveResult<Self> {
        if version == BITVM2_ENCODING_VERSION {
            Ok(Self(version))
        } else {
            Err(boundary_error(
                BoundaryValidationError::InvalidEncodingVersion,
            ))
        }
    }

    pub const fn current() -> Self {
        Self(BITVM2_ENCODING_VERSION)
    }

    pub fn validate(self) -> ConclaveResult<()> {
        Self::new(self.0).map(|_| ())
    }
}

macro_rules! bytes_id {
    ($name:ident, $size:expr) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        pub struct $name([u8; $size]);

        impl $name {
            pub fn new(value: [u8; $size]) -> ConclaveResult<Self> {
                if value == [0; $size] {
                    return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
                }
                Ok(Self(value))
            }

            pub fn validate(self) -> ConclaveResult<()> {
                Self::new(self.0).map(|_| ())
            }

            pub const fn bytes(self) -> [u8; $size] {
                self.0
            }
        }
    };
}

bytes_id!(BitVm2InstanceId, 16);
bytes_id!(BitVm2CommitmentId, 16);
bytes_id!(BitVm2ObservationId, 16);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BitVm2ChainId(String);

impl BitVm2ChainId {
    pub fn new(value: impl Into<String>) -> ConclaveResult<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 64 || !value.is_ascii() {
            return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
        }
        Ok(Self(value))
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitVm2Role {
    Operator,
    Challenger,
    Verifier,
    Monitor,
}

/// Challenge-window semantics are inclusive at both boundaries. This is a
/// local structural rule only; it is not a chain observation or timeout proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2ChallengeWindow {
    pub start_block: u64,
    pub end_block: u64,
}

impl BitVm2ChallengeWindow {
    pub fn new(start_block: u64, end_block: u64) -> ConclaveResult<Self> {
        if end_block < start_block {
            return Err(boundary_error(
                BoundaryValidationError::InvalidChallengeWindow,
            ));
        }
        Ok(Self {
            start_block,
            end_block,
        })
    }

    pub const fn contains(self, block_height: u64) -> bool {
        block_height >= self.start_block && block_height <= self.end_block
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitVm2ObservationKind {
    CommitmentPosted,
    ChallengeObserved,
    ResolutionObserved,
    TimeoutObserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalChainObservation {
    pub encoding_version: BitVm2EncodingVersion,
    pub observation_id: BitVm2ObservationId,
    pub instance_id: BitVm2InstanceId,
    pub chain_id: BitVm2ChainId,
    pub kind: BitVm2ObservationKind,
    pub block_height: u64,
    pub event_digest: [u8; 32],
}

impl ExternalChainObservation {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        self.observation_id.validate()?;
        self.instance_id.validate()?;
        self.chain_id.validate()?;
        if self.event_digest == [0; 32] {
            return Err(boundary_error(BoundaryValidationError::InvalidObservation));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationOutcome {
    Recorded,
    AlreadyKnown,
}

/// Durable monitor state is fed only by externally observed chain events.
/// Replaying the same event is idempotent; reusing an observation ID for a
/// different event is rejected as a conflict.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2ObservationLedger {
    observations: HashMap<BitVm2ObservationId, ExternalChainObservation>,
}

impl BitVm2ObservationLedger {
    pub fn observe(
        &mut self,
        observation: ExternalChainObservation,
    ) -> ConclaveResult<ObservationOutcome> {
        observation.validate()?;
        match self.observations.get(&observation.observation_id) {
            Some(existing) if existing == &observation => Ok(ObservationOutcome::AlreadyKnown),
            Some(_) => Err(boundary_error(BoundaryValidationError::ReplayConflict)),
            None => {
                self.observations
                    .insert(observation.observation_id, observation);
                Ok(ObservationOutcome::Recorded)
            }
        }
    }

    pub fn len(&self) -> usize {
        self.observations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitVm2Backend {
    Unconfigured,
    ProviderOwned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2TransactionTemplate {
    pub encoding_version: BitVm2EncodingVersion,
    pub instance_id: BitVm2InstanceId,
    pub template_digest: [u8; 32],
    pub input_count: u16,
    pub output_count: u16,
}

impl BitVm2TransactionTemplate {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        self.instance_id.validate()?;
        if self.template_digest == [0; 32] || self.output_count == 0 {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2DisproveEnvelope {
    pub encoding_version: BitVm2EncodingVersion,
    pub digest: [u8; 32],
    pub payload_len: u32,
}

impl BitVm2DisproveEnvelope {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        if self.digest == [0; 32] || self.payload_len == 0 {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        Ok(())
    }
}

/// Challenge phase in the BitVM2 dispute protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengePhase {
    None,
    Commitment,
    Challenge,
    ResolvedPenalty,
    ResolvedRelease,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2ChallengeStatus {
    pub phase: ChallengePhase,
    pub instance_id: BitVm2InstanceId,
    pub commitment_id: BitVm2CommitmentId,
    pub commitment_txid: Option<ArkTransactionId>,
    pub challenge_txid: Option<ArkTransactionId>,
    pub challenge_block: Option<u64>,
    pub resolution: Option<BitVm2ObservationId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2ForfeitTransaction {
    pub encoding_version: BitVm2EncodingVersion,
    pub instance_id: BitVm2InstanceId,
    pub commitment_id: BitVm2CommitmentId,
    pub vutxo: VUtxoDescriptor,
    pub tree_root: ArkTransactionId,
    pub template: BitVm2TransactionTemplate,
    pub challenge_window: BitVm2ChallengeWindow,
    pub csv_delay: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2Commitment {
    pub encoding_version: BitVm2EncodingVersion,
    pub instance_id: BitVm2InstanceId,
    pub commitment_id: BitVm2CommitmentId,
    pub role: BitVm2Role,
    pub state_root_hash: [u8; 32],
    pub vtxo_count: u32,
    pub merkle_root: [u8; 32],
    pub taproot_internal_key: [u8; 32],
    pub block_height: u64,
    pub challenge_window: BitVm2ChallengeWindow,
}

impl BitVm2Commitment {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        self.instance_id.validate()?;
        self.commitment_id.validate()?;
        self.challenge_window.validate()?;
        if self.state_root_hash == [0; 32]
            || self.merkle_root == [0; 32]
            || self.taproot_internal_key == [0; 32]
            || self.vtxo_count == 0
        {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        Ok(())
    }
}

impl BitVm2ChallengeWindow {
    pub fn validate(self) -> ConclaveResult<()> {
        Self::new(self.start_block, self.end_block).map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2ChallengeResponse {
    pub encoding_version: BitVm2EncodingVersion,
    pub instance_id: BitVm2InstanceId,
    pub commitment_id: BitVm2CommitmentId,
    pub tap_index: u32,
    pub disprove: BitVm2DisproveEnvelope,
    pub expected_output_hash: [u8; 32],
}

impl BitVm2ChallengeResponse {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        self.instance_id.validate()?;
        self.commitment_id.validate()?;
        self.disprove.validate()?;
        if self.expected_output_hash == [0; 32] {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2Monitor {
    ledger: BitVm2ObservationLedger,
}

impl BitVm2Monitor {
    pub fn observe(
        &mut self,
        observation: ExternalChainObservation,
    ) -> ConclaveResult<ObservationOutcome> {
        self.ledger.observe(observation)
    }

    pub fn observation_count(&self) -> usize {
        self.ledger.len()
    }
}

/// BitVM2 orchestrator. Unsupported value-bearing methods intentionally do not
/// touch `active_challenges`; only `observe_chain_event` can change monitor
/// state, and it requires an externally supplied observation.
pub struct BitVm2Orchestrator {
    #[allow(dead_code)]
    ark_manager: Arc<crate::protocol::ark::ArkManager>,
    #[allow(dead_code)]
    bitvm_manager: Arc<BitVmManager>,
    #[allow(dead_code)]
    backend: BitVm2Backend,
    #[allow(dead_code)]
    active_challenges: HashMap<String, BitVm2ChallengeStatus>,
    monitor: BitVm2Monitor,
}

impl BitVm2Orchestrator {
    pub fn new(
        ark_manager: Arc<crate::protocol::ark::ArkManager>,
        bitvm_manager: Arc<BitVmManager>,
    ) -> Self {
        Self {
            ark_manager,
            bitvm_manager,
            backend: BitVm2Backend::Unconfigured,
            active_challenges: HashMap::new(),
            monitor: BitVm2Monitor::default(),
        }
    }

    pub fn backend(&self) -> BitVm2Backend {
        self.backend
    }

    pub fn observe_chain_event(
        &mut self,
        observation: ExternalChainObservation,
    ) -> ConclaveResult<ObservationOutcome> {
        self.monitor.observe(observation)
    }

    pub fn observed_event_count(&self) -> usize {
        self.monitor.observation_count()
    }

    pub fn create_forfeit_with_commitment(
        &self,
        _vutxo: VUtxoDescriptor,
        _vtxo_tree: crate::protocol::ark::VtxoTreeNode,
        _state_root_hash: [u8; 32],
        _taproot_internal_key: [u8; 32],
    ) -> ConclaveResult<BitVm2ForfeitTransaction> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::ForfeitConstruction,
        ))
    }

    pub fn post_commitment(&mut self, _commitment: BitVm2Commitment) -> ConclaveResult<String> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::CommitmentPosting,
        ))
    }

    pub fn challenge_commitment(
        &mut self,
        _commitment_id: &str,
        _response: BitVm2ChallengeResponse,
    ) -> ConclaveResult<()> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::ChallengeSubmission,
        ))
    }

    pub fn resolve_challenge(
        &mut self,
        _commitment_id: &str,
        _operator_punished: bool,
        _block_height: u64,
    ) -> ConclaveResult<()> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::ChallengeResolution,
        ))
    }

    pub fn get_challenge_status(
        &self,
        _commitment_id: &str,
    ) -> ConclaveResult<BitVm2ChallengeStatus> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::ChallengeStatus,
        ))
    }

    pub fn is_within_challenge_window(
        &self,
        _commitment_id: &str,
        _current_block: u64,
    ) -> ConclaveResult<bool> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::ChallengeWindow,
        ))
    }

    pub fn sign_forfeit(
        &self,
        _forfeit_tx: &BitVm2ForfeitTransaction,
        _derivation_path: &str,
    ) -> ConclaveResult<String> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::ForfeitSigning,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        enclave::cloud::CloudEnclave,
        protocol::ark::{ArkManager, ArkVtxoId},
        UnsupportedReason,
    };

    fn orchestrator() -> BitVm2Orchestrator {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let ark = Arc::new(ArkManager::new(enclave.clone()));
        let bitvm = Arc::new(BitVmManager::new(enclave));
        BitVm2Orchestrator::new(ark, bitvm)
    }

    fn observation(digest: u8) -> ExternalChainObservation {
        ExternalChainObservation {
            encoding_version: BitVm2EncodingVersion::current(),
            observation_id: BitVm2ObservationId::new([1; 16]).expect("valid observation id"),
            instance_id: BitVm2InstanceId::new([2; 16]).expect("valid instance id"),
            chain_id: BitVm2ChainId::new("bitcoin").expect("valid chain id"),
            kind: BitVm2ObservationKind::CommitmentPosted,
            block_height: 100,
            event_digest: [digest; 32],
        }
    }

    #[test]
    fn validates_challenge_window_boundaries_and_identifiers() {
        assert!(BitVm2ChallengeWindow::new(10, 20)
            .expect("valid window")
            .contains(10));
        assert!(BitVm2ChallengeWindow::new(10, 20)
            .expect("valid window")
            .contains(20));
        assert!(!BitVm2ChallengeWindow::new(10, 20)
            .expect("valid window")
            .contains(9));
        assert!(!BitVm2ChallengeWindow::new(10, 20)
            .expect("valid window")
            .contains(21));
        assert!(matches!(
            BitVm2ChallengeWindow::new(21, 20),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidChallengeWindow
            ))
        ));
        assert!(matches!(
            BitVm2EncodingVersion::new(2),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidEncodingVersion
            ))
        ));
    }

    #[test]
    fn duplicate_chain_observations_are_idempotent_and_conflicts_fail_closed() {
        let mut monitor = BitVm2Monitor::default();
        assert_eq!(
            monitor
                .observe(observation(3))
                .expect("records observation"),
            ObservationOutcome::Recorded
        );
        assert_eq!(
            monitor
                .observe(observation(3))
                .expect("duplicate is idempotent"),
            ObservationOutcome::AlreadyKnown
        );
        assert!(matches!(
            monitor.observe(observation(4)),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::ReplayConflict
            ))
        ));
        assert_eq!(monitor.observation_count(), 1);
    }

    #[test]
    fn unsupported_operations_do_not_mutate_or_synthesize_state() {
        let mut manager = orchestrator();
        let before = manager.observed_event_count();
        let vutxo = VUtxoDescriptor::new(
            ArkVtxoId::new("vtxo-1").expect("valid vtxo id"),
            100,
            crate::protocol::ark::ArkDerivationIndex::new(0),
            "bc1q-example",
        )
        .expect("valid vtxo");
        let tree = crate::protocol::ark::VtxoTreeNode {
            tx_id: ArkTransactionId::new("root").expect("valid tx id"),
            left: None,
            right: None,
            is_leaf: true,
        };
        let commitment = BitVm2Commitment {
            encoding_version: BitVm2EncodingVersion::current(),
            instance_id: BitVm2InstanceId::new([2; 16]).expect("valid instance id"),
            commitment_id: BitVm2CommitmentId::new([3; 16]).expect("valid commitment id"),
            role: BitVm2Role::Operator,
            state_root_hash: [4; 32],
            vtxo_count: 1,
            merkle_root: [5; 32],
            taproot_internal_key: [6; 32],
            block_height: 100,
            challenge_window: BitVm2ChallengeWindow::new(100, 110).expect("valid window"),
        };
        let response = BitVm2ChallengeResponse {
            encoding_version: BitVm2EncodingVersion::current(),
            instance_id: commitment.instance_id,
            commitment_id: commitment.commitment_id,
            tap_index: 0,
            disprove: BitVm2DisproveEnvelope {
                encoding_version: BitVm2EncodingVersion::current(),
                digest: [7; 32],
                payload_len: 64,
            },
            expected_output_hash: [8; 32],
        };

        assert_unsupported(
            manager.create_forfeit_with_commitment(vutxo.clone(), tree, [4; 32], [6; 32]),
            UnsupportedOperation::ForfeitConstruction,
        );
        assert_unsupported(
            manager.post_commitment(commitment),
            UnsupportedOperation::CommitmentPosting,
        );
        assert_unsupported(
            manager.challenge_commitment("commitment", response),
            UnsupportedOperation::ChallengeSubmission,
        );
        assert_unsupported(
            manager.resolve_challenge("commitment", true, 110),
            UnsupportedOperation::ChallengeResolution,
        );
        assert_unsupported(
            manager.get_challenge_status("commitment"),
            UnsupportedOperation::ChallengeStatus,
        );
        assert_unsupported(
            manager.is_within_challenge_window("commitment", 110),
            UnsupportedOperation::ChallengeWindow,
        );
        assert_eq!(manager.observed_event_count(), before);
        assert_eq!(manager.backend(), BitVm2Backend::Unconfigured);
    }

    #[test]
    fn observed_events_are_the_only_modeled_state_transition() {
        let mut manager = orchestrator();
        assert_eq!(
            manager
                .observe_chain_event(observation(3))
                .expect("records external event"),
            ObservationOutcome::Recorded
        );
        assert_eq!(manager.observed_event_count(), 1);
    }

    fn assert_unsupported<T>(result: ConclaveResult<T>, operation: UnsupportedOperation) {
        match result {
            Err(ConclaveError::ProtocolUnsupported {
                protocol: UnsupportedProtocol::BitVm2,
                operation: actual_operation,
                reason: UnsupportedReason::NoAuditedImplementation,
            }) => assert_eq!(actual_operation, operation),
            _ => panic!("expected typed BitVM2 unsupported error"),
        }
    }
}
