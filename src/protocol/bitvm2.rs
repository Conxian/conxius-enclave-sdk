//! BitVM2 Challenge Orchestration Module
//!
//! Defines the integration boundary for Ark forfeit transactions and BitVM2
//! optimistic challenge-response state.
//!
//! Value-bearing commitment, proof, challenge, settlement, and signing
//! operations remain explicitly unsupported until audited implementations and
//! chain/proof evidence are available.
//!
//! Architecture (Q4 2025):
//! - Permissionless challengers (existential honesty - 1-of-n)
//! - Optimistic commitment model with fraud proofs
//! - Client-side proof segmentation is covered by feature-gated regression tests;
//!   this module does not serialize those chunks into on-chain scripts.
//!
//! References:
//! - BitVM2 Whitepaper: https://bitvm.org/bitvm_bridge.pdf
//! - ePrint IACR: https://eprint.iacr.org/2025/1158.pdf

use crate::protocol::ark::{ArkManager, VUtxoDescriptor, VtxoTreeNode};
use crate::protocol::bitvm::BitVmManager;
use crate::{protocol_unsupported, ConclaveResult, UnsupportedOperation, UnsupportedProtocol};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Challenge phase in the BitVM2 dispute protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengePhase {
    /// No dispute in progress
    None,
    /// Operator posted optimistic commitment
    Commitment,
    /// Challenger posted fraud proof
    Challenge,
    /// Challenge resolved, operator punished
    ResolvedPenalty,
    /// Challenge resolved, challenger punished (false claim)
    ResolvedRelease,
}

/// Status of a BitVM2 challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitVm2ChallengeStatus {
    pub phase: ChallengePhase,
    pub commitment_txid: Option<String>,
    pub challenge_txid: Option<String>,
    pub challenge_block: Option<u64>,
    pub resolution: Option<String>,
}

/// Forfeit transaction with BitVM2 challenge data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitVm2ForfeitTransaction {
    /// The Ark vTXO being forfeited
    pub vutxo: VUtxoDescriptor,
    /// The vTXO tree root for this forfeit
    pub tree_root: String,
    /// BitVM2 commitment hash
    pub commitment_hash: [u8; 32],
    /// Challenge window in blocks
    pub challenge_window: u32,
    /// CSV delay for timeout
    pub csv_delay: u32,
}

/// Optimistic commitment for BitVM2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitVm2Commitment {
    /// Hash of the batch state root
    pub state_root_hash: [u8; 32],
    /// Number of vTXOs in the batch
    pub vtxo_count: u32,
    /// Aggregated tree merkle root
    pub merkle_root: [u8; 32],
    /// Operator's Taproot internal key
    pub taproot_internal_key: [u8; 32],
    /// Block height when commitment was made
    pub block_height: u64,
}

/// Response to a BitVM2 challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitVm2ChallengeResponse {
    /// The specific tap index being challenged
    pub tap_index: u32,
    /// SNARK proof for the disputed computation
    pub snark_proof: Vec<u8>,
    /// Input witness data
    pub witness: Vec<Vec<u8>>,
    /// Expected output hash
    pub expected_output_hash: [u8; 32],
}

/// BitVM2 Orchestrator - manages challenge lifecycle
pub struct BitVm2Orchestrator {
    #[allow(dead_code)]
    ark_manager: Arc<ArkManager>,
    #[allow(dead_code)]
    bitvm_manager: Arc<BitVmManager>,
    #[allow(dead_code)]
    active_challenges: std::collections::HashMap<String, BitVm2ChallengeStatus>,
}

impl BitVm2Orchestrator {
    /// Create a new BitVM2 orchestrator
    pub fn new(ark_manager: Arc<ArkManager>, bitvm_manager: Arc<BitVmManager>) -> Self {
        Self {
            ark_manager,
            bitvm_manager,
            active_challenges: std::collections::HashMap::new(),
        }
    }

    /// Creates a forfeit transaction with BitVM2 challenge data
    /// Integrates Ark vTXO with BitVM2 optimistic commitment
    pub fn create_forfeit_with_commitment(
        &self,
        _vutxo: VUtxoDescriptor,
        _vtxo_tree: VtxoTreeNode,
        _state_root_hash: [u8; 32],
        _taproot_internal_key: [u8; 32],
    ) -> ConclaveResult<BitVm2ForfeitTransaction> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::ForfeitConstruction,
        ))
    }

    /// Post an optimistic commitment for a batch of vTXOs
    pub fn post_commitment(&mut self, _commitment: BitVm2Commitment) -> ConclaveResult<String> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::CommitmentPosting,
        ))
    }

    /// Challenge an optimistic commitment (permissionless)
    /// Anyone can challenge - existential honesty model
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

    /// Resolve a challenge after verification
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

    /// Get the status of a challenge
    pub fn get_challenge_status(
        &self,
        _commitment_id: &str,
    ) -> ConclaveResult<BitVm2ChallengeStatus> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::ChallengeStatus,
        ))
    }

    /// Check if a commitment is still within the challenge window
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

    /// Sign a forfeit transaction for an exiting vTXO
    /// This is called when the challenge window expires without challenge
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
    use crate::enclave::cloud::CloudEnclave;
    use crate::ConclaveError;

    fn create_test_orchestrator() -> BitVm2Orchestrator {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let ark = Arc::new(ArkManager::new(enclave.clone()));
        let bitvm = Arc::new(BitVmManager::new(enclave));
        BitVm2Orchestrator::new(ark, bitvm)
    }

    #[test]
    fn test_bitvm2_operations_are_explicitly_unsupported() {
        let mut orch = create_test_orchestrator();
        let vutxo = VUtxoDescriptor {
            vutxo_id: "test_vutxo_1".to_string(),
            amount: 100000,
            derivation_index: 0,
            address: "bc1q_test".to_string(),
        };
        let tree = VtxoTreeNode {
            tx_id: "root".to_string(),
            left: None,
            right: None,
            is_leaf: true,
        };
        let commitment = BitVm2Commitment {
            state_root_hash: [2u8; 32],
            vtxo_count: 100,
            merkle_root: [3u8; 32],
            taproot_internal_key: [4u8; 32],
            block_height: 850000,
        };
        let response = BitVm2ChallengeResponse {
            tap_index: 100,
            snark_proof: vec![5u8; 64],
            witness: vec![vec![6u8; 32]],
            expected_output_hash: [7u8; 32],
        };

        assert_unsupported(
            orch.create_forfeit_with_commitment(vutxo.clone(), tree, [0u8; 32], [1u8; 32]),
            UnsupportedOperation::ForfeitConstruction,
        );
        assert_unsupported(
            orch.post_commitment(commitment),
            UnsupportedOperation::CommitmentPosting,
        );
        assert!(orch.active_challenges.is_empty());
        assert_unsupported(
            orch.challenge_commitment("commitment", response),
            UnsupportedOperation::ChallengeSubmission,
        );
        assert_unsupported(
            orch.resolve_challenge("commitment", true, 850100),
            UnsupportedOperation::ChallengeResolution,
        );
        assert_unsupported(
            orch.get_challenge_status("commitment"),
            UnsupportedOperation::ChallengeStatus,
        );
        assert_unsupported(
            orch.is_within_challenge_window("commitment", 850100),
            UnsupportedOperation::ChallengeWindow,
        );
        assert_unsupported(
            orch.sign_forfeit(
                &BitVm2ForfeitTransaction {
                    vutxo,
                    tree_root: "root".to_string(),
                    commitment_hash: [0u8; 32],
                    challenge_window: 42,
                    csv_delay: 144,
                },
                "m/84'/0'/0'",
            ),
            UnsupportedOperation::ForfeitSigning,
        );
    }

    #[test]
    fn test_simulated_proof_cannot_succeed() {
        let mut orch = create_test_orchestrator();

        let response = BitVm2ChallengeResponse {
            tap_index: 100,
            snark_proof: Vec::new(),
            witness: vec![],
            expected_output_hash: [0u8; 32],
        };

        assert_unsupported(
            orch.challenge_commitment("commitment", response),
            UnsupportedOperation::ChallengeSubmission,
        );
        assert!(orch.active_challenges.is_empty());
    }

    fn assert_unsupported<T>(result: ConclaveResult<T>, operation: UnsupportedOperation) {
        match result {
            Err(ConclaveError::ProtocolUnsupported {
                protocol: UnsupportedProtocol::BitVm2,
                operation: actual_operation,
                reason: crate::UnsupportedReason::NoAuditedImplementation,
            }) => assert_eq!(actual_operation, operation),
            _ => panic!("expected typed BitVM2 unsupported error"),
        }
    }

    #[test]
    #[cfg(feature = "bip110_compliant")]
    fn test_bip110_ordered_bitvm2_proof_segmentation() {
        let proof: Vec<u8> = (0..513).map(|index| (index % 251) as u8).collect();
        let chunks = crate::protocol::bip110::try_chunk_for_bip110(&proof, 256)
            .expect("strict chunking succeeds");

        assert_eq!(
            chunks.iter().map(|chunk| chunk.len()).collect::<Vec<_>>(),
            vec![256, 256, 1]
        );
        let reconstructed: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(reconstructed, proof);
    }
}
