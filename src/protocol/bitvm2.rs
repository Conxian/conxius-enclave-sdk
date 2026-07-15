//! BitVM2 Challenge Orchestration Module
//!
//! Implements the integration of Ark forfeit transactions with the BitVM2 optimistic
//! challenge-response tree. This enables trust-minimized exits from Ark vTXOs.
//!
//! Architecture (Q4 2025):
//! - Permissionless challengers (existential honesty - 1-of-n)
//! - Optimistic commitment model with fraud proofs
//! - Script chunking for Bitcoin's 100KB block limit
//!
//! References:
//! - BitVM2 Whitepaper: https://bitvm.org/bitvm_bridge.pdf
//! - ePrint IACR: https://eprint.iacr.org/2025/1158.pdf

use crate::protocol::ark::{ArkManager, VUtxoDescriptor, VtxoTreeNode};
use crate::protocol::bitvm::{BitVmChallenge, BitVmManager};
use crate::{ConclaveError, ConclaveResult};
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
    ark_manager: Arc<ArkManager>,
    bitvm_manager: Arc<BitVmManager>,
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
        vutxo: VUtxoDescriptor,
        vtxo_tree: VtxoTreeNode,
        state_root_hash: [u8; 32],
        taproot_internal_key: [u8; 32],
    ) -> ConclaveResult<BitVm2ForfeitTransaction> {
        // Calculate merkle root from tree
        let merkle_root = self.calculate_tree_root(&vtxo_tree)?;

        // Create commitment hash from state data
        let mut commitment_data = Vec::new();
        commitment_data.extend_from_slice(&state_root_hash);
        commitment_data.extend_from_slice(&merkle_root);
        commitment_data.extend_from_slice(&taproot_internal_key);

        use blake2::{Blake2s256, Digest};
        let mut hasher = Blake2s256::new();
        hasher.update(&commitment_data);
        let commitment_hash = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&commitment_hash);

        Ok(BitVm2ForfeitTransaction {
            vutxo,
            tree_root: hex::encode(merkle_root),
            commitment_hash: hash,
            challenge_window: 42, // ~7 hours at 10min blocks
            csv_delay: 144,       // ~24 hours
        })
    }

    /// Post an optimistic commitment for a batch of vTXOs
    pub fn post_commitment(&mut self, commitment: BitVm2Commitment) -> ConclaveResult<String> {
        // Generate a unique ID for this commitment
        use blake2::{Blake2s256, Digest};
        let mut hasher = Blake2s256::new();
        hasher.update(commitment.state_root_hash);
        hasher.update(commitment.block_height.to_le_bytes());
        let commitment_id = hex::encode(hasher.finalize());

        // Register the challenge status
        self.active_challenges.insert(
            commitment_id.clone(),
            BitVm2ChallengeStatus {
                phase: ChallengePhase::Commitment,
                commitment_txid: None,
                challenge_txid: None,
                challenge_block: None,
                resolution: None,
            },
        );

        Ok(commitment_id)
    }

    /// Challenge an optimistic commitment (permissionless)
    /// Anyone can challenge - existential honesty model
    pub fn challenge_commitment(
        &mut self,
        commitment_id: &str,
        response: BitVm2ChallengeResponse,
    ) -> ConclaveResult<()> {
        let status = self
            .active_challenges
            .get_mut(commitment_id)
            .ok_or(ConclaveError::InvalidPayload)?;

        // Verify we're in commitment phase
        if status.phase != ChallengePhase::Commitment {
            return Err(ConclaveError::InvalidPayload);
        }

        // Verify tap index is within bounds
        if response.tap_index >= 364 {
            return Err(ConclaveError::InvalidPayload);
        }

        // Create BitVM challenge for SNARK verification
        let _bitvm_challenge = BitVmChallenge {
            challenge_hash: response.expected_output_hash,
            tap_index: response.tap_index,
            total_taps: 364,
        };

        // The challenge response contains a SNARK proof that would be verified
        // on-chain. Here we just record the challenge.
        status.phase = ChallengePhase::Challenge;
        status.challenge_txid = Some(hex::encode(
            response
                .snark_proof
                .iter()
                .take(32)
                .cloned()
                .collect::<Vec<_>>(),
        ));
        status.challenge_block = Some(0); // Would be set on-chain

        Ok(())
    }

    /// Resolve a challenge after verification
    pub fn resolve_challenge(
        &mut self,
        commitment_id: &str,
        operator_punished: bool,
        _block_height: u64,
    ) -> ConclaveResult<()> {
        let status = self
            .active_challenges
            .get_mut(commitment_id)
            .ok_or(ConclaveError::InvalidPayload)?;

        if status.phase != ChallengePhase::Challenge {
            return Err(ConclaveError::InvalidPayload);
        }

        if operator_punished {
            status.phase = ChallengePhase::ResolvedPenalty;
            status.resolution = Some("Operator punished - forfeit released".to_string());
        } else {
            status.phase = ChallengePhase::ResolvedRelease;
            status.resolution = Some("Challenge rejected - commitment valid".to_string());
        }

        Ok(())
    }

    /// Get the status of a challenge
    pub fn get_challenge_status(
        &self,
        commitment_id: &str,
    ) -> ConclaveResult<BitVm2ChallengeStatus> {
        self.active_challenges
            .get(commitment_id)
            .cloned()
            .ok_or(ConclaveError::InvalidPayload)
    }

    /// Check if a commitment is still within the challenge window
    pub fn is_within_challenge_window(
        &self,
        commitment_id: &str,
        _current_block: u64,
    ) -> ConclaveResult<bool> {
        let status = self.get_challenge_status(commitment_id)?;

        if status.phase != ChallengePhase::Commitment {
            return Ok(false);
        }

        // Challenge window is 42 blocks (~7 hours)
        // In production, we'd check the actual commitment block
        Ok(true)
    }

    /// Sign a forfeit transaction for an exiting vTXO
    /// This is called when the challenge window expires without challenge
    pub fn sign_forfeit(
        &self,
        forfeit_tx: &BitVm2ForfeitTransaction,
        derivation_path: &str,
    ) -> ConclaveResult<String> {
        // Create a hash of the forfeit data for signing
        use blake2::{Blake2s256, Digest};
        let mut hasher = Blake2s256::new();
        hasher.update(forfeit_tx.commitment_hash);
        hasher.update(forfeit_tx.vutxo.vutxo_id.as_bytes());
        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(&hasher.finalize());

        self.ark_manager
            .sign_forfeit_transaction(tx_hash, derivation_path)
    }

    /// Calculate the merkle root hash from a vTXO tree
    fn calculate_tree_root(&self, tree: &VtxoTreeNode) -> ConclaveResult<[u8; 32]> {
        if tree.is_leaf {
            use blake2::{Blake2s256, Digest};
            let mut hasher = Blake2s256::new();
            hasher.update(tree.tx_id.as_bytes());
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            Ok(hash)
        } else {
            let left_hash =
                self.calculate_tree_root(tree.left.as_ref().ok_or(ConclaveError::InvalidPayload)?)?;
            let right_hash = self
                .calculate_tree_root(tree.right.as_ref().ok_or(ConclaveError::InvalidPayload)?)?;

            use blake2::{Blake2s256, Digest};
            let mut hasher = Blake2s256::new();
            hasher.update(left_hash);
            hasher.update(right_hash);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            Ok(hash)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::cloud::CloudEnclave;

    fn create_test_orchestrator() -> BitVm2Orchestrator {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let ark = Arc::new(ArkManager::new(enclave.clone()));
        let bitvm = Arc::new(BitVmManager::new(enclave));
        BitVm2Orchestrator::new(ark, bitvm)
    }

    #[test]
    fn test_forfeit_with_commitment() {
        let orch = create_test_orchestrator();

        let vutxo = VUtxoDescriptor {
            vutxo_id: "test_vutxo_1".to_string(),
            amount: 100000,
            derivation_index: 0,
            address: "bc1q_test".to_string(),
        };

        let tree = VtxoTreeNode {
            tx_id: "root".to_string(),
            left: Some(Box::new(VtxoTreeNode {
                tx_id: "left".to_string(),
                left: None,
                right: None,
                is_leaf: true,
            })),
            right: Some(Box::new(VtxoTreeNode {
                tx_id: "right".to_string(),
                left: None,
                right: None,
                is_leaf: true,
            })),
            is_leaf: false,
        };

        let state_hash = [0u8; 32];
        let taproot_key = [1u8; 32];

        let forfeit = orch
            .create_forfeit_with_commitment(vutxo.clone(), tree, state_hash, taproot_key)
            .unwrap();

        assert_eq!(forfeit.vutxo.vutxo_id, "test_vutxo_1");
        assert_eq!(forfeit.challenge_window, 42);
        assert_eq!(forfeit.csv_delay, 144);
    }

    #[test]
    fn test_commitment_lifecycle() {
        let mut orch = create_test_orchestrator();

        let commitment = BitVm2Commitment {
            state_root_hash: [2u8; 32],
            vtxo_count: 100,
            merkle_root: [3u8; 32],
            taproot_internal_key: [4u8; 32],
            block_height: 850000,
        };

        let commitment_id = orch.post_commitment(commitment).unwrap();
        assert!(!commitment_id.is_empty());

        let status = orch.get_challenge_status(&commitment_id).unwrap();
        assert_eq!(status.phase, ChallengePhase::Commitment);

        // Post a challenge
        let response = BitVm2ChallengeResponse {
            tap_index: 100,
            snark_proof: vec![5u8; 64],
            witness: vec![vec![6u8; 32]],
            expected_output_hash: [7u8; 32],
        };

        orch.challenge_commitment(&commitment_id, response).unwrap();

        let status = orch.get_challenge_status(&commitment_id).unwrap();
        assert_eq!(status.phase, ChallengePhase::Challenge);

        // Resolve
        orch.resolve_challenge(&commitment_id, true, 850100)
            .unwrap();

        let status = orch.get_challenge_status(&commitment_id).unwrap();
        assert_eq!(status.phase, ChallengePhase::ResolvedPenalty);
    }

    #[test]
    fn test_invalid_challenge() {
        let mut orch = create_test_orchestrator();

        // Tap index out of bounds
        let response = BitVm2ChallengeResponse {
            tap_index: 400, // Should be < 364
            snark_proof: vec![0u8; 64],
            witness: vec![],
            expected_output_hash: [0u8; 32],
        };

        let commitment = BitVm2Commitment {
            state_root_hash: [0u8; 32],
            vtxo_count: 10,
            merkle_root: [0u8; 32],
            taproot_internal_key: [0u8; 32],
            block_height: 850000,
        };

        let commitment_id = orch.post_commitment(commitment).unwrap();
        let result = orch.challenge_commitment(&commitment_id, response);

        assert!(result.is_err());
    }
}
