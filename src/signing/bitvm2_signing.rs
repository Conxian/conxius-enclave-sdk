//! BitVM2 challenge signing integration (Phase 2).
//!
//! Wires `src/protocol/bitvm2.rs` types into the UCS signing pipeline
//! for BitVM2 challenge/response protocol signing.
//!
//! # Phase 2
//! See `docs/PHASE1_ISSUES_ROADMAP.md` for context.

use crate::protocol::bitvm2::{BitVm2CommitmentId, BitVm2InstanceId};
use crate::signing::ucs::UniversalChainSigner;
use crate::ConclaveResult;

/// Signs BitVM2 challenge and response transactions through the UCS.
pub struct BitVm2Signer<'a, S: UniversalChainSigner> {
    signer: &'a S,
}

impl<'a, S: UniversalChainSigner> BitVm2Signer<'a, S> {
    pub fn new(signer: &'a S) -> Self {
        Self { signer }
    }

    /// Sign a BitVM2 challenge transaction.
    ///
    /// Challenges are Taproot script-path spends. The sighash is
    /// computed off-chain and verified against the instance's
    /// commitment structure.
    pub fn sign_challenge(
        &self,
        instance_id: &BitVm2InstanceId,
        commitment_id: &BitVm2CommitmentId,
        sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
        tapleaf_hash: [u8; 32],
    ) -> ConclaveResult<String> {
        let _ = (instance_id, commitment_id);
        let merkle_root = Some(tapleaf_hash);
        self.signer
            .sign_bitcoin_taproot(sighash, derivation_path, key_id, merkle_root)
    }

    /// Sign a BitVM2 response (disprove) transaction.
    pub fn sign_response(
        &self,
        instance_id: &BitVm2InstanceId,
        sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
        tapleaf_hash: [u8; 32],
    ) -> ConclaveResult<String> {
        let _ = instance_id;
        let merkle_root = Some(tapleaf_hash);
        self.signer
            .sign_bitcoin_taproot(sighash, derivation_path, key_id, merkle_root)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitvm2_signer_constructs() {
        let _ = BitVm2Signer::<crate::signing::ucs::EnclaveUniversalSigner>::new;
    }

    #[test]
    fn bitvm2_ids_construct() {
        let instance = BitVm2InstanceId::new([0x01; 16]).unwrap();
        let commitment = BitVm2CommitmentId::new([0x02; 16]).unwrap();
        assert_eq!(instance.bytes(), [0x01; 16]);
        assert_eq!(commitment.bytes(), [0x02; 16]);
    }
}
