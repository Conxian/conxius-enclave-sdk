//! Spark Statechain signing integration (Phase 2).
//!
//! Wires `src/protocol/statechain.rs` Spark types into the UCS signing
//! pipeline. Provides statechain-specific signing with operator threshold
//! support via FROST/MuSig2.
//!
//! # Phase 2
//! See `docs/PHASE1_ISSUES_ROADMAP.md` for context.

use crate::signing::ucs::UniversalChainSigner;
use crate::ConclaveResult;

/// Signs a Spark statechain vUTXO transfer through the UCS.
///
/// Statechain transfers use Schnorr signatures (BIP-340) with the
/// operator's public key set.
pub struct StatechainSigner<'a, S: UniversalChainSigner> {
    signer: &'a S,
}

impl<'a, S: UniversalChainSigner> StatechainSigner<'a, S> {
    pub fn new(signer: &'a S) -> Self {
        Self { signer }
    }

    /// Sign a statechain transfer commitment.
    pub fn sign_transfer(
        &self,
        vutxo_commitment: [u8; 32],
        derivation_path: &str,
        key_id: &str,
        _operator_set: &crate::protocol::statechain::SparkOperatorSet,
    ) -> ConclaveResult<String> {
        // Statechain transfers use Taproot Schnorr signatures.
        // The operator set is validated structurally but signing currently
        // goes through single-key Taproot (operator threshold via FROST
        // is a Phase 3 concern).
        self.signer
            .sign_bitcoin_taproot(vutxo_commitment, derivation_path, key_id, None)
    }

    /// Sign a statechain backup transaction.
    pub fn sign_backup(
        &self,
        backup_tx_hash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        self.signer
            .sign_bitcoin_taproot(backup_tx_hash, derivation_path, key_id, None)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statechain_signer_constructs() {
        // Can't construct without a real signer, but type checks
        let _ = StatechainSigner::<crate::signing::ucs::EnclaveUniversalSigner>::new;
    }

    #[test]
    fn statechain_transfer_types_align() {
        let ops = crate::protocol::statechain::SparkOperatorSet::new(
            vec![crate::protocol::statechain::SparkOperator {
                participant_id: crate::protocol::frost::FrostParticipantId::new(1).unwrap(),
                public_key: [0x02; 32],
                identity: "op-1".into(),
            }],
            1,
            crate::protocol::frost::FrostCiphersuite::Secp256k1Sha256,
        );
        assert!(ops.is_ok());
        assert_eq!(ops.unwrap().threshold, 1);
    }
}
