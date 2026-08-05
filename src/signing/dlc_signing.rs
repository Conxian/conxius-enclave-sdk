//! DLC (Discreet Log Contract) signing integration (Phase 2+).
//!
//! Wires `src/protocol/dlc.rs` types into the UCS signing pipeline
//! for DLC oracle attestation and CET (Contract Execution Transaction) signing.
//!
//! DLCs use Schnorr signatures for oracle attestations and Taproot
//! for CET outputs.

use crate::signing::ucs::UniversalChainSigner;
use crate::ConclaveResult;

/// Signs DLC oracle attestations and CETs through the UCS.
pub struct DlcSigner<'a, S: UniversalChainSigner> {
    signer: &'a S,
}

impl<'a, S: UniversalChainSigner> DlcSigner<'a, S> {
    pub fn new(signer: &'a S) -> Self {
        Self { signer }
    }

    /// Sign a DLC oracle attestation (Schnorr).
    ///
    /// Oracle attestations commit to a specific outcome at a given
    /// event maturity. Uses Taproot Schnorr (BIP-340) signing.
    pub fn sign_oracle_attestation(
        &self,
        event_id: [u8; 32],
        outcome: u64,
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        let message = Self::oracle_message_hash(event_id, outcome);
        self.signer
            .sign_bitcoin_taproot(message, derivation_path, key_id, None)
    }

    /// Sign a Contract Execution Transaction (CET).
    ///
    /// CETs spend from a DLC funding output and enforce the
    /// oracle-attested outcome distribution.
    pub fn sign_cet(
        &self,
        cet_sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
        tapleaf_hash: [u8; 32],
    ) -> ConclaveResult<String> {
        self.signer
            .sign_bitcoin_taproot(cet_sighash, derivation_path, key_id, Some(tapleaf_hash))
    }

    /// Sign a refund transaction (timelock path).
    pub fn sign_refund(
        &self,
        refund_sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        self.signer
            .sign_bitcoin_taproot(refund_sighash, derivation_path, key_id, None)
    }

    fn oracle_message_hash(event_id: [u8; 32], outcome: u64) -> [u8; 32] {
        use bitcoin::hashes::{sha256, HashEngine};
        let tag = sha256::Hash::hash("DLC/oracle/outcome".as_bytes());
        let mut engine = sha256::Hash::engine();
        engine.input(tag.as_byte_array().as_slice());
        engine.input(tag.as_byte_array().as_slice());
        engine.input(&event_id);
        engine.input(&outcome.to_le_bytes());
        sha256::Hash::from_engine(engine).to_byte_array()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dlc_signer_constructs() {
        let _ = DlcSigner::<crate::signing::ucs::EnclaveUniversalSigner>::new;
    }

    #[test]
    fn oracle_hash_is_deterministic() {
        let h1 = DlcSigner::<crate::signing::ucs::EnclaveUniversalSigner>::oracle_message_hash(
            [0xAB; 32], 42,
        );
        let h2 = DlcSigner::<crate::signing::ucs::EnclaveUniversalSigner>::oracle_message_hash(
            [0xAB; 32], 42,
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn oracle_hash_differs_by_outcome() {
        let h1 = DlcSigner::<crate::signing::ucs::EnclaveUniversalSigner>::oracle_message_hash(
            [0xAB; 32], 0,
        );
        let h2 = DlcSigner::<crate::signing::ucs::EnclaveUniversalSigner>::oracle_message_hash(
            [0xAB; 32], 1,
        );
        assert_ne!(h1, h2);
    }
}
