//! ZKML (Zero-Knowledge Machine Learning) signing integration (Phase 2+).
//!
//! Signs ZKML proof commitments through the UCS for on-chain
//! verification of ML model inference results.
//!
//! # References
//! - SNARK/STARK proof verification on Bitcoin via BitVM
//! - zkml crate integration (proof generation)

use crate::signing::ucs::UniversalChainSigner;
use crate::ConclaveResult;

/// Signs ZKML proof commitments through the UCS.
pub struct ZkmlSigner<'a, S: UniversalChainSigner> {
    signer: &'a S,
}

impl<'a, S: UniversalChainSigner> ZkmlSigner<'a, S> {
    pub fn new(signer: &'a S) -> Self {
        Self { signer }
    }

    /// Sign a ZKML proof commitment for on-chain verification.
    ///
    /// The proof commitment binds a model identifier, inference
    /// result hash, and public inputs into a single attestation.
    pub fn sign_proof_commitment(
        &self,
        proof_hash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        self.signer
            .sign_bitcoin_taproot(proof_hash, derivation_path, key_id, None)
    }

    /// Sign a ZKML model registration.
    ///
    /// Model registrations commit to the model architecture hash
    /// and training dataset merkle root.
    pub fn sign_model_registration(
        &self,
        model_commitment: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        self.signer
            .sign_bitcoin_taproot(model_commitment, derivation_path, key_id, None)
    }

    /// Sign an Ethereum-bound ZKML verification result.
    ///
    /// For chains that verify ZK proofs natively (EVM with
    /// precompiled pairing checks).
    pub fn sign_evm_verification(
        &self,
        verification_digest: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        self.signer
            .sign_ethereum(verification_digest, derivation_path, key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zkml_signer_constructs() {
        let _ = ZkmlSigner::<crate::signing::ucs::EnclaveUniversalSigner>::new;
    }
}
