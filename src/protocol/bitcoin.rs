use crate::{ConclaveResult, ConclaveError, enclave::{SignRequest, HeadlessEnclave}};
use bitcoin::hashes::Hash;
use bitcoin::taproot::TapLeafHash;

/// Native Bitcoin Taproot (Schnorr) Manager.
/// Aligned with the "Zero Secret Egress" ethos.
pub struct TaprootManager<'a> {
    enclave: &'a dyn HeadlessEnclave,
}

impl<'a> TaprootManager<'a> {
    pub fn new(enclave: &'a dyn HeadlessEnclave) -> Self {
        Self { enclave }
    }

    /// Prepares and signs a Taproot (BIP341) Schnorr signature.
    /// This uses the enclave's Schnorr signing path (m/86').
    pub fn sign_taproot_sighash(
        &self,
        sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        if !derivation_path.contains("86'") {
            return Err(ConclaveError::CryptoError("Taproot requires m/86' derivation path".to_string()));
        }

        let request = SignRequest {
            message_hash: sighash.to_vec(),
            derivation_path: derivation_path.to_string(),
            key_id: key_id.to_string(),
        };

        let response = self.enclave.sign(request)?;
        Ok(response.signature_hex)
    }

    /// Decoupled Taproot leaf signing for script path spending.
    pub fn sign_tapscript_leaf(
        &self,
        leaf_hash: TapLeafHash,
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        self.sign_taproot_sighash(leaf_hash.to_byte_array(), derivation_path, key_id)
    }
}
