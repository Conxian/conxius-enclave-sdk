//! Bitcoin covenant signing integration (Phase 2+).
//!
//! OP_CAT-based recursive covenant signing through the UCS.
//! Covenants enforce spending conditions across transaction chains
//! using introspection opcodes.
//!
//! # References
//! - BIP-347: OP_CAT proposal
//! - BIP-119: OP_CHECKTEMPLATEVERIFY (CTV)

use crate::signing::ucs::UniversalChainSigner;
use crate::ConclaveResult;

/// Signs covenant transactions through the UCS.
pub struct CovenantSigner<'a, S: UniversalChainSigner> {
    signer: &'a S,
}

impl<'a, S: UniversalChainSigner> CovenantSigner<'a, S> {
    pub fn new(signer: &'a S) -> Self { Self { signer } }

    /// Sign a covenant transition (spend from covenanted UTXO).
    ///
    /// Covenant outputs require Taproot script-path spending where
    /// the script enforces recursive spending conditions via OP_CAT
    /// and TX_HASH introspection.
    pub fn sign_covenant_spend(
        &self,
        covenant_sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
        tapleaf_hash: [u8; 32],
    ) -> ConclaveResult<String> {
        self.signer.sign_bitcoin_taproot(
            covenant_sighash, derivation_path, key_id, Some(tapleaf_hash),
        )
    }

    /// Sign a CTV (CHECKTEMPLATEVERIFY) template commitment.
    ///
    /// CTV commits to a specific transaction template hash that
    /// constrains future spends.
    pub fn sign_ctv_template(
        &self,
        template_hash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        self.signer.sign_bitcoin_taproot(template_hash, derivation_path, key_id, None)
    }

    /// Sign a vault emergency unbonding transaction.
    ///
    /// Vaults use time-locked covenant paths that allow recovery
    /// after a timelock expires.
    pub fn sign_vault_unbond(
        &self,
        unbond_sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        self.signer.sign_bitcoin_ecdsa(unbond_sighash, derivation_path, key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covenant_signer_constructs() {
        let _ = CovenantSigner::<crate::signing::ucs::EnclaveUniversalSigner>::new;
    }
}
