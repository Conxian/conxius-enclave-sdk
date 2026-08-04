//! Lightning Network signing integration (Phase 2+).
//!
//! BOLT 12 offer signing, BIP-353 Human Readable Names,
//! and LNURL-auth attestation through the UCS.

use crate::signing::ucs::UniversalChainSigner;
use crate::ConclaveResult;

/// Signs Lightning protocol messages through the UCS.
pub struct LightningSigner<'a, S: UniversalChainSigner> {
    signer: &'a S,
}

impl<'a, S: UniversalChainSigner> LightningSigner<'a, S> {
    pub fn new(signer: &'a S) -> Self { Self { signer } }

    /// Sign a BOLT 12 offer.
    ///
    /// BOLT 12 offers use Schnorr signatures over the offer
    /// TLV merkle root.
    pub fn sign_bolt12_offer(
        &self,
        offer_digest: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        self.signer.sign_bitcoin_taproot(offer_digest, derivation_path, key_id, None)
    }

    /// Sign a BIP-353 Human Readable Name resolution.
    ///
    /// BIP-353 uses DNSSEC-style proofs with Bitcoin keys.
    pub fn sign_bip353_resolution(
        &self,
        name_hash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        self.signer.sign_bitcoin_taproot(name_hash, derivation_path, key_id, None)
    }

    /// Sign an LNURL-auth challenge.
    ///
    /// LNURL-auth uses ECDSA over secp256k1 with a linking
    /// key derived from the LNURL path.
    pub fn sign_lnurl_auth(
        &self,
        challenge: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        // LNURL-auth uses legacy ECDSA (not Taproot)
        self.signer.sign_bitcoin_ecdsa(challenge, derivation_path, key_id)
    }

    /// Sign a Lightning commitment transaction.
    pub fn sign_commitment_tx(
        &self,
        commitment_sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        self.signer.sign_bitcoin_taproot(commitment_sighash, derivation_path, key_id, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lightning_signer_constructs() {
        let _ = LightningSigner::<crate::signing::ucs::EnclaveUniversalSigner>::new;
    }
}
