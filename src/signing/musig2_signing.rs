//! MuSig2 signing integration with UCS (SDK-003).
//!
//! Wraps `src/protocol/musig2.rs` MuSig2Session into the signing module,
//! providing nonce generation, partial signing, and signature aggregation
//! as discrete pipeline steps.
//!
//! # SDK-003
//! See `docs/PHASE1_ISSUES_ROADMAP.md` for acceptance criteria.

use crate::protocol::musig2::MuSig2Session;
use crate::ConclaveResult;
use musig2::{PartialSignature, PubNonce, SecNonce};
use secp256k1::{PublicKey, SecretKey};

/// MuSig2 multisig signer backed by the existing protocol module.
pub struct MuSig2Signer;

impl MuSig2Signer {
    pub fn new() -> Self {
        Self
    }

    /// Create a new MuSig2 session from a list of participant public keys.
    pub fn new_session(&self, pubkeys: &[PublicKey]) -> ConclaveResult<MuSig2Session> {
        MuSig2Session::new(pubkeys)
    }

    /// Generate a nonce pair for a participant.
    pub fn generate_nonce(
        &self,
        session: &MuSig2Session,
        secret_key: &SecretKey,
    ) -> ConclaveResult<(SecNonce, PubNonce)> {
        session.generate_nonce(secret_key)
    }

    /// Create a partial signature.
    pub fn partial_sign(
        &self,
        session: &MuSig2Session,
        sec_nonce: SecNonce,
        pub_nonces: Vec<PubNonce>,
        secret_key: &SecretKey,
        message: [u8; 32],
    ) -> ConclaveResult<PartialSignature> {
        session.partial_sign(sec_nonce, pub_nonces, secret_key, message)
    }

    /// Aggregate partial signatures into a final signature.
    pub fn aggregate(
        &self,
        session: &MuSig2Session,
        pub_nonces: Vec<PubNonce>,
        partial_sigs: Vec<PartialSignature>,
        message: [u8; 32],
    ) -> ConclaveResult<Vec<u8>> {
        session.aggregate_signatures(pub_nonces, partial_sigs, message)
    }
}

impl Default for MuSig2Signer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn musig2_signer_constructs() {
        let signer = MuSig2Signer::new();
        let _ = signer;
        let _ = MuSig2Signer;
    }

    #[test]
    fn musig2_signer_is_send_sync() {
        fn _assert(_s: impl Send + Sync) {}
        _assert(MuSig2Signer::new());
    }
}
