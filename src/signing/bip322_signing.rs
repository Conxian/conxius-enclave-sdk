//! BIP-322 message signing attestation (SDK-004).
//!
//! Wraps `src/protocol/bip322.rs` Bip322Bridge for Simple Verification
//! message signing, integrated with the UCS signing pipeline.
//!
//! # SDK-004
//! See `docs/PHASE1_ISSUES_ROADMAP.md` for acceptance criteria.

use crate::protocol::bip322::{Bip322Bridge, Bip322Verification};
use crate::ConclaveResult;
use bitcoin::Network;

/// BIP-322 attestation signer for sovereign message verification.
pub struct Bip322AttestationSigner {
    bridge: Bip322Bridge,
}

impl Bip322AttestationSigner {
    pub fn new() -> Self {
        Self {
            bridge: Bip322Bridge,
        }
    }

    /// Compute the BIP-322 message hash (tagged hash).
    pub fn message_hash(&self, message: &str) -> [u8; 32] {
        Bip322Bridge::message_hash(message)
    }

    /// Verify a simple BIP-322 signature for a given network.
    pub fn verify_for_network(
        &self,
        message: &str,
        address: &str,
        signature_base64: &str,
        network: Network,
    ) -> ConclaveResult<Bip322Verification> {
        self.bridge
            .verify_simple_signature_for_network(message, address, signature_base64, network)
    }

    /// Verify a simple BIP-322 signature (returns `true` if valid, `false`
    /// for invalid or inconclusive).
    pub fn verify_simple(
        &self,
        address: &str,
        message: &str,
        signature_base64: &str,
    ) -> ConclaveResult<bool> {
        self.bridge
            .verify_simple_signature(address, message, signature_base64)
    }
}

impl Default for Bip322AttestationSigner {
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
    fn bip322_signer_constructs() {
        let signer = Bip322AttestationSigner::new();
        let hash = signer.message_hash("hello bitcoin");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn bip322_signer_is_send_sync() {
        fn _assert(_s: impl Send + Sync) {}
        _assert(Bip322AttestationSigner::new());
    }

    #[test]
    fn bip322_verify_invalid_signature_returns_false() {
        let signer = Bip322AttestationSigner::new();
        // Verification of garbage should fail, not panic
        let result = signer.verify_simple(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            "test",
            "invalid",
        );
        // May be Ok(false) or Err depending on network validation
        if let Ok(valid) = result {
            assert!(!valid);
        }
    }
}
