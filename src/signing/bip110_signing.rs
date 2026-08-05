//! BIP-110 enforcement integration with the signing pipeline (SDK-007).
//!
//! Wraps `src/protocol/bip110.rs` Bip110Validator to enforce reduced-data
//! temporary softfork limits on all signing inputs before they reach the
//! enclave.
//!
//! # SDK-007
//! See `docs/PHASE1_ISSUES_ROADMAP.md` for acceptance criteria.

#[cfg(feature = "bip110_compliant")]
use crate::protocol::bip110::Bip110Validator;
use crate::ConclaveResult;

/// BIP-110 enforcement wrapper for the signing pipeline.
pub struct Bip110Enforcer {
    #[cfg(feature = "bip110_compliant")]
    validator: Bip110Validator,
}

impl Bip110Enforcer {
    /// Create an enforcer with default BIP-110 limits.
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "bip110_compliant")]
            validator: Bip110Validator::new(),
        }
    }

    /// Validate that pushdata does not exceed BIP-110 limits.
    pub fn validate_pushdata(&self, data: &[u8]) -> ConclaveResult<()> {
        #[cfg(feature = "bip110_compliant")]
        {
            self.validator.validate_pushdata(data)
        }
        #[cfg(not(feature = "bip110_compliant"))]
        {
            let _ = data;
            Ok(())
        }
    }

    /// Validate that a script pubkey does not exceed BIP-110 limits.
    pub fn validate_script_pubkey<S: AsRef<[u8]>>(&self, script: S) -> ConclaveResult<()> {
        #[cfg(feature = "bip110_compliant")]
        {
            self.validator.validate_script_pubkey(script)
        }
        #[cfg(not(feature = "bip110_compliant"))]
        {
            let _ = script;
            Ok(())
        }
    }

    /// Validate a witness item against BIP-110 size limits.
    pub fn validate_witness_item(&self, item: &[u8]) -> ConclaveResult<()> {
        #[cfg(feature = "bip110_compliant")]
        {
            self.validator.validate_script_argument_witness_item(item)
        }
        #[cfg(not(feature = "bip110_compliant"))]
        {
            let _ = item;
            Ok(())
        }
    }

    /// Validate a taproot control block.
    pub fn validate_control_block(&self, control_block: &[u8]) -> ConclaveResult<()> {
        #[cfg(feature = "bip110_compliant")]
        {
            self.validator.validate_taproot_control_block(control_block)
        }
        #[cfg(not(feature = "bip110_compliant"))]
        {
            let _ = control_block;
            Ok(())
        }
    }

    /// Validate message chunking for BIP-110 compliance. Returns chunked
    /// message if validation passes.
    pub fn validate_and_chunk_message(&self, message: &str) -> ConclaveResult<Vec<Vec<u8>>> {
        #[cfg(feature = "bip110_compliant")]
        {
            self.validator.validate_message_chunking(message)
        }
        #[cfg(not(feature = "bip110_compliant"))]
        {
            let _ = message;
            Ok(vec![message.as_bytes().to_vec()])
        }
    }

    /// Returns true if the message requires chunking under BIP-110.
    pub fn requires_chunking(&self, message: &str) -> bool {
        #[cfg(feature = "bip110_compliant")]
        {
            self.validator.requires_chunking(message)
        }
        #[cfg(not(feature = "bip110_compliant"))]
        {
            let _ = message;
            false
        }
    }
}

impl Default for Bip110Enforcer {
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
    fn bip110_enforcer_constructs() {
        let enforcer = Bip110Enforcer::new();
        // Small pushdata should always pass
        assert!(enforcer.validate_pushdata(&[0x00; 32]).is_ok());
    }

    #[test]
    fn bip110_enforcer_is_send_sync() {
        fn _assert(_s: impl Send + Sync) {}
        _assert(Bip110Enforcer::new());
    }

    #[test]
    fn bip110_validate_witness_item_accepts_small_data() {
        let enforcer = Bip110Enforcer::new();
        assert!(enforcer.validate_witness_item(&[0x01; 64]).is_ok());
    }

    #[test]
    fn bip110_validate_script_pubkey_accepts_standard() {
        let enforcer = Bip110Enforcer::new();
        // P2WPKH script pubkey: 0x00 0x14 <20 bytes>
        let spk = [
            0x00, 0x14, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb,
        ];
        assert!(enforcer.validate_script_pubkey(spk).is_ok());
    }

    #[test]
    fn bip110_requires_chunking_short_message() {
        let enforcer = Bip110Enforcer::new();
        // Short message should never require chunking
        assert!(!enforcer.requires_chunking("hello"));
    }
}
