//! BIP-110 Reduced Data Temporary Softfork Compliance
//!
//! Implements BIP-110 rules for transaction construction and verification.
//! When the `bip110_compliant` feature is enabled, all transaction operations
//! enforce the following consensus limits:
//!
//! | Rule | Limit | Description |
//! |------|-------|-------------|
//! | Pushdata/Witness | 256 bytes | OP_PUSHDATA and witness items >256 bytes invalid |
//! | OP_RETURN | 83 bytes | Restores 83-byte OP_RETURN as consensus rule |
//! | ScriptPubKey | 34 bytes | New outputs >34 bytes invalid unless OP_RETURN |
//!
//! References:
//! - [BIP-110 Specification](https://bips.dev/110)
//! - [Bitcoin Optech Newsletter #412](https://bitcoinops.org/en/newsletters/2026/07/03)

use crate::{ConclaveError, ConclaveResult};

/// BIP-110 consensus limits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bip110Limits {
    /// Maximum size for OP_PUSHDATA and witness items (256 bytes)
    pub max_pushdata_bytes: usize,
    /// Maximum size for OP_RETURN outputs (83 bytes)
    pub max_op_return_bytes: usize,
    /// Maximum size for non-OP_RETURN scriptPubKeys (34 bytes)
    pub max_script_pubkey_bytes: usize,
}

impl Default for Bip110Limits {
    fn default() -> Self {
        Self {
            max_pushdata_bytes: 256,
            max_op_return_bytes: 83,
            max_script_pubkey_bytes: 34,
        }
    }
}

/// BIP-110 compliance errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bip110Violation {
    /// Pushdata exceeds 256-byte limit
    PushdataTooLarge { actual: usize, limit: usize },
    /// OP_RETURN output exceeds 83-byte limit
    OpReturnTooLarge { actual: usize, limit: usize },
    /// Non-OP_RETURN scriptPubKey exceeds 34-byte limit
    ScriptPubkeyTooLarge { actual: usize, limit: usize },
}

impl std::fmt::Display for Bip110Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Bip110Violation::PushdataTooLarge { actual, limit } => {
                write!(
                    f,
                    "Pushdata size {} exceeds BIP-110 limit of {} bytes",
                    actual, limit
                )
            }
            Bip110Violation::OpReturnTooLarge { actual, limit } => {
                write!(
                    f,
                    "OP_RETURN size {} exceeds BIP-110 limit of {} bytes",
                    actual, limit
                )
            }
            Bip110Violation::ScriptPubkeyTooLarge { actual, limit } => {
                write!(
                    f,
                    "ScriptPubKey size {} exceeds BIP-110 limit of {} bytes",
                    actual, limit
                )
            }
        }
    }
}

/// BIP-110 compliance validator
pub struct Bip110Validator {
    limits: Bip110Limits,
}

impl Bip110Validator {
    /// Create a new BIP-110 validator with default limits
    pub fn new() -> Self {
        Self {
            limits: Bip110Limits::default(),
        }
    }

    /// Create a new BIP-110 validator with custom limits (for testing)
    pub fn with_limits(limits: Bip110Limits) -> Self {
        Self { limits }
    }

    /// Get the current limits
    pub fn limits(&self) -> Bip110Limits {
        self.limits
    }

    /// Validate a pushdata segment for BIP-110 compliance
    pub fn validate_pushdata(&self, data: &[u8]) -> ConclaveResult<()> {
        if data.len() > self.limits.max_pushdata_bytes {
            return Err(ConclaveError::InvalidPayload);
        }
        Ok(())
    }

    /// Validate that a message can be chunked for BIP-322 under BIP-110 rules
    ///
    /// Messages longer than 256 bytes need to be split into chunks.
    /// Each chunk (including prefix) must fit within the pushdata limit.
    pub fn validate_message_chunking(&self, message: &str) -> ConclaveResult<Vec<Vec<u8>>> {
        let message_bytes = message.as_bytes();

        // Calculate header size (1 byte for length prefix)
        let header_size = 1;
        let max_payload = self.limits.max_pushdata_bytes - header_size;

        // BIP-322 uses compact integer encoding for message length
        // For messages <= 252 bytes, use single byte length
        // For longer messages, we need to chunk

        let mut chunks = Vec::new();
        let mut remaining = message_bytes;

        while !remaining.is_empty() {
            let chunk_size = remaining.len().min(max_payload);
            let mut chunk = Vec::with_capacity(header_size + chunk_size);
            chunk.push(chunk_size as u8);
            chunk.extend_from_slice(&remaining[..chunk_size]);
            chunks.push(chunk);
            remaining = &remaining[chunk_size..];
        }

        Ok(chunks)
    }

    /// Calculate the number of chunks needed for a message under BIP-110
    pub fn chunk_count(&self, message: &str) -> usize {
        let message_bytes = message.as_bytes();
        let max_payload = self.limits.max_pushdata_bytes - 1; // 1 byte for length
        message_bytes.len().div_ceil(max_payload)
    }

    /// Check if a message requires chunking under BIP-110
    pub fn requires_chunking(&self, message: &str) -> bool {
        // BIP-322 normally uses a single push for the message
        // With BIP-110, messages > 252 bytes need chunking
        let prefix = b"\x18Bitcoin Signed Message:\n";
        let header_size = 1; // Length byte
        let message_bytes = message.as_bytes();

        prefix.len() + header_size + message_bytes.len() > self.limits.max_pushdata_bytes
    }
}

impl Default for Bip110Validator {
    fn default() -> Self {
        Self::new()
    }
}

/// Chunk data into BIP-110 compliant segments
pub fn chunk_for_bip110(data: &[u8], max_chunk_size: usize) -> Vec<Vec<u8>> {
    let max_size = max_chunk_size.min(256); // Hard limit of 256
    data.chunks(max_size).map(|chunk| chunk.to_vec()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_limits() {
        let validator = Bip110Validator::new();
        let limits = validator.limits();

        assert_eq!(limits.max_pushdata_bytes, 256);
        assert_eq!(limits.max_op_return_bytes, 83);
        assert_eq!(limits.max_script_pubkey_bytes, 34);
    }

    #[test]
    fn test_validate_pushdata_under_limit() {
        let validator = Bip110Validator::new();
        let data = vec![0u8; 256];
        assert!(validator.validate_pushdata(&data).is_ok());
    }

    #[test]
    fn test_validate_pushdata_over_limit() {
        let validator = Bip110Validator::new();
        let data = vec![0u8; 257];
        assert!(validator.validate_pushdata(&data).is_err());
    }

    #[test]
    fn test_chunk_count_short_message() {
        let validator = Bip110Validator::new();
        assert_eq!(validator.chunk_count("hello"), 1);
    }

    #[test]
    fn test_chunk_count_long_message() {
        let validator = Bip110Validator::new();
        let long_message = "x".repeat(300);
        // 300 bytes with 255 byte chunks = 2 chunks needed
        assert_eq!(validator.chunk_count(&long_message), 2);
    }

    #[test]
    fn test_requires_chunking_short() {
        let validator = Bip110Validator::new();
        assert!(!validator.requires_chunking("hello"));
    }

    #[test]
    fn test_requires_chunking_long() {
        let validator = Bip110Validator::new();
        let long_message = "x".repeat(300);
        assert!(validator.requires_chunking(&long_message));
    }

    #[test]
    fn test_message_chunking() {
        let validator = Bip110Validator::new();
        let message = "hello world";
        let chunks = validator.validate_message_chunking(message).unwrap();

        // Short message should be one chunk
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0][0], message.len() as u8);
        assert_eq!(&chunks[0][1..], message.as_bytes());
    }

    #[test]
    fn test_message_chunking_long() {
        let validator = Bip110Validator::new();
        let message = "x".repeat(300);
        let chunks = validator.validate_message_chunking(&message).unwrap();

        // Should be at least 2 chunks for 300 bytes
        assert!(chunks.len() >= 2);
    }

    #[test]
    fn test_chunk_for_bip110() {
        let data = vec![0u8; 300];
        let chunks = chunk_for_bip110(&data, 256);

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 256);
        assert_eq!(chunks[1].len(), 44);
    }
}
