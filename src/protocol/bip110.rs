//! BIP-110 Reduced Data Temporary Softfork validation helpers.
//!
//! The `bip110_compliant` feature exposes opt-in validators for the subset of
//! BIP-110 rules that this SDK can model without a transaction/script
//! interpreter. Callers must select the appropriate context: a full
//! `scriptPubKey`, a script's pushdata, a script-argument witness item, a
//! witness script, or a Taproot control block.
//!
//! These helpers do not execute Bitcoin Script and are not a complete
//! consensus validator.
//!
//! References:
//! - [BIP-110 Specification](https://github.com/bitcoin/bips/blob/master/bip-0110.mediawiki)
//! - [BIP-322 Specification](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki)

use crate::{ConclaveError, ConclaveResult};
use bitcoin::script::{Instruction, ScriptExt, ScriptPubKeyBuf, ScriptPubKeyExt, ScriptSigBuf};

const MAX_PUSH_DATA_BYTES: usize = 256;
const MAX_OP_RETURN_BYTES: usize = 83;
const MAX_SCRIPT_PUBKEY_BYTES: usize = 34;
const MAX_TAPROOT_CONTROL_BLOCK_BYTES: usize = 257;
const MIN_TAPROOT_CONTROL_BLOCK_BYTES: usize = 33;

/// BIP-110 consensus limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bip110Limits {
    /// Maximum size for OP_PUSHDATA payloads and script-argument witness items.
    pub max_pushdata_bytes: usize,
    /// Maximum serialized size for an output whose first opcode is OP_RETURN.
    pub max_op_return_bytes: usize,
    /// Maximum serialized size for a non-OP_RETURN output scriptPubKey.
    pub max_script_pubkey_bytes: usize,
}

impl Default for Bip110Limits {
    fn default() -> Self {
        Self {
            max_pushdata_bytes: MAX_PUSH_DATA_BYTES,
            max_op_return_bytes: MAX_OP_RETURN_BYTES,
            max_script_pubkey_bytes: MAX_SCRIPT_PUBKEY_BYTES,
        }
    }
}

/// BIP-110 compliance errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bip110Violation {
    /// Pushdata exceeds the configured limit.
    PushdataTooLarge { actual: usize, limit: usize },
    /// An OP_RETURN scriptPubKey exceeds the configured full-script limit.
    OpReturnTooLarge { actual: usize, limit: usize },
    /// A non-OP_RETURN scriptPubKey exceeds the configured full-script limit.
    ScriptPubkeyTooLarge { actual: usize, limit: usize },
    /// A script could not be parsed into complete instructions.
    MalformedScript,
    /// A script-argument witness item exceeds the configured pushdata limit.
    WitnessItemTooLarge { actual: usize, limit: usize },
    /// A Taproot control block is not structurally serialized as 33+32*n bytes.
    MalformedTaprootControlBlock { actual: usize },
    /// A Taproot control block exceeds BIP-110's 257-byte limit.
    TaprootControlBlockTooLarge { actual: usize, limit: usize },
}

impl std::fmt::Display for Bip110Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Bip110Violation::PushdataTooLarge { actual, limit } => {
                write!(
                    f,
                    "Pushdata size {actual} exceeds BIP-110 limit of {limit} bytes"
                )
            }
            Bip110Violation::OpReturnTooLarge { actual, limit } => {
                write!(
                    f,
                    "OP_RETURN scriptPubKey size {actual} exceeds BIP-110 limit of {limit} bytes"
                )
            }
            Bip110Violation::ScriptPubkeyTooLarge { actual, limit } => {
                write!(
                    f,
                    "scriptPubKey size {actual} exceeds BIP-110 limit of {limit} bytes"
                )
            }
            Bip110Violation::MalformedScript => {
                write!(f, "script is not validly serialized")
            }
            Bip110Violation::WitnessItemTooLarge { actual, limit } => {
                write!(
                    f,
                    "script-argument witness item size {actual} exceeds BIP-110 limit of {limit} bytes"
                )
            }
            Bip110Violation::MalformedTaprootControlBlock { actual } => {
                write!(
                    f,
                    "Taproot control block size {actual} is not 33 + 32*n bytes"
                )
            }
            Bip110Violation::TaprootControlBlockTooLarge { actual, limit } => {
                write!(
                    f,
                    "Taproot control block size {actual} exceeds BIP-110 limit of {limit} bytes"
                )
            }
        }
    }
}

impl Bip110Violation {
    fn into_conclave_error(self) -> ConclaveError {
        ConclaveError::InvalidPayload
    }
}

/// BIP-110 compliance validator.
pub struct Bip110Validator {
    limits: Bip110Limits,
}

impl Bip110Validator {
    /// Create a validator with the default BIP-110 limits.
    pub fn new() -> Self {
        Self {
            limits: Bip110Limits::default(),
        }
    }

    /// Create a validator with custom limits, clamped to consensus maxima.
    ///
    /// This compatibility constructor allows stricter policy limits but cannot
    /// relax BIP-110's `256/83/34` maxima. Use [`Self::try_with_limits`] when
    /// callers need explicit rejection instead of clamping.
    pub fn with_limits(limits: Bip110Limits) -> Self {
        Self {
            limits: Bip110Limits {
                max_pushdata_bytes: limits.max_pushdata_bytes.min(MAX_PUSH_DATA_BYTES),
                max_op_return_bytes: limits.max_op_return_bytes.min(MAX_OP_RETURN_BYTES),
                max_script_pubkey_bytes: limits
                    .max_script_pubkey_bytes
                    .min(MAX_SCRIPT_PUBKEY_BYTES),
            },
        }
    }

    /// Create a validator, rejecting limits that relax BIP-110 maxima.
    pub fn try_with_limits(limits: Bip110Limits) -> ConclaveResult<Self> {
        if limits.max_pushdata_bytes > MAX_PUSH_DATA_BYTES
            || limits.max_op_return_bytes > MAX_OP_RETURN_BYTES
            || limits.max_script_pubkey_bytes > MAX_SCRIPT_PUBKEY_BYTES
        {
            return Err(ConclaveError::InvalidPayload);
        }

        Ok(Self { limits })
    }

    /// Get the current limits.
    pub fn limits(&self) -> Bip110Limits {
        self.limits
    }

    fn validate_pushdata_violation(&self, data: &[u8]) -> Result<(), Bip110Violation> {
        if data.len() > self.limits.max_pushdata_bytes {
            return Err(Bip110Violation::PushdataTooLarge {
                actual: data.len(),
                limit: self.limits.max_pushdata_bytes,
            });
        }
        Ok(())
    }

    /// Validate a pushdata payload for BIP-110 compliance.
    pub fn validate_pushdata(&self, data: &[u8]) -> ConclaveResult<()> {
        self.validate_pushdata_violation(data)
            .map_err(|_| ConclaveError::InvalidPayload)
    }

    fn validate_script_pubkey_violation(
        &self,
        script_pubkey: &[u8],
    ) -> Result<(), Bip110Violation> {
        let script = ScriptPubKeyBuf::from_bytes(script_pubkey.to_vec());
        if script.is_op_return() {
            if script_pubkey.len() > self.limits.max_op_return_bytes {
                return Err(Bip110Violation::OpReturnTooLarge {
                    actual: script_pubkey.len(),
                    limit: self.limits.max_op_return_bytes,
                });
            }
        } else if script_pubkey.len() > self.limits.max_script_pubkey_bytes {
            return Err(Bip110Violation::ScriptPubkeyTooLarge {
                actual: script_pubkey.len(),
                limit: self.limits.max_script_pubkey_bytes,
            });
        }
        Ok(())
    }

    /// Validate the full serialized output `scriptPubKey`.
    ///
    /// BIP-110 boundaries are inclusive: non-OP_RETURN scripts of 34 bytes and
    /// first-opcode-OP_RETURN scripts of 83 bytes are accepted.
    pub fn validate_script_pubkey<S: AsRef<[u8]>>(&self, script_pubkey: S) -> ConclaveResult<()> {
        self.validate_script_pubkey_violation(script_pubkey.as_ref())
            .map_err(|_| ConclaveError::InvalidPayload)
    }

    fn validate_script_pushdata_violation(&self, script: &[u8]) -> Result<(), Bip110Violation> {
        let script = ScriptSigBuf::from_bytes(script.to_vec());
        for instruction in script.instructions() {
            match instruction {
                Ok(Instruction::Op(_)) => {}
                Ok(Instruction::PushBytes(bytes)) => {
                    self.validate_pushdata_violation(bytes.as_bytes())?
                }
                Err(_) => return Err(Bip110Violation::MalformedScript),
            }
        }
        Ok(())
    }

    /// Validate every data push in a serialized script.
    pub fn validate_script_pushdata<S: AsRef<[u8]>>(&self, script: S) -> ConclaveResult<()> {
        self.validate_script_pushdata_violation(script.as_ref())
            .map_err(|_| ConclaveError::InvalidPayload)
    }

    /// Validate a script-argument witness item.
    ///
    /// Witness scripts and Tapleaf scripts are intentionally not accepted by
    /// this helper; they have different BIP-110 treatment and should be passed
    /// through their own context-aware call sites.
    pub fn validate_script_argument_witness_item(&self, item: &[u8]) -> ConclaveResult<()> {
        if item.len() > self.limits.max_pushdata_bytes {
            return Err(Bip110Violation::WitnessItemTooLarge {
                actual: item.len(),
                limit: self.limits.max_pushdata_bytes,
            }
            .into_conclave_error());
        }
        Ok(())
    }

    /// Validate a Taproot control block's serialized size and shape.
    ///
    /// This checks only the byte-length structure. It does not validate the
    /// control block's parity bit, leaf version semantics, or Merkle proof.
    pub fn validate_taproot_control_block(&self, control_block: &[u8]) -> ConclaveResult<()> {
        if control_block.len() > MAX_TAPROOT_CONTROL_BLOCK_BYTES {
            return Err(Bip110Violation::TaprootControlBlockTooLarge {
                actual: control_block.len(),
                limit: MAX_TAPROOT_CONTROL_BLOCK_BYTES,
            }
            .into_conclave_error());
        }
        if control_block.len() < MIN_TAPROOT_CONTROL_BLOCK_BYTES
            || (control_block.len() - MIN_TAPROOT_CONTROL_BLOCK_BYTES) % 32 != 0
        {
            return Err(Bip110Violation::MalformedTaprootControlBlock {
                actual: control_block.len(),
            }
            .into_conclave_error());
        }
        Ok(())
    }

    fn max_chunk_payload(&self) -> Option<usize> {
        self.limits
            .max_pushdata_bytes
            .min(MAX_PUSH_DATA_BYTES)
            .checked_sub(1)
            .filter(|payload| *payload > 0)
    }

    /// Segment a message into length-prefixed BIP-110-sized chunks.
    ///
    /// This is a generic client-side helper, not BIP-322 serialization. A
    /// non-empty message cannot be represented when the configured maximum
    /// leaves no room for a one-byte chunk length, so the method fails closed.
    pub fn validate_message_chunking(&self, message: &str) -> ConclaveResult<Vec<Vec<u8>>> {
        let max_payload = self
            .max_chunk_payload()
            .ok_or(ConclaveError::InvalidPayload)?;
        let message_bytes = message.as_bytes();
        if message_bytes.is_empty() {
            return Ok(Vec::new());
        }

        let mut chunks = Vec::new();
        let mut remaining = message_bytes;

        while !remaining.is_empty() {
            let chunk_size = remaining.len().min(max_payload);
            let mut chunk = Vec::with_capacity(1 + chunk_size);
            chunk.push(chunk_size as u8);
            chunk.extend_from_slice(&remaining[..chunk_size]);
            chunks.push(chunk);
            remaining = &remaining[chunk_size..];
        }

        Ok(chunks)
    }

    /// Compatibility wrapper for the original infallible chunk-count API.
    ///
    /// Invalid zero-capacity configurations return `0` instead of panicking.
    /// Prefer [`Self::try_chunk_count`] when configuration errors matter.
    #[deprecated(note = "use try_chunk_count for fallible validation")]
    pub fn chunk_count(&self, message: &str) -> usize {
        self.try_chunk_count(message).unwrap_or_default()
    }

    /// Calculate the number of length-prefixed chunks needed for a message.
    pub fn try_chunk_count(&self, message: &str) -> ConclaveResult<usize> {
        let max_payload = self
            .max_chunk_payload()
            .ok_or(ConclaveError::InvalidPayload)?;
        Ok(message.len().div_ceil(max_payload))
    }

    /// Check if a message needs generic client-side chunking.
    pub fn requires_chunking(&self, message: &str) -> bool {
        if message.is_empty() {
            return false;
        }

        self.max_chunk_payload()
            .is_none_or(|max_payload| message.len() > max_payload)
    }
}

impl Default for Bip110Validator {
    fn default() -> Self {
        Self::new()
    }
}

/// Compatibility wrapper for the original infallible segmentation API.
///
/// A zero-sized configuration returns an empty result instead of panicking or
/// dropping data. Prefer [`try_chunk_for_bip110`] when configuration errors
/// matter.
#[deprecated(note = "use try_chunk_for_bip110 for fallible validation")]
pub fn chunk_for_bip110(data: &[u8], max_chunk_size: usize) -> Vec<Vec<u8>> {
    try_chunk_for_bip110(data, max_chunk_size).unwrap_or_default()
}

/// Strictly chunk data into BIP-110-sized segments without silently truncating
/// data or accepting a zero-sized configuration.
pub fn try_chunk_for_bip110(data: &[u8], max_chunk_size: usize) -> ConclaveResult<Vec<Vec<u8>>> {
    let max_size = max_chunk_size.min(MAX_PUSH_DATA_BYTES);
    if max_size == 0 {
        return Err(ConclaveError::InvalidPayload);
    }

    Ok(data.chunks(max_size).map(|chunk| chunk.to_vec()).collect())
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
    fn test_validate_pushdata_boundaries() {
        let validator = Bip110Validator::new();
        assert!(validator.validate_pushdata(&vec![0u8; 256]).is_ok());
        assert!(validator.validate_pushdata(&vec![0u8; 257]).is_err());
    }

    #[test]
    fn test_validate_script_pubkey_boundaries() {
        let validator = Bip110Validator::new();

        assert!(validator.validate_script_pubkey(vec![0u8; 34]).is_ok());
        assert!(validator.validate_script_pubkey(vec![0u8; 35]).is_err());

        let mut op_return_83 = vec![0x6a];
        op_return_83.extend(std::iter::repeat_n(0u8, 82));
        assert!(validator.validate_script_pubkey(&op_return_83).is_ok());

        let mut op_return_84 = vec![0x6a];
        op_return_84.extend(std::iter::repeat_n(0u8, 83));
        assert!(validator.validate_script_pubkey(&op_return_84).is_err());
    }

    #[test]
    fn test_validate_script_pushdata() {
        let validator = Bip110Validator::new();

        let mut compliant = vec![0x4d, 0x00, 0x01];
        compliant.extend(std::iter::repeat_n(0u8, 256));
        assert!(validator.validate_script_pushdata(&compliant).is_ok());

        let mut oversized = vec![0x4d, 0x01, 0x01];
        oversized.extend(std::iter::repeat_n(0u8, 257));
        assert!(validator.validate_script_pushdata(&oversized).is_err());
    }

    #[test]
    fn test_context_aware_witness_limits() {
        let validator = Bip110Validator::new();
        assert!(validator
            .validate_script_argument_witness_item(&vec![0u8; 256])
            .is_ok());
        assert!(validator
            .validate_script_argument_witness_item(&vec![0u8; 257])
            .is_err());
        assert!(validator
            .validate_taproot_control_block(&vec![0u8; 257])
            .is_ok());
        assert!(validator
            .validate_taproot_control_block(&vec![0u8; 258])
            .is_err());
        assert!(validator
            .validate_taproot_control_block(&vec![0u8; 34])
            .is_err());
    }

    #[test]
    fn test_with_limits_cannot_relax_consensus_maxima() {
        let validator = Bip110Validator::with_limits(Bip110Limits {
            max_pushdata_bytes: 999,
            max_op_return_bytes: 999,
            max_script_pubkey_bytes: 999,
        });
        assert_eq!(validator.limits(), Bip110Limits::default());
        assert!(Bip110Validator::try_with_limits(Bip110Limits {
            max_pushdata_bytes: 257,
            ..Bip110Limits::default()
        })
        .is_err());
    }

    #[test]
    #[allow(deprecated)]
    fn test_chunk_count_public_compatibility_and_strict_variant() {
        let validator = Bip110Validator::new();
        #[allow(deprecated)]
        let compatibility_count = validator.chunk_count("hello");
        assert_eq!(compatibility_count, 1);
        assert_eq!(validator.try_chunk_count("hello").unwrap(), 1);

        let zero = Bip110Validator::with_limits(Bip110Limits {
            max_pushdata_bytes: 0,
            ..Bip110Limits::default()
        });
        assert_eq!(zero.chunk_count("x"), 0);
        assert!(zero.try_chunk_count("x").is_err());
    }

    #[test]
    fn test_requires_chunking() {
        let validator = Bip110Validator::new();
        assert!(!validator.requires_chunking("hello"));
        assert!(validator.requires_chunking(&"x".repeat(300)));
    }

    #[test]
    fn test_message_chunking() {
        let validator = Bip110Validator::new();
        let message = "hello world";
        let chunks = validator.validate_message_chunking(message).unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0][0], message.len() as u8);
        assert_eq!(&chunks[0][1..], message.as_bytes());
    }

    #[test]
    fn test_message_chunking_long() {
        let validator = Bip110Validator::new();
        let message = "x".repeat(300);
        let chunks = validator.validate_message_chunking(&message).unwrap();
        assert_eq!(chunks.len(), 2);
        assert!(chunks.iter().all(|chunk| chunk.len() <= 256));
    }

    #[test]
    #[allow(deprecated)]
    fn test_chunk_for_bip110_public_compatibility_and_strict_variant() {
        let data = vec![0u8; 300];
        #[allow(deprecated)]
        let compatibility_chunks = chunk_for_bip110(&data, 256);
        assert_eq!(compatibility_chunks.len(), 2);
        assert_eq!(compatibility_chunks[0].len(), 256);
        assert_eq!(compatibility_chunks[1].len(), 44);

        let strict_chunks = try_chunk_for_bip110(&data, 256).unwrap();
        assert_eq!(strict_chunks, compatibility_chunks);

        assert!(chunk_for_bip110(&[1u8], 0).is_empty());
        assert!(try_chunk_for_bip110(&[1u8], 0).is_err());
        assert!(try_chunk_for_bip110(&[], 0).is_err());
    }

    #[test]
    fn test_ordered_commitment_segmentation() {
        let large_commitment: Vec<u8> = (0..1000).map(|index| (index % 251) as u8).collect();
        let chunks = try_chunk_for_bip110(&large_commitment, 256).unwrap();
        let validator = Bip110Validator::new();

        for chunk in &chunks {
            assert!(validator.validate_pushdata(chunk).is_ok());
        }

        let reconstructed: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(reconstructed, large_commitment);
    }
}
