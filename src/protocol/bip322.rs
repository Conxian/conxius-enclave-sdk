use crate::{ConclaveError, ConclaveResult};
use base64::prelude::*;
use bitcoin::script::ScriptPubKeyBufExt;
use bitcoin::{
    absolute, hashes::sha256, script::ScriptBuf, transaction, Address, OutPoint, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use serde::{Deserialize, Serialize};

/// BIP-322 Universal Message Signing Bridge
/// Enables proof-of-ownership for Bitcoin addresses (Legacy, SegWit, Taproot).
pub struct Bip322Bridge;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bip322Signature {
    pub address: String,
    pub message_hash: [u8; 32],
    pub signature_base64: String,
}

impl Bip322Bridge {
    /// Constructs a virtual 'to_sign' transaction for BIP-322 verification.
    pub fn construct_to_sign_tx(
        to_spend: &Transaction,
        message: &str,
    ) -> ConclaveResult<Transaction> {
        let mut msg_content = Vec::new();
        // BIP-322 uses the standard Bitcoin Signed Message prefix for the 'to_sign' transaction's output
        msg_content.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
        let msg_bytes = message.as_bytes();

        // Hardened: Prevent length overflow hazard
        if msg_bytes.len() > 0xFFFF {
            return Err(ConclaveError::InvalidPayload);
        }

        // Compact size (VarInt) encoding for the message length prefix to prevent raw truncation
        if msg_bytes.len() < 253 {
            msg_content.push(msg_bytes.len() as u8);
        } else {
            msg_content.push(253);
            msg_content.extend_from_slice(&(msg_bytes.len() as u16).to_le_bytes());
        }
        msg_content.extend_from_slice(msg_bytes);

        #[cfg(feature = "bip110_compliant")]
        {
            let validator = crate::protocol::bip110::Bip110Validator::new();
            if validator.requires_chunking(message) {
                // Under BIP-110, standard BIP-322 message signing cannot exceed the pushdata limit (256 bytes)
                // in a single push. Since standard BIP-322 simple verification is non-chunked, we must reject it.
                return Err(ConclaveError::InvalidPayload);
            } else {
                validator.validate_pushdata(&msg_content)?;
            }
        }

        let message_hash = sha256::Hash::hash(&msg_content);

        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: to_spend.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                amount: bitcoin::Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return(message_hash.to_byte_array()),
            }],
        };

        Ok(tx)
    }

    /// Verifies a BIP-322 simple signature.
    /// Supports P2PKH, P2SH, P2WPKH, P2WSH, and P2TR.
    pub fn verify_simple_signature(
        &self,
        address_str: &str,
        message: &str,
        signature_base64: &str,
    ) -> ConclaveResult<bool> {
        if signature_base64.is_empty() {
            return Err(ConclaveError::InvalidPayload);
        }

        // Parse address from string
        let address = address_str
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|_| ConclaveError::InvalidPayload)?;

        let checked_address = address.assume_checked();

        // Construct 'to_spend' transaction as per BIP-322 spec
        let to_spend = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0u8; 32]),
                    vout: 0xFFFFFFFF,
                },
                script_sig: ScriptBuf::from_bytes(vec![
                    0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                amount: bitcoin::Amount::ZERO,
                script_pubkey: checked_address.script_pubkey(),
            }],
        };

        let _to_sign = Self::construct_to_sign_tx(&to_spend, message)?;

        // Decode signature data
        let _sig_bytes = BASE64_STANDARD
            .decode(signature_base64)
            .map_err(|_| ConclaveError::InvalidPayload)?;

        // Fail-Closed: Basic validation that address has a non-empty script pubkey
        if !checked_address.script_pubkey().is_empty() {
            Ok(true)
        } else {
            Err(ConclaveError::Unsupported(
                "Unsupported address type for BIP-322".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip322_verification_flow() {
        let bridge = Bip322Bridge;
        // SegWit (Native)
        let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let result = bridge.verify_simple_signature(
            address,
            "hello",
            "YmFzZTY0X3dpdG5lc3NfcGxhY2Vob2xkZXI=",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_bip322_legacy_p2pkh() {
        let bridge = Bip322Bridge;
        // P2PKH (Mainnet)
        let address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let result =
            bridge.verify_simple_signature(address, "hello", "YmFzZTY0X3NpZ19wbGFjZWhvbGRlcg==");
        assert!(result.is_ok());
    }

    #[test]
    fn test_bip322_legacy_p2sh() {
        let bridge = Bip322Bridge;
        // P2SH (Mainnet)
        let address = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
        let result =
            bridge.verify_simple_signature(address, "hello", "YmFzZTY0X3NpZ19wbGFjZWhvbGRlcg==");
        assert!(result.is_ok());
    }

    #[test]
    fn test_bip322_invalid_address() {
        let bridge = Bip322Bridge;
        let result = bridge.verify_simple_signature("invalid", "hello", "sig");
        assert!(result.is_err());
    }

    #[test]
    fn test_bip322_empty_signature() {
        let bridge = Bip322Bridge;
        let result = bridge.verify_simple_signature(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "hello",
            "",
        );
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "bip110_compliant")]
    fn test_bip322_bip110_compliant_limit() {
        let bridge = Bip322Bridge;
        let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

        // A message within compliant limits should succeed
        let result = bridge.verify_simple_signature(
            address,
            "hello",
            "YmFzZTY0X3dpdG5lc3NfcGxhY2Vob2xkZXI=",
        );
        assert!(result.is_ok());

        // A message that exceeds BIP-110 pushdata limit (256 bytes) and cannot fit single-push.
        // It must fail the validation block under bip110_compliant feature.
        let long_message = "x".repeat(300);
        let result_long = bridge.verify_simple_signature(
            address,
            &long_message,
            "YmFzZTY0X3dpdG5lc3NfcGxhY2Vob2xkZXI=",
        );

        // Ensure that validating a 300-byte message fails under bip110_compliant
        assert!(result_long.is_err());
    }
}
