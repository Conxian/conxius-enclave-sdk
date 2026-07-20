use crate::{ConclaveError, ConclaveResult};
use base64::prelude::*;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::sha256;
use bitcoin::script::{ScriptBufExt, ScriptExt, ScriptPubKeyBuf, ScriptPubKeyExt, ScriptSigBuf};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    absolute, ecdsa, key::CompressedPublicKey, secp256k1, taproot, transaction, Address, Amount,
    OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const BIP322_MESSAGE_TAG: &[u8] = b"BIP0322-signed-message";
const TAPROOT_CONTROL_BLOCK_MIN_BYTES: usize = 33;
const TAPROOT_CONTROL_BLOCK_MAX_BYTES: usize = 257;

/// BIP-322 Universal Message Signing Bridge.
///
/// Simple verification is intentionally limited to native P2WPKH and Taproot
/// key-path witnesses. P2WSH and Taproot script-path witnesses are structurally
/// checked where possible and returned as unsupported because this crate does
/// not contain a Bitcoin Script interpreter. Legacy, P2SH, P2A, and future
/// witness-version addresses are unsupported for simple verification.
pub struct Bip322Bridge;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bip322Signature {
    pub address: String,
    pub message_hash: [u8; 32],
    pub signature_base64: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimpleChallenge {
    P2wpkh,
    P2wsh,
    P2tr,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaprootWitnessKind {
    KeyPath,
    ScriptPath,
    Annex,
}

impl Bip322Bridge {
    /// Calculate the BIP-322 tagged hash of the message bytes.
    ///
    /// The message is hashed as-is, without the legacy Bitcoin Signed Message
    /// prefix, a length prefix, or a null terminator.
    pub fn message_hash(message: &str) -> [u8; 32] {
        let tag_hash = Sha256::digest(BIP322_MESSAGE_TAG);
        let mut hasher = Sha256::new();
        hasher.update(tag_hash);
        hasher.update(tag_hash);
        hasher.update(message.as_bytes());
        hasher.finalize().into()
    }

    /// Construct the BIP-322 virtual `to_spend` transaction.
    ///
    /// With `bip110_compliant`, this validates output-creation limits but does
    /// not reject a future witness version. Future or undefined witness
    /// versions become unsupported only when a spend context is constructed.
    pub fn construct_to_spend_tx(
        script_pubkey: ScriptPubKeyBuf,
        message: &str,
    ) -> ConclaveResult<Transaction> {
        let message_hash = Self::message_hash(message);
        let mut script_sig = Vec::with_capacity(34);
        script_sig.push(0x00); // OP_0
        script_sig.push(0x20); // PUSH32
        script_sig.extend_from_slice(&message_hash);

        let tx = Transaction {
            version: transaction::Version::maybe_non_standard(0),
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0u8; 32]),
                    vout: u32::MAX,
                },
                script_sig: ScriptSigBuf::from_bytes(script_sig),
                sequence: Sequence::ZERO,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                amount: Amount::ZERO,
                script_pubkey,
            }],
        };

        Self::validate_to_spend_shape(&tx, Some(message))?;

        #[cfg(feature = "bip110_compliant")]
        Self::validate_bip110_to_spend_output(&tx)?;

        Ok(tx)
    }

    /// Constructs a virtual `to_sign` transaction for BIP-322 verification.
    ///
    /// The supplied message is checked against the canonical message hash in
    /// `to_spend`; it is not ignored.
    pub fn construct_to_sign_tx(
        to_spend: &Transaction,
        message: &str,
    ) -> ConclaveResult<Transaction> {
        Self::construct_to_sign_tx_with_witness_and_message(to_spend, message, Witness::default())
    }

    /// Construct `to_sign` with a supplied witness and message binding.
    pub fn construct_to_sign_tx_with_witness_and_message(
        to_spend: &Transaction,
        message: &str,
        witness: Witness,
    ) -> ConclaveResult<Transaction> {
        Self::validate_to_spend_shape(to_spend, Some(message))?;
        Self::construct_to_sign_tx_unchecked(to_spend, witness)
    }

    /// Construct `to_sign` from a canonical `to_spend` without a message.
    ///
    /// This compatibility wrapper validates the complete transaction shape but
    /// cannot validate message binding because no message is supplied. Callers
    /// performing verification must use
    /// [`Self::construct_to_sign_tx_with_witness_and_message`].
    pub fn construct_to_sign_tx_with_witness(
        to_spend: &Transaction,
        witness: Witness,
    ) -> ConclaveResult<Transaction> {
        Self::validate_to_spend_shape(to_spend, None)?;
        Self::construct_to_sign_tx_unchecked(to_spend, witness)
    }

    fn construct_to_sign_tx_unchecked(
        to_spend: &Transaction,
        witness: Witness,
    ) -> ConclaveResult<Transaction> {
        let tx = Transaction {
            version: transaction::Version::maybe_non_standard(0),
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: to_spend.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::ZERO,
                witness,
            }],
            outputs: vec![TxOut {
                amount: Amount::ZERO,
                // BIP-322's virtual output is exactly OP_RETURN, with no data push.
                script_pubkey: ScriptPubKeyBuf::from_bytes(vec![0x6a]),
            }],
        };

        #[cfg(feature = "bip110_compliant")]
        Self::validate_bip110_to_sign_context(to_spend, &tx.inputs[0].witness)?;

        Ok(tx)
    }

    fn validate_to_spend_shape(
        to_spend: &Transaction,
        expected_message: Option<&str>,
    ) -> ConclaveResult<()> {
        if to_spend.version.to_u32() != 0
            || to_spend.lock_time != absolute::LockTime::ZERO
            || to_spend.inputs.len() != 1
            || to_spend.outputs.len() != 1
        {
            return Err(ConclaveError::InvalidPayload);
        }

        let input = &to_spend.inputs[0];
        if input.previous_output.txid != Txid::from_byte_array([0u8; 32])
            || input.previous_output.vout != u32::MAX
            || input.sequence != Sequence::ZERO
            || !input.witness.is_empty()
        {
            return Err(ConclaveError::InvalidPayload);
        }

        let script_sig = input.script_sig.as_bytes();
        if script_sig.len() != 34 || script_sig[0] != 0x00 || script_sig[1] != 0x20 {
            return Err(ConclaveError::InvalidPayload);
        }
        if let Some(message) = expected_message {
            if script_sig[2..] != Self::message_hash(message) {
                return Err(ConclaveError::InvalidPayload);
            }
        }

        let output = &to_spend.outputs[0];
        if output.amount != Amount::ZERO || output.script_pubkey.is_empty() {
            return Err(ConclaveError::InvalidPayload);
        }

        Ok(())
    }

    #[cfg(feature = "bip110_compliant")]
    fn validate_bip110_to_spend_output(to_spend: &Transaction) -> ConclaveResult<()> {
        let validator = crate::protocol::bip110::Bip110Validator::new();
        let input = &to_spend.inputs[0];
        let output = &to_spend.outputs[0];

        validator.validate_script_pushdata(input.script_sig.as_bytes())?;
        validator.validate_script_pubkey(output.script_pubkey.as_bytes())?;
        Ok(())
    }

    #[cfg(feature = "bip110_compliant")]
    fn validate_bip110_to_sign_context(
        to_spend: &Transaction,
        witness: &Witness,
    ) -> ConclaveResult<()> {
        let validator = crate::protocol::bip110::Bip110Validator::new();
        let output = &to_spend.outputs[0];

        Self::validate_bip110_to_spend_output(to_spend)?;
        validator.validate_script_pubkey([0x6a])?;

        if output.script_pubkey.is_witness_program()
            && !output.script_pubkey.is_p2wpkh()
            && !output.script_pubkey.is_p2wsh()
            && !output.script_pubkey.is_p2tr()
            && !output.script_pubkey.is_p2a()
        {
            return Err(ConclaveError::Unsupported(
                "Future or undefined witness versions are unsupported in BIP-110 mode".to_string(),
            ));
        }

        Self::validate_bip110_witness(&validator, &output.script_pubkey, witness)
    }

    #[cfg(feature = "bip110_compliant")]
    fn validate_bip110_witness(
        validator: &crate::protocol::bip110::Bip110Validator,
        script_pubkey: &ScriptPubKeyBuf,
        witness: &Witness,
    ) -> ConclaveResult<()> {
        if script_pubkey.is_p2a() {
            return Err(ConclaveError::Unsupported(
                "P2A spend construction is unsupported in BIP-110 mode".to_string(),
            ));
        }

        if Self::challenge_type(script_pubkey) == SimpleChallenge::Unsupported {
            return Err(ConclaveError::Unsupported(
                "BIP-110 simple signing supports only native P2WPKH, P2WSH, and P2TR scriptPubKeys"
                    .to_string(),
            ));
        }

        if witness.is_empty() {
            return Ok(());
        }

        if script_pubkey.is_p2wpkh() {
            for item in witness.iter() {
                validator.validate_script_argument_witness_item(item)?;
            }
        } else if script_pubkey.is_p2wsh() {
            Self::validate_p2wsh_witness_structure(script_pubkey, witness)?;
            for item in witness.iter().take(witness.len() - 1) {
                validator.validate_script_argument_witness_item(item)?;
            }
            let witness_script = witness.last().ok_or(ConclaveError::InvalidPayload)?;
            validator.validate_script_pushdata(witness_script)?;
        } else if script_pubkey.is_p2tr() {
            let _ = Self::inspect_taproot_witness(witness, Some(validator))?;
        }

        Ok(())
    }

    #[cfg(feature = "bip110_compliant")]
    fn inspect_taproot_witness_with_validator(
        witness: &Witness,
        validator: &crate::protocol::bip110::Bip110Validator,
    ) -> ConclaveResult<TaprootWitnessKind> {
        Self::inspect_taproot_witness(witness, Some(validator))
    }

    fn inspect_taproot_witness(
        witness: &Witness,
        #[cfg(feature = "bip110_compliant")] validator: Option<
            &crate::protocol::bip110::Bip110Validator,
        >,
        #[cfg(not(feature = "bip110_compliant"))] _validator: Option<()>,
    ) -> ConclaveResult<TaprootWitnessKind> {
        if witness.is_empty() {
            return Err(ConclaveError::InvalidPayload);
        }

        let annex = if witness.len() >= 2
            && witness
                .last()
                .is_some_and(|item| item.first() == Some(&0x50))
        {
            Some(witness.last().ok_or(ConclaveError::InvalidPayload)?)
        } else {
            None
        };
        let spend_len = witness.len() - usize::from(annex.is_some());

        #[cfg(feature = "bip110_compliant")]
        if annex.is_some() {
            return Err(ConclaveError::Unsupported(
                "Taproot annex spends are unsupported in BIP-110 mode".to_string(),
            ));
        }

        if spend_len == 0 {
            return Err(ConclaveError::InvalidPayload);
        }

        if spend_len == 1 {
            let signature = witness.get(0).ok_or(ConclaveError::InvalidPayload)?;
            if signature.len() != 64 && signature.len() != 65 {
                return Err(ConclaveError::InvalidPayload);
            }
            return if annex.is_some() {
                Ok(TaprootWitnessKind::Annex)
            } else {
                Ok(TaprootWitnessKind::KeyPath)
            };
        }

        let control_block_index = spend_len - 1;
        let tapscript_index = spend_len - 2;
        let control_block = witness
            .get(control_block_index)
            .ok_or(ConclaveError::InvalidPayload)?;
        Self::validate_taproot_control_block_shape(control_block)?;

        let tapscript = witness
            .get(tapscript_index)
            .ok_or(ConclaveError::InvalidPayload)?;
        Self::validate_serialized_script(tapscript)?;

        #[cfg(feature = "bip110_compliant")]
        {
            for index in 0..tapscript_index {
                let item = witness.get(index).ok_or(ConclaveError::InvalidPayload)?;
                if let Some(validator) = validator {
                    validator.validate_script_argument_witness_item(item)?;
                }
            }
        }

        #[cfg(feature = "bip110_compliant")]
        if let Some(validator) = validator {
            validator.validate_taproot_control_block(control_block)?;
            Self::validate_defined_taproot_control_block(control_block)?;
            validator.validate_script_pushdata(tapscript)?;
        }

        if annex.is_some() {
            Ok(TaprootWitnessKind::Annex)
        } else {
            Ok(TaprootWitnessKind::ScriptPath)
        }
    }

    fn validate_taproot_control_block_shape(control_block: &[u8]) -> ConclaveResult<()> {
        if !(TAPROOT_CONTROL_BLOCK_MIN_BYTES..=TAPROOT_CONTROL_BLOCK_MAX_BYTES)
            .contains(&control_block.len())
            || (control_block.len() - TAPROOT_CONTROL_BLOCK_MIN_BYTES) % 32 != 0
        {
            return Err(ConclaveError::InvalidPayload);
        }
        Ok(())
    }

    #[cfg(feature = "bip110_compliant")]
    fn validate_defined_taproot_control_block(control_block: &[u8]) -> ConclaveResult<()> {
        let control_block = taproot::ControlBlock::decode(control_block)
            .map_err(|_| ConclaveError::InvalidPayload)?;
        if control_block.leaf_version != taproot::LeafVersion::TapScript {
            return Err(ConclaveError::Unsupported(
                "Future or undefined Taproot leaf versions are unsupported in BIP-110 mode"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_serialized_script(script: &[u8]) -> ConclaveResult<()> {
        let script = ScriptSigBuf::from_bytes(script.to_vec());
        if script
            .instructions()
            .any(|instruction| instruction.is_err())
        {
            return Err(ConclaveError::InvalidPayload);
        }
        Ok(())
    }

    fn validate_p2wsh_witness_structure(
        script_pubkey: &ScriptPubKeyBuf,
        witness: &Witness,
    ) -> ConclaveResult<()> {
        let witness_script = witness.last().ok_or(ConclaveError::InvalidPayload)?;
        Self::validate_serialized_script(witness_script)?;

        let expected_hash = &script_pubkey.as_bytes()[2..];
        let actual_hash = sha256::Hash::hash(witness_script);
        if actual_hash.as_byte_array() != expected_hash {
            return Err(ConclaveError::InvalidPayload);
        }
        Ok(())
    }

    fn decode_simple_signature_witness(signature_base64: &str) -> ConclaveResult<Witness> {
        let encoded = signature_base64
            .strip_prefix("smp")
            .unwrap_or(signature_base64);
        let signature_bytes = BASE64_STANDARD
            .decode(encoded)
            .map_err(|_| ConclaveError::InvalidPayload)?;
        if signature_bytes.is_empty() {
            return Err(ConclaveError::InvalidPayload);
        }

        deserialize::<Witness>(&signature_bytes).map_err(|_| ConclaveError::InvalidPayload)
    }

    fn challenge_type(script_pubkey: &ScriptPubKeyBuf) -> SimpleChallenge {
        if script_pubkey.is_p2wpkh() {
            SimpleChallenge::P2wpkh
        } else if script_pubkey.is_p2wsh() {
            SimpleChallenge::P2wsh
        } else if script_pubkey.is_p2tr() {
            SimpleChallenge::P2tr
        } else {
            SimpleChallenge::Unsupported
        }
    }

    fn unsupported_simple_signature() -> ConclaveError {
        ConclaveError::Unsupported(
            "BIP-322 simple verification supports only native P2WPKH and P2TR key-path witnesses"
                .to_string(),
        )
    }

    fn verify_p2wpkh(
        to_spend: &Transaction,
        to_sign: &Transaction,
        witness: &Witness,
    ) -> ConclaveResult<bool> {
        if witness.len() != 2 {
            return Err(ConclaveError::InvalidPayload);
        }

        let signature_bytes = witness.get(0).ok_or(ConclaveError::InvalidPayload)?;
        let public_key_bytes = witness.get(1).ok_or(ConclaveError::InvalidPayload)?;
        let signature = ecdsa::Signature::from_slice(signature_bytes)
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let public_key = CompressedPublicKey::from_slice(public_key_bytes)
            .map_err(|_| ConclaveError::InvalidPayload)?;

        if signature.sighash_type != EcdsaSighashType::All {
            return Ok(false);
        }

        let mut normalized_signature = signature.signature;
        normalized_signature.normalize_s();
        if normalized_signature != signature.signature {
            return Ok(false);
        }

        let expected_script = ScriptPubKeyBuf::new_p2wpkh(public_key.wpubkey_hash());
        if expected_script != to_spend.outputs[0].script_pubkey {
            return Ok(false);
        }

        let mut sighash_cache = SighashCache::new(to_sign);
        let sighash = sighash_cache
            .p2wpkh_signature_hash(
                0,
                &to_spend.outputs[0].script_pubkey,
                Amount::ZERO,
                EcdsaSighashType::All,
            )
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let message = secp256k1::Message::from_digest(sighash.to_byte_array());

        Ok(public_key.verify(message, signature).is_ok())
    }

    fn verify_p2tr(
        to_spend: &Transaction,
        to_sign: &Transaction,
        witness: &Witness,
    ) -> ConclaveResult<bool> {
        if witness.len() != 1 {
            return Err(ConclaveError::InvalidPayload);
        }

        let signature_bytes = witness.get(0).ok_or(ConclaveError::InvalidPayload)?;
        let signature = taproot::Signature::from_slice(signature_bytes)
            .map_err(|_| ConclaveError::InvalidPayload)?;
        if signature.sighash_type != TapSighashType::Default
            && signature.sighash_type != TapSighashType::All
        {
            return Ok(false);
        }

        let output_key_bytes: [u8; 32] = to_spend.outputs[0].script_pubkey.as_bytes()[2..]
            .try_into()
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let output_key = secp256k1::XOnlyPublicKey::from_byte_array(output_key_bytes)
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let prevout = [to_spend.outputs[0].clone()];
        let prevouts = Prevouts::All(&prevout);
        let mut sighash_cache = SighashCache::new(to_sign);
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(0, &prevouts, signature.sighash_type)
            .map_err(|_| ConclaveError::InvalidPayload)?;

        Ok(
            secp256k1::schnorr::verify(&signature.signature, &sighash.to_byte_array(), &output_key)
                .is_ok(),
        )
    }

    /// Verifies a BIP-322 simple signature.
    ///
    /// Supported cryptographic verification types:
    /// - native P2WPKH with a two-item ECDSA witness and `SIGHASH_ALL`;
    /// - P2TR key-path spends with a 64/65-byte Schnorr witness and
    ///   `SIGHASH_DEFAULT` or `SIGHASH_ALL`.
    ///
    /// P2WSH, Taproot script-path/annex, legacy, P2SH, P2A, and future witness
    /// versions return `ConclaveError::Unsupported` rather than being treated
    /// as valid. Malformed Base64, witness serialization, keys, signatures, or
    /// script structures return `ConclaveError::InvalidPayload`.
    pub fn verify_simple_signature(
        &self,
        address_str: &str,
        message: &str,
        signature_base64: &str,
    ) -> ConclaveResult<bool> {
        let address = address_str
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|_| ConclaveError::InvalidPayload)?
            .assume_checked();
        let script_pubkey = address.script_pubkey();

        let challenge = Self::challenge_type(&script_pubkey);
        if challenge == SimpleChallenge::Unsupported {
            return Err(Self::unsupported_simple_signature());
        }

        let to_spend = Self::construct_to_spend_tx(script_pubkey, message)?;
        let witness = Self::decode_simple_signature_witness(signature_base64)?;
        let to_sign = Self::construct_to_sign_tx_with_witness_and_message(
            &to_spend,
            message,
            witness.clone(),
        )?;

        match challenge {
            SimpleChallenge::P2wpkh => Self::verify_p2wpkh(&to_spend, &to_sign, &witness),
            SimpleChallenge::P2wsh => {
                Self::validate_p2wsh_witness_structure(
                    &to_spend.outputs[0].script_pubkey,
                    &witness,
                )?;
                Err(Self::unsupported_simple_signature())
            }
            SimpleChallenge::P2tr => {
                #[cfg(feature = "bip110_compliant")]
                let witness_kind = {
                    let validator = crate::protocol::bip110::Bip110Validator::new();
                    Self::inspect_taproot_witness_with_validator(&witness, &validator)?
                };
                #[cfg(not(feature = "bip110_compliant"))]
                let witness_kind = Self::inspect_taproot_witness(&witness, None)?;

                match witness_kind {
                    TaprootWitnessKind::KeyPath => {
                        Self::verify_p2tr(&to_spend, &to_sign, &witness)
                    }
                    TaprootWitnessKind::ScriptPath => {
                        Err(ConclaveError::Unsupported(
                            "Taproot script-path BIP-322 verification is unsupported without a Script interpreter"
                                .to_string(),
                        ))
                    }
                    TaprootWitnessKind::Annex => Err(ConclaveError::Unsupported(
                        "Taproot annex BIP-322 verification is unsupported".to_string(),
                    )),
                }
            }
            SimpleChallenge::Unsupported => Err(Self::unsupported_simple_signature()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{key::WPubkeyHash, Network};

    const P2WPKH_ADDRESS: &str = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";
    const P2WPKH_HELLO_SIGNATURE: &str =
        "smpAkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";
    const P2TR_ADDRESS: &str = "bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler";
    const P2TR_NO_PREFIX_SIGNATURE: &str =
        "AUCJYOwOjxYAvatTAGYaVlNXBVyFuc4MwNQkOuK2tl8xhfKDONd0NjfYyNSYcRqeCp8hsAnCEPHAVEkO9h6vbQ/R";

    fn bytes32(value: &str) -> [u8; 32] {
        hex::decode(value)
            .expect("test vector is valid hex")
            .try_into()
            .expect("test vector has 32 bytes")
    }

    fn p2wpkh_address(hash: [u8; 20]) -> String {
        let script = ScriptPubKeyBuf::new_p2wpkh(WPubkeyHash::from_byte_array(hash));
        Address::from_script(&script, Network::Bitcoin)
            .expect("P2WPKH script is an address")
            .to_string()
    }

    fn taproot_control_block(first_byte: u8) -> Vec<u8> {
        let mut control_block = vec![first_byte];
        control_block.extend_from_slice(&bytes32(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ));
        control_block
    }

    fn encode_witness(witness: &Witness) -> String {
        format!(
            "smp{}",
            BASE64_STANDARD.encode(bitcoin::consensus::encode::serialize(witness))
        )
    }

    #[test]
    fn test_bip322_official_p2wpkh_positive_vector() {
        let bridge = Bip322Bridge;
        assert!(matches!(
            bridge.verify_simple_signature(P2WPKH_ADDRESS, "Hello World", P2WPKH_HELLO_SIGNATURE),
            Ok(true)
        ));
    }

    #[test]
    fn test_bip322_official_p2tr_positive_vector_without_prefix() {
        let bridge = Bip322Bridge;
        assert!(matches!(
            bridge.verify_simple_signature(
                P2TR_ADDRESS,
                "No prefix fallback",
                P2TR_NO_PREFIX_SIGNATURE,
            ),
            Ok(true)
        ));
    }

    #[test]
    fn test_bip322_official_negative_vectors() {
        let bridge = Bip322Bridge;
        assert!(matches!(
            bridge.verify_simple_signature(P2WPKH_ADDRESS, "Wrong message", P2WPKH_HELLO_SIGNATURE),
            Ok(false)
        ));

        let other_address = p2wpkh_address([1u8; 20]);
        assert!(matches!(
            bridge.verify_simple_signature(&other_address, "Hello World", P2WPKH_HELLO_SIGNATURE),
            Ok(false)
        ));

        assert!(matches!(
            bridge.verify_simple_signature(P2WPKH_ADDRESS, "", "smpAA=="),
            Err(ConclaveError::InvalidPayload)
        ));
        assert!(matches!(
            bridge.verify_simple_signature(P2WPKH_ADDRESS, "", "not-valid-base64!!!"),
            Err(ConclaveError::InvalidPayload)
        ));
        assert!(matches!(
            bridge.verify_simple_signature(P2WPKH_ADDRESS, "", "smpAAABAA=="),
            Err(ConclaveError::InvalidPayload)
        ));
    }

    #[test]
    fn test_bip322_unsupported_address_types_fail_closed() {
        let bridge = Bip322Bridge;
        assert!(matches!(
            bridge.verify_simple_signature(
                "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                "hello",
                "not-a-witness",
            ),
            Err(ConclaveError::Unsupported(_))
        ));
        assert!(matches!(
            bridge.verify_simple_signature(
                "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
                "hello",
                "not-a-witness",
            ),
            Err(ConclaveError::Unsupported(_))
        ));
    }

    #[test]
    fn test_bip322_p2wsh_and_taproot_script_path_are_unsupported() {
        let bridge = Bip322Bridge;
        let p2wsh_address = "bc1qp0ahvfh83088w49k405szqgg4f3pptr7p2g06tdxfjcd40z4lh4q95lsz9";
        let p2wsh_signature = "smpBQBHMEQCIFX9aaqPJWq2Ff2kpen5bFDTid+ehgUOpHV0LfjncXy4AiA3GNicF7aKPzdpa9PCpmaYQs3pHd+qbvvhXdxOCKCAMAFIMEUCIQD/ELXg6CNYyUQijCg96JtgvgjZb9dsl1Ctof4QAeyTcQIgVM/1AAblFl/DCt6A1gJg+T/i2qU5SQD09+chFJzolRwBSDBFAiEAlqRfSFyWNVQhvaCnmeV5tyneiCWMTcFbuujoD/pFa3wCIGnZjfQb8NolSYq9asV+ZeBSkCGHJcqnaV4JYS5MYPEGAWlTIQJ1aLEfEi/4p7wcV+XHZCBVvGGJZ7L3v+jhH+mZA8lN0yECCovfec+kIdllXpKCgA8RX/HZ2x5yHOtCSKP8/sf6pnwhAwxSng6kCgCXXSAmJOOZFdr3vdK3HzGqCFloOHgc5fM6U64=";
        assert!(matches!(
            bridge.verify_simple_signature(
                p2wsh_address,
                "This is not the message that was signed",
                p2wsh_signature
            ),
            Err(ConclaveError::Unsupported(_))
        ));

        let mut script_path = Witness::default();
        script_path.push([0x51]);
        script_path.push(taproot_control_block(0xc1));
        let encoded = encode_witness(&script_path);
        assert!(matches!(
            bridge.verify_simple_signature(P2TR_ADDRESS, "message", &encoded),
            Err(ConclaveError::Unsupported(_))
        ));
    }

    #[test]
    fn test_bip322_taproot_annexes_are_explicitly_unsupported() {
        let bridge = Bip322Bridge;

        let mut key_path = Witness::default();
        key_path.push([0u8; 64]);
        key_path.push([0x50, 0x01]);
        assert!(matches!(
            bridge.verify_simple_signature(P2TR_ADDRESS, "message", &encode_witness(&key_path),),
            Err(ConclaveError::Unsupported(_))
        ));

        let mut script_path = Witness::default();
        script_path.push([0x01]);
        script_path.push([0x51]);
        script_path.push(taproot_control_block(0xc1));
        script_path.push([0x50, 0x01]);
        assert!(matches!(
            bridge.verify_simple_signature(P2TR_ADDRESS, "message", &encode_witness(&script_path),),
            Err(ConclaveError::Unsupported(_))
        ));
    }

    #[test]
    fn test_bip322_canonical_to_spend_and_to_sign_vectors() {
        let address = P2WPKH_ADDRESS
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .expect("test vector address")
            .assume_checked();
        let message = "Hello World";
        let to_spend = Bip322Bridge::construct_to_spend_tx(address.script_pubkey(), message)
            .expect("to_spend construction");
        let to_sign =
            Bip322Bridge::construct_to_sign_tx(&to_spend, message).expect("to_sign construction");

        assert_eq!(
            Bip322Bridge::message_hash(message),
            bytes32("f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a")
        );
        assert_eq!(to_spend.version.to_u32(), 0);
        assert_eq!(to_spend.lock_time, absolute::LockTime::ZERO);
        assert_eq!(to_spend.inputs[0].sequence, Sequence::ZERO);
        assert_eq!(to_spend.inputs[0].previous_output.vout, u32::MAX);
        assert_eq!(to_spend.inputs[0].script_sig.as_bytes()[0], 0x00);
        assert_eq!(to_spend.inputs[0].script_sig.as_bytes()[1], 0x20);
        assert_eq!(
            &to_spend.inputs[0].script_sig.as_bytes()[2..],
            &Bip322Bridge::message_hash(message)
        );
        assert!(to_spend.inputs[0].witness.is_empty());
        assert_eq!(to_spend.outputs[0].amount, Amount::ZERO);

        assert_eq!(to_sign.version.to_u32(), 0);
        assert_eq!(
            to_sign.inputs[0].previous_output.txid,
            to_spend.compute_txid()
        );
        assert_eq!(to_sign.inputs[0].sequence, Sequence::ZERO);
        assert!(to_sign.inputs[0].script_sig.is_empty());
        assert!(to_sign.inputs[0].witness.is_empty());
        assert_eq!(to_sign.outputs[0].amount, Amount::ZERO);
        assert_eq!(to_sign.outputs[0].script_pubkey.as_bytes(), &[0x6a]);

        assert_eq!(
            to_spend.compute_txid().to_string(),
            "b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b"
        );
        assert_eq!(
            to_sign.compute_txid().to_string(),
            "88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf"
        );
    }

    #[test]
    fn test_bip322_to_sign_rejects_message_mismatch_and_noncanonical_shape() {
        let address = P2WPKH_ADDRESS
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .expect("test vector address")
            .assume_checked();
        let to_spend = Bip322Bridge::construct_to_spend_tx(address.script_pubkey(), "hello")
            .expect("to_spend construction");

        assert!(matches!(
            Bip322Bridge::construct_to_sign_tx(&to_spend, "wrong message"),
            Err(ConclaveError::InvalidPayload)
        ));

        let mut malformed = to_spend.clone();
        malformed.inputs[0].sequence = Sequence::MAX;
        assert!(matches!(
            Bip322Bridge::construct_to_sign_tx(&malformed, "hello"),
            Err(ConclaveError::InvalidPayload)
        ));

        let mut mismatched_hash = to_spend.clone();
        let mut script_sig = mismatched_hash.inputs[0].script_sig.as_bytes().to_vec();
        script_sig[2] ^= 1;
        mismatched_hash.inputs[0].script_sig = ScriptSigBuf::from_bytes(script_sig);
        assert!(matches!(
            Bip322Bridge::construct_to_sign_tx(&mismatched_hash, "hello"),
            Err(ConclaveError::InvalidPayload)
        ));
    }

    #[test]
    fn test_bip322_messages_are_not_limited_by_legacy_payload_boundary() {
        let bridge = Bip322Bridge;
        for length in [230usize, 231, 4096] {
            let message = "x".repeat(length);
            assert!(matches!(
                bridge.verify_simple_signature(P2WPKH_ADDRESS, &message, P2WPKH_HELLO_SIGNATURE,),
                Ok(false)
            ));
        }
    }

    #[test]
    #[cfg(feature = "bip110_compliant")]
    fn test_bip322_bip110_validates_virtual_transaction_contexts() {
        let oversized_script = ScriptPubKeyBuf::from_bytes(vec![0u8; 35]);
        assert!(Bip322Bridge::construct_to_spend_tx(oversized_script, "hello").is_err());

        let future_witness = ScriptPubKeyBuf::from_bytes({
            let mut script = vec![0x52, 0x14];
            script.extend_from_slice(&[0u8; 20]);
            script
        });
        let future_to_spend = Bip322Bridge::construct_to_spend_tx(future_witness, "hello")
            .expect("future witness-version outputs are creatable");
        assert!(matches!(
            Bip322Bridge::construct_to_sign_tx(&future_to_spend, "hello"),
            Err(ConclaveError::Unsupported(_))
        ));

        let script_pubkey = ScriptPubKeyBuf::new_p2wpkh(WPubkeyHash::from_byte_array([0u8; 20]));
        let to_spend = Bip322Bridge::construct_to_spend_tx(script_pubkey, "hello").unwrap();
        let mut witness = Witness::default();
        witness.push(vec![0u8; 257]);
        assert!(Bip322Bridge::construct_to_sign_tx_with_witness_and_message(
            &to_spend, "hello", witness,
        )
        .is_err());
    }

    #[test]
    #[cfg(feature = "bip110_compliant")]
    fn test_bip322_bip110_rejects_p2a_spend_construction() {
        let p2a_script = ScriptPubKeyBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73]);
        let to_spend = Bip322Bridge::construct_to_spend_tx(p2a_script, "message")
            .expect("generic P2A output creation remains supported");

        assert!(matches!(
            Bip322Bridge::construct_to_sign_tx(&to_spend, "message"),
            Err(ConclaveError::Unsupported(message)) if message.contains("P2A")
        ));
    }

    #[test]
    #[cfg(feature = "bip110_compliant")]
    fn test_bip322_bip110_rejects_p2pkh_p2sh_and_custom_scripts() {
        let mut p2pkh_script = vec![0x76, 0xa9, 0x14];
        p2pkh_script.extend_from_slice(&[0u8; 20]);
        p2pkh_script.extend_from_slice(&[0x88, 0xac]);

        let mut p2sh_script = vec![0xa9, 0x14];
        p2sh_script.extend_from_slice(&[0u8; 20]);
        p2sh_script.push(0x87);

        for (script_type, script_bytes) in [
            ("P2PKH", p2pkh_script),
            ("P2SH", p2sh_script),
            ("custom", vec![0x51]),
        ] {
            let to_spend = Bip322Bridge::construct_to_spend_tx(
                ScriptPubKeyBuf::from_bytes(script_bytes),
                "message",
            )
            .expect("unsupported script output creation remains structurally valid");
            let mut witness = Witness::default();
            witness.push([0u8; 64]);

            assert!(
                matches!(
                    Bip322Bridge::construct_to_sign_tx_with_witness_and_message(
                        &to_spend, "message", witness,
                    ),
                    Err(ConclaveError::Unsupported(_))
                ),
                "{script_type} must be rejected in BIP-110 mode"
            );
        }
    }

    #[test]
    #[cfg(feature = "bip110_compliant")]
    fn test_bip322_bip110_rejects_taproot_annexes_during_spend_construction() {
        let address = P2TR_ADDRESS
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .expect("test vector address")
            .assume_checked();
        let to_spend = Bip322Bridge::construct_to_spend_tx(address.script_pubkey(), "message")
            .expect("to_spend construction");

        let mut key_path = Witness::default();
        key_path.push([0u8; 64]);
        key_path.push([0x50, 0x01]);
        assert!(matches!(
            Bip322Bridge::construct_to_sign_tx_with_witness_and_message(
                &to_spend, "message", key_path,
            ),
            Err(ConclaveError::Unsupported(_))
        ));

        let mut script_path = Witness::default();
        script_path.push([0x01]);
        script_path.push([0x51]);
        script_path.push(taproot_control_block(0xc1));
        script_path.push([0x50, 0x01]);
        assert!(matches!(
            Bip322Bridge::construct_to_sign_tx_with_witness_and_message(
                &to_spend,
                "message",
                script_path,
            ),
            Err(ConclaveError::Unsupported(_))
        ));
    }

    #[test]
    #[cfg(feature = "bip110_compliant")]
    fn test_bip322_bip110_rejects_future_tapleaf_version() {
        let address = P2TR_ADDRESS
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .expect("test vector address")
            .assume_checked();
        let to_spend = Bip322Bridge::construct_to_spend_tx(address.script_pubkey(), "message")
            .expect("to_spend construction");

        let mut script_path = Witness::default();
        script_path.push([0x51]);
        script_path.push(taproot_control_block(0xd1));
        assert!(matches!(
            Bip322Bridge::construct_to_sign_tx_with_witness_and_message(
                &to_spend,
                "message",
                script_path,
            ),
            Err(ConclaveError::Unsupported(_))
        ));
    }
}
