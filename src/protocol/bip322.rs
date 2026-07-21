use crate::{ConclaveError, ConclaveResult};
use base64::prelude::*;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::sha256;
use bitcoin::psbt::Psbt;
use bitcoin::script::{ScriptBufExt, ScriptExt, ScriptPubKeyBuf, ScriptPubKeyExt, ScriptSigBuf};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    absolute, ecdsa, key::CompressedPublicKey, secp256k1, taproot, transaction, Address, Amount,
    OutPoint, Sequence, TapScript, Transaction, TxIn, TxOut, Txid, Witness,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

const BIP322_MESSAGE_TAG: &[u8] = b"BIP0322-signed-message";
const TAPROOT_CONTROL_BLOCK_MIN_BYTES: usize = 33;
const TAPROOT_CONTROL_BLOCK_MAX_BYTES: usize = 257;

/// BIP-322 Universal Message Signing Bridge.
///
/// Simple verification is intentionally limited to native P2WPKH and Taproot
/// key-path witnesses. P2WSH and Taproot script-path witnesses are structurally
/// checked where possible and returned as typed inconclusive outcomes because
/// this crate does not contain a Bitcoin Script interpreter. Legacy, P2SH,
/// P2A, and future witness-version addresses remain conditional boundaries.
/// Full and Proof-of-Funds payloads are decoded only far enough to reject
/// malformed wire data; their required transaction/PSBT finalization and
/// consensus/script validation are outside this module's scope and therefore
/// return typed unsupported-format errors instead of `Inconclusive`.
/// The construction helpers are structural transaction builders and do not
/// expand the verification support boundary.
pub struct Bip322Bridge;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bip322Signature {
    pub address: String,
    pub message_hash: [u8; 32],
    pub signature_base64: String,
}

/// Result of the supported BIP-322 verification boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Bip322Verification {
    /// The supported script and cryptographic checks succeeded.
    Valid,
    /// The supported script and cryptographic checks completed and failed.
    Invalid,
    /// The input is structurally valid, but this module cannot execute its
    /// supported script form.
    Inconclusive {
        /// The exact unsupported boundary reached by verification.
        reason: Bip322InconclusiveReason,
    },
}

impl fmt::Display for Bip322Verification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => formatter.write_str("valid"),
            Self::Invalid => formatter.write_str("invalid"),
            Self::Inconclusive { reason } => write!(formatter, "inconclusive: {reason}"),
        }
    }
}

/// A precise reason why BIP-322 verification stopped without a valid/invalid result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum Bip322InconclusiveReason {
    #[error("P2WSH script execution is unavailable")]
    P2wshScriptExecution,
    #[error("Taproot script-path execution is unavailable")]
    TaprootScriptPathExecution,
    #[error("Taproot annex execution is unavailable")]
    TaprootAnnex,
    #[error("legacy address verification is unavailable")]
    LegacyAddress,
    #[error("P2SH address verification is unavailable")]
    P2shAddress,
    #[error("P2A verification is unavailable")]
    P2a,
    #[error("future witness-version verification is unavailable")]
    FutureWitnessVersion,
    #[error("future Taproot leaf-version execution is unavailable")]
    FutureTaprootLeafVersion,
    #[error("the Bitcoin script is not supported by this verification boundary")]
    UnsupportedScript,
}

/// Typed errors raised before a BIP-322 verification outcome can be produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum Bip322Error {
    #[error("the address is not valid for the expected Bitcoin network")]
    NetworkMismatch,
    #[error("Full BIP-322 verification is unsupported by this module")]
    UnsupportedFullFormat,
    #[error("Proof-of-Funds BIP-322 verification is unsupported by this module")]
    UnsupportedProofOfFundsFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimpleChallenge {
    P2wpkh,
    P2wsh,
    P2tr,
    Legacy,
    P2sh,
    P2a,
    FutureWitness,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureVariant {
    Simple,
    Full,
    ProofOfFunds,
}

#[derive(Debug)]
enum DecodedSignature {
    Simple(Witness),
    Full,
    ProofOfFunds,
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
        let tx = Self::construct_to_spend_tx_unchecked(script_pubkey, message)?;

        #[cfg(feature = "bip110_compliant")]
        Self::validate_bip110_to_spend_output(&tx)?;

        Ok(tx)
    }

    fn construct_to_spend_tx_unchecked(
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
        Ok(tx)
    }

    /// Constructs a virtual `to_sign` transaction for BIP-322 verification.
    ///
    /// The supplied message is checked against the canonical message hash in
    /// `to_spend`; it is not ignored. Construction support does not imply that
    /// this module can execute the challenge script during verification.
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
        Self::construct_to_sign_tx_for_construction(to_spend, witness)
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
        Self::construct_to_sign_tx_for_construction(to_spend, witness)
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

        Ok(tx)
    }

    fn construct_to_sign_tx_for_construction(
        to_spend: &Transaction,
        witness: Witness,
    ) -> ConclaveResult<Transaction> {
        let tx = Self::construct_to_sign_tx_unchecked(to_spend, witness)?;

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

        if !matches!(
            Self::challenge_type(script_pubkey),
            SimpleChallenge::P2wpkh | SimpleChallenge::P2wsh | SimpleChallenge::P2tr
        ) {
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
            if witness.len() >= 2
                && witness
                    .last()
                    .is_some_and(|item| item.first() == Some(&0x50))
            {
                return Err(ConclaveError::Unsupported(
                    "Taproot annex spends are unsupported in BIP-110 mode".to_string(),
                ));
            }
            let _ = Self::inspect_taproot_witness(witness, Some(validator))?;
        }

        Ok(())
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
            || !(control_block.len() - TAPROOT_CONTROL_BLOCK_MIN_BYTES).is_multiple_of(32)
        {
            return Err(ConclaveError::InvalidPayload);
        }
        Ok(())
    }

    fn validate_taproot_script_path_commitment(
        script_pubkey: &ScriptPubKeyBuf,
        witness: &Witness,
    ) -> ConclaveResult<Bip322InconclusiveReason> {
        let annex = witness.len() >= 2
            && witness
                .last()
                .is_some_and(|item| item.first() == Some(&0x50));
        let spend_len = witness.len() - usize::from(annex);
        if spend_len < 2 {
            return Err(ConclaveError::InvalidPayload);
        }

        let control_block_bytes = witness
            .get(spend_len - 1)
            .ok_or(ConclaveError::InvalidPayload)?;
        Self::validate_taproot_control_block_shape(control_block_bytes)?;
        let control_block = taproot::ControlBlock::decode(control_block_bytes)
            .map_err(|_| ConclaveError::InvalidPayload)?;

        let tapscript_bytes = witness
            .get(spend_len - 2)
            .ok_or(ConclaveError::InvalidPayload)?;
        Self::validate_serialized_script(tapscript_bytes)?;

        let output_key_bytes: [u8; 32] = script_pubkey
            .as_bytes()
            .get(2..)
            .ok_or(ConclaveError::InvalidPayload)?
            .try_into()
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let output_key = secp256k1::XOnlyPublicKey::from_byte_array(output_key_bytes)
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let tapscript = TapScript::from_bytes(tapscript_bytes);

        if !control_block.verify_taproot_commitment(output_key.into(), tapscript) {
            return Err(ConclaveError::InvalidPayload);
        }

        Ok(match control_block.leaf_version {
            taproot::LeafVersion::TapScript => Bip322InconclusiveReason::TaprootScriptPathExecution,
            taproot::LeafVersion::Future(_) => Bip322InconclusiveReason::FutureTaprootLeafVersion,
        })
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
            .instructions_minimal()
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

        let expected_hash = script_pubkey
            .as_bytes()
            .get(2..)
            .ok_or(ConclaveError::InvalidPayload)?;
        let actual_hash = sha256::Hash::hash(witness_script);
        if actual_hash.as_byte_array() != expected_hash {
            return Err(ConclaveError::InvalidPayload);
        }
        Ok(())
    }

    fn parse_signature_variant(signature_base64: &str) -> ConclaveResult<(SignatureVariant, &str)> {
        if let Some(encoded) = signature_base64.strip_prefix("smp") {
            return Ok((SignatureVariant::Simple, encoded));
        }
        if let Some(encoded) = signature_base64.strip_prefix("ful") {
            return Ok((SignatureVariant::Full, encoded));
        }
        if let Some(encoded) = signature_base64.strip_prefix("pof") {
            return Ok((SignatureVariant::ProofOfFunds, encoded));
        }

        // BIP-322 permits a verifier to assume the Simple variant when no
        // recognized variant tag is present. Leave the entire input for strict
        // Base64 and witness parsing; unknown textual prefixes are not tags.
        Ok((SignatureVariant::Simple, signature_base64))
    }

    fn decode_signature(signature_base64: &str) -> ConclaveResult<DecodedSignature> {
        let (variant, encoded) = Self::parse_signature_variant(signature_base64)?;
        let signature_bytes = BASE64_STANDARD
            .decode(encoded)
            .map_err(|_| ConclaveError::InvalidPayload)?;
        if signature_bytes.is_empty() {
            return Err(ConclaveError::InvalidPayload);
        }

        match variant {
            SignatureVariant::Simple => deserialize::<Witness>(&signature_bytes)
                .map(DecodedSignature::Simple)
                .map_err(|_| ConclaveError::InvalidPayload),
            // BIP-322 requires Full signatures to be finalized `to_sign`
            // transactions and Proof-of-Funds signatures to be finalized PSBTs
            // before basic validation and script execution. The rust-bitcoin
            // decoders establish only consensus/PSBT wire validity; this module
            // deliberately does not implement the remaining finalization,
            // consensus, UTXO, or script checks. Decode the bytes so malformed
            // payloads remain InvalidPayload, then classify every decoded Full
            // or Proof-of-Funds payload as a typed unsupported format.
            // References:
            // https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#verification
            // https://docs.rs/bitcoin/0.33.0-beta/bitcoin/psbt/struct.Psbt.html
            SignatureVariant::Full => deserialize::<Transaction>(&signature_bytes)
                .map(|_| DecodedSignature::Full)
                .map_err(|_| ConclaveError::InvalidPayload),
            SignatureVariant::ProofOfFunds => Psbt::deserialize(&signature_bytes)
                .map(|_| DecodedSignature::ProofOfFunds)
                .map_err(|_| ConclaveError::InvalidPayload),
        }
    }

    fn challenge_type(script_pubkey: &ScriptPubKeyBuf) -> SimpleChallenge {
        if script_pubkey.is_p2wpkh() {
            SimpleChallenge::P2wpkh
        } else if script_pubkey.is_p2wsh() {
            SimpleChallenge::P2wsh
        } else if script_pubkey.is_p2tr() {
            SimpleChallenge::P2tr
        } else if script_pubkey.is_p2pkh() {
            SimpleChallenge::Legacy
        } else if script_pubkey.is_p2sh() {
            SimpleChallenge::P2sh
        } else if script_pubkey.is_p2a() {
            SimpleChallenge::P2a
        } else if script_pubkey.is_witness_program() {
            SimpleChallenge::FutureWitness
        } else {
            SimpleChallenge::Unsupported
        }
    }

    fn challenge_inconclusive_reason(
        challenge: SimpleChallenge,
    ) -> Option<Bip322InconclusiveReason> {
        match challenge {
            SimpleChallenge::Legacy => Some(Bip322InconclusiveReason::LegacyAddress),
            SimpleChallenge::P2sh => Some(Bip322InconclusiveReason::P2shAddress),
            SimpleChallenge::P2a => Some(Bip322InconclusiveReason::P2a),
            SimpleChallenge::FutureWitness => Some(Bip322InconclusiveReason::FutureWitnessVersion),
            SimpleChallenge::Unsupported => Some(Bip322InconclusiveReason::UnsupportedScript),
            SimpleChallenge::P2wpkh | SimpleChallenge::P2wsh | SimpleChallenge::P2tr => None,
        }
    }

    fn unsupported_simple_signature(reason: Bip322InconclusiveReason) -> ConclaveError {
        ConclaveError::Unsupported(format!("BIP-322 verification inconclusive: {reason}"))
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
            return Err(ConclaveError::InvalidPayload);
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
            return Err(ConclaveError::InvalidPayload);
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

    fn parse_address(
        address_str: &str,
    ) -> ConclaveResult<Address<bitcoin::address::NetworkUnchecked>> {
        address_str
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|_| ConclaveError::InvalidPayload)
    }

    fn verify_simple_signature_with_address(
        &self,
        address: &Address,
        message: &str,
        signature_base64: &str,
    ) -> ConclaveResult<Bip322Verification> {
        let script_pubkey = address.script_pubkey();
        let challenge = Self::challenge_type(&script_pubkey);
        let to_spend = Self::construct_to_spend_tx_unchecked(script_pubkey, message)?;
        let decoded = Self::decode_signature(signature_base64)?;

        match decoded {
            DecodedSignature::Full => {
                Err(ConclaveError::Bip322(Bip322Error::UnsupportedFullFormat))
            }
            DecodedSignature::ProofOfFunds => Err(ConclaveError::Bip322(
                Bip322Error::UnsupportedProofOfFundsFormat,
            )),
            DecodedSignature::Simple(witness) => {
                if let Some(reason) = Self::challenge_inconclusive_reason(challenge) {
                    return Ok(Bip322Verification::Inconclusive { reason });
                }

                let to_sign = Self::construct_to_sign_tx_unchecked(&to_spend, witness.clone())?;

                match challenge {
                    SimpleChallenge::P2wpkh => {
                        Ok(if Self::verify_p2wpkh(&to_spend, &to_sign, &witness)? {
                            Bip322Verification::Valid
                        } else {
                            Bip322Verification::Invalid
                        })
                    }
                    SimpleChallenge::P2wsh => {
                        Self::validate_p2wsh_witness_structure(
                            &to_spend.outputs[0].script_pubkey,
                            &witness,
                        )?;
                        Ok(Bip322Verification::Inconclusive {
                            reason: Bip322InconclusiveReason::P2wshScriptExecution,
                        })
                    }
                    SimpleChallenge::P2tr => {
                        let witness_kind = Self::inspect_taproot_witness(&witness, None)?;
                        match witness_kind {
                            TaprootWitnessKind::KeyPath => {
                                Ok(if Self::verify_p2tr(&to_spend, &to_sign, &witness)? {
                                    Bip322Verification::Valid
                                } else {
                                    Bip322Verification::Invalid
                                })
                            }
                            TaprootWitnessKind::ScriptPath => {
                                let reason = Self::validate_taproot_script_path_commitment(
                                    &to_spend.outputs[0].script_pubkey,
                                    &witness,
                                )?;
                                Ok(Bip322Verification::Inconclusive { reason })
                            }
                            TaprootWitnessKind::Annex => {
                                let annex = witness.len() >= 2
                                    && witness
                                        .last()
                                        .is_some_and(|item| item.first() == Some(&0x50));
                                let spend_len = witness.len() - usize::from(annex);
                                if spend_len > 1 {
                                    Self::validate_taproot_script_path_commitment(
                                        &to_spend.outputs[0].script_pubkey,
                                        &witness,
                                    )?;
                                }
                                Ok(Bip322Verification::Inconclusive {
                                    reason: Bip322InconclusiveReason::TaprootAnnex,
                                })
                            }
                        }
                    }
                    SimpleChallenge::Legacy
                    | SimpleChallenge::P2sh
                    | SimpleChallenge::P2a
                    | SimpleChallenge::FutureWitness
                    | SimpleChallenge::Unsupported => {
                        let reason = Self::challenge_inconclusive_reason(challenge)
                            .ok_or(ConclaveError::InvalidPayload)?;
                        Ok(Bip322Verification::Inconclusive { reason })
                    }
                }
            }
        }
    }

    /// Verify a BIP-322 Simple signature under an explicit application network policy.
    ///
    /// The address is parsed as `NetworkUnchecked` and then checked with the
    /// bitcoin crate's canonical `require_network` API. Testnet, signet, and
    /// regtest matching follows the crate's address-encoding semantics: shared
    /// test-family encodings match where the encoding cannot distinguish them.
    ///
    /// Supported verification is limited to native P2WPKH and native P2TR
    /// key-path signatures. Construction support is not verification support.
    /// P2WSH, Taproot script-path/annex, legacy, P2SH, P2A, future witness
    /// versions remain explicit inconclusive boundaries. Full and
    /// Proof-of-Funds are decoded and rejected as typed unsupported formats.
    /// No Bitcoin Script/Tapscript interpreter is implemented here.
    pub fn verify_simple_signature_for_network(
        &self,
        message: &str,
        address_str: &str,
        signature_base64: &str,
        expected_network: bitcoin::Network,
    ) -> ConclaveResult<Bip322Verification> {
        let address = Self::parse_address(address_str)?
            .require_network(expected_network)
            .map_err(|_| ConclaveError::Bip322(Bip322Error::NetworkMismatch))?;
        self.verify_simple_signature_with_address(&address, message, signature_base64)
    }

    /// Verifies a BIP-322 Simple signature without enforcing an application network policy.
    ///
    /// This compatibility wrapper validates the address encoding, but it does
    /// not require a caller-selected `bitcoin::Network`. It maps `Valid` and
    /// `Invalid` to the historical boolean result and maps every structured
    /// `Inconclusive` result to the existing typed `ConclaveError::Unsupported`
    /// error so unsupported forms are never silently accepted.
    ///
    /// The supported cryptographic forms are native P2WPKH and native P2TR
    /// key-path signatures. An absent `smp` prefix remains accepted only under
    /// BIP-322's backward-compatibility rule for pre-finalization verifiers.
    pub fn verify_simple_signature(
        &self,
        address_str: &str,
        message: &str,
        signature_base64: &str,
    ) -> ConclaveResult<bool> {
        let address = Self::parse_address(address_str)?.assume_checked();
        match self.verify_simple_signature_with_address(&address, message, signature_base64)? {
            Bip322Verification::Valid => Ok(true),
            Bip322Verification::Invalid => Ok(false),
            Bip322Verification::Inconclusive { reason } => {
                Err(Self::unsupported_simple_signature(reason))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "bip110_compliant")]
    use bitcoin::key::WPubkeyHash;
    use bitcoin::{Network, TestnetVersion};

    // Official BIP-322 vectors:
    // https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki
    // https://github.com/bitcoin/bips/blob/master/bip-0322/basic-test-vectors.json
    // https://github.com/bitcoin/bips/blob/master/bip-0322/generated-test-vectors.json
    const P2WPKH_ADDRESS: &str = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";
    const P2WPKH_EMPTY_SIGNATURE: &str =
        "smpAkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";
    const P2WPKH_HELLO_SIGNATURE: &str =
        "smpAkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";
    const GENERATED_P2WPKH_WRONG_SIGNER_ADDRESS: &str =
        "bc1qgg6lpr05az2l5kz402ddz5ez7fdu25kgmd40lf";
    const GENERATED_P2WPKH_MESSAGE: &str = "2V6TUTMSH4VQ3Z7WZWKYD7DFNH";
    const GENERATED_P2WPKH_SIGNATURE: &str =
        "smpAkgwRQIhALC6hdfxNy1n45d7UXSskRBdfZW0Al259E1kDMpipdYkAiAJPfZqb+WurZuf1apU5xeE6Igui9dvt5tihQLDvxlY1AEhAqbnruyo677ktQjio7XOchO3w51Dh9AbRVngha5jtNfT";
    const P2TR_ADDRESS: &str = "bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler";
    const P2TR_NO_PREFIX_SIGNATURE: &str =
        "AUCJYOwOjxYAvatTAGYaVlNXBVyFuc4MwNQkOuK2tl8xhfKDONd0NjfYyNSYcRqeCp8hsAnCEPHAVEkO9h6vbQ/R";
    const GENERATED_P2TR_ADDRESS: &str =
        "bc1pcquvhrqv0q68t4m0hfq6tpn006qrskyc7yrqnp2uyrf2emg3wynsdjyk38";
    const GENERATED_P2TR_MESSAGE: &str = "PURVOQ544B6HUATVBJZN5EZJUU";
    const GENERATED_P2TR_SIGNATURE: &str =
        "smpAUB6B2Rbupzua8LTQIF06516wzl+cwKy1be8RgoiW0riyXdKwe6GTz/5Hnb37m67pJwIKCh+D5jDueG6KpvYpmu8";
    const P2WSH_ADDRESS: &str = "bc1qp0ahvfh83088w49k405szqgg4f3pptr7p2g06tdxfjcd40z4lh4q95lsz9";
    const P2WSH_MESSAGE: &str = "This will be a p2wsh 3-of-3 multisig BIP 322 signed message";
    const P2WSH_SIGNATURE: &str =
        "smpBQBHMEQCIFX9aaqPJWq2Ff2kpen5bFDTid+ehgUOpHV0LfjncXy4AiA3GNicF7aKPzdpa9PCpmaYQs3pHd+qbvvhXdxOCKCAMAFIMEUCIQD/ELXg6CNYyUQijCg96JtgvgjZb9dsl1Ctof4QAeyTcQIgVM/1AAblFl/DCt6A1gJg+T/i2qU5SQD09+chFJzolRwBSDBFAiEAlqRfSFyWNVQhvaCnmeV5tyneiCWMTcFbuujoD/pFa3wCIGnZjfQb8NolSYq9asV+ZeBSkCGHJcqnaV4JYS5MYPEGAWlTIQJ1aLEfEi/4p7wcV+XHZCBVvGGJZ7L3v+jhH+mZA8lN0yECCovfec+kIdllXpKCgA8RX/HZ2x5yHOtCSKP8/sf6pnwhAwxSng6kCgCXXSAmJOOZFdr3vdK3HzGqCFloOHgc5fM6U64=";
    const OFFICIAL_INCORRECT_FORMAT_SIGNATURE: &str =
        "fulAUDZwFXUp+adN+/UZj5dVrGAbB3zKs1Vcalz5fCF9srxS63eSWNGvH1NYbrBkPt1BJDUyWUz9zgUxfc63/QheT6M";

    fn bytes32(value: &str) -> [u8; 32] {
        hex::decode(value)
            .expect("test vector is valid hex")
            .try_into()
            .expect("test vector has 32 bytes")
    }

    fn network_variant_of_p2wpkh(network: Network) -> String {
        let address = P2WPKH_ADDRESS
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .expect("official P2WPKH address")
            .assume_checked();
        Address::from_script(&address.script_pubkey(), network)
            .expect("P2WPKH script is an address")
            .to_string()
    }

    fn decode_witness(signature: &str) -> Witness {
        let encoded = signature
            .strip_prefix("smp")
            .expect("official vector uses the Simple prefix");
        let bytes = BASE64_STANDARD
            .decode(encoded)
            .expect("official vector has valid base64");
        deserialize(&bytes).expect("official vector has a valid witness")
    }

    fn taproot_script_path_vector() -> (String, Witness) {
        let internal_key = secp256k1::XOnlyPublicKey::from_byte_array(bytes32(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ))
        .expect("test internal key");
        let tapscript = bitcoin::TapScriptBuf::from_bytes(vec![0x51]);
        let spend_info =
            taproot::TaprootSpendInfo::with_huffman_tree(internal_key, [(1u32, tapscript.clone())])
                .expect("test Taproot tree");
        let address = Address::p2tr_tweaked(spend_info.output_key(), Network::Bitcoin);
        let control_block = spend_info
            .control_block(&(tapscript.clone(), taproot::LeafVersion::TapScript))
            .expect("test control block");

        let mut witness = Witness::default();
        witness.push(tapscript.as_bytes());
        witness.push(control_block.serialize());
        (address.to_string(), witness)
    }

    #[cfg(feature = "bip110_compliant")]
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
        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    "Hello World",
                    P2WPKH_ADDRESS,
                    P2WPKH_HELLO_SIGNATURE,
                    Network::Bitcoin,
                )
                .expect("official P2WPKH vector"),
            Bip322Verification::Valid
        );
        assert!(bridge
            .verify_simple_signature(P2WPKH_ADDRESS, "Hello World", P2WPKH_HELLO_SIGNATURE)
            .expect("compatibility wrapper"));
    }

    #[test]
    fn test_bip322_official_p2tr_positive_vector_without_prefix() {
        let bridge = Bip322Bridge;
        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    "No prefix fallback",
                    P2TR_ADDRESS,
                    P2TR_NO_PREFIX_SIGNATURE,
                    Network::Bitcoin,
                )
                .expect("official P2TR vector"),
            Bip322Verification::Valid
        );
        assert!(bridge
            .verify_simple_signature(P2TR_ADDRESS, "No prefix fallback", P2TR_NO_PREFIX_SIGNATURE)
            .expect("compatibility wrapper"));
    }

    #[test]
    fn test_bip322_unprefixed_lowercase_base64_uses_simple_fallback() {
        let witness = Witness::from_slice(&vec![Vec::<u8>::new(); 104]);
        let encoded = BASE64_STANDARD.encode(bitcoin::consensus::encode::serialize(&witness));
        assert!(encoded
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_lowercase()));

        let decoded =
            Bip322Bridge::decode_signature(&encoded).expect("valid unprefixed witness encoding");
        assert!(matches!(
            decoded,
            DecodedSignature::Simple(ref decoded) if decoded.len() == witness.len()
        ));
    }

    #[test]
    fn test_bip322_official_generated_p2tr_positive_vector() {
        let bridge = Bip322Bridge;
        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    GENERATED_P2TR_MESSAGE,
                    GENERATED_P2TR_ADDRESS,
                    GENERATED_P2TR_SIGNATURE,
                    Network::Bitcoin,
                )
                .expect("generated official P2TR vector"),
            Bip322Verification::Valid
        );
        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    "PURVOQ544B6HUATVBJZN5EZJUU!",
                    GENERATED_P2TR_ADDRESS,
                    GENERATED_P2TR_SIGNATURE,
                    Network::Bitcoin,
                )
                .expect("wrong-message vector is structurally valid"),
            Bip322Verification::Invalid
        );
    }

    #[test]
    fn test_bip322_explicit_network_policy_uses_bitcoin_address_semantics() {
        let bridge = Bip322Bridge;
        let mainnet = P2WPKH_ADDRESS.to_string();
        let testnet = network_variant_of_p2wpkh(Network::Testnet(TestnetVersion::V3));
        let signet = network_variant_of_p2wpkh(Network::Signet);
        let regtest = network_variant_of_p2wpkh(Network::Regtest);

        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    "Hello World",
                    &mainnet,
                    P2WPKH_HELLO_SIGNATURE,
                    Network::Bitcoin,
                )
                .expect("mainnet address matches mainnet policy"),
            Bip322Verification::Valid
        );
        assert!(matches!(
            bridge.verify_simple_signature_for_network(
                "Hello World",
                &mainnet,
                P2WPKH_HELLO_SIGNATURE,
                Network::Testnet(TestnetVersion::V3),
            ),
            Err(ConclaveError::Bip322(Bip322Error::NetworkMismatch))
        ));

        for network in [
            Network::Testnet(TestnetVersion::V3),
            Network::Testnet(TestnetVersion::V4),
            Network::Signet,
        ] {
            assert_eq!(
                bridge
                    .verify_simple_signature_for_network(
                        "Hello World",
                        &testnet,
                        P2WPKH_HELLO_SIGNATURE,
                        network,
                    )
                    .expect("tb encoding is valid for the Bitcoin test family"),
                Bip322Verification::Valid
            );
        }
        assert!(matches!(
            bridge.verify_simple_signature_for_network(
                "Hello World",
                &testnet,
                P2WPKH_HELLO_SIGNATURE,
                Network::Regtest,
            ),
            Err(ConclaveError::Bip322(Bip322Error::NetworkMismatch))
        ));

        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    "Hello World",
                    &signet,
                    P2WPKH_HELLO_SIGNATURE,
                    Network::Signet,
                )
                .expect("tb encoding matches signet policy"),
            Bip322Verification::Valid
        );
        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    "Hello World",
                    &regtest,
                    P2WPKH_HELLO_SIGNATURE,
                    Network::Regtest,
                )
                .expect("bcrt encoding matches regtest policy"),
            Bip322Verification::Valid
        );
        assert!(matches!(
            bridge.verify_simple_signature_for_network(
                "Hello World",
                &regtest,
                P2WPKH_HELLO_SIGNATURE,
                Network::Signet,
            ),
            Err(ConclaveError::Bip322(Bip322Error::NetworkMismatch))
        ));

        assert!(bridge
            .verify_simple_signature(&testnet, "Hello World", P2WPKH_HELLO_SIGNATURE)
            .expect("compatibility wrapper is network agnostic"));
    }

    #[test]
    fn test_bip322_full_and_proof_of_funds_reject_incomplete_material() {
        let bridge = Bip322Bridge;
        let address = P2WPKH_ADDRESS
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .expect("official P2WPKH address")
            .assume_checked();
        let to_spend = Bip322Bridge::construct_to_spend_tx(address.script_pubkey(), "Hello World")
            .expect("to_spend construction");
        let to_sign = Bip322Bridge::construct_to_sign_tx(&to_spend, "Hello World")
            .expect("canonical empty to_sign shape");

        let full_signature = format!(
            "ful{}",
            BASE64_STANDARD.encode(bitcoin::consensus::encode::serialize(&to_sign))
        );
        assert!(matches!(
            bridge.verify_simple_signature_for_network(
                "Hello World",
                P2WPKH_ADDRESS,
                &full_signature,
                Network::Bitcoin,
            ),
            Err(ConclaveError::Bip322(Bip322Error::UnsupportedFullFormat))
        ));
        assert!(matches!(
            bridge.verify_simple_signature(P2WPKH_ADDRESS, "Hello World", &full_signature),
            Err(ConclaveError::Bip322(Bip322Error::UnsupportedFullFormat))
        ));

        assert!(matches!(
            bridge.verify_simple_signature_for_network(
                "Hello World",
                P2WPKH_ADDRESS,
                "fulnot-base64",
                Network::Bitcoin,
            ),
            Err(ConclaveError::InvalidPayload)
        ));
        let invalid_transaction = format!("ful{}", BASE64_STANDARD.encode([0x01_u8, 0x02, 0x03]));
        assert!(matches!(
            bridge.verify_simple_signature_for_network(
                "Hello World",
                P2WPKH_ADDRESS,
                &invalid_transaction,
                Network::Bitcoin,
            ),
            Err(ConclaveError::InvalidPayload)
        ));

        let proof = Psbt::from_unsigned_tx(to_sign).expect("canonical Proof-of-Funds shape");
        let proof_signature = format!("pof{}", BASE64_STANDARD.encode(proof.serialize()));
        assert!(matches!(
            bridge.verify_simple_signature_for_network(
                "Hello World",
                P2WPKH_ADDRESS,
                &proof_signature,
                Network::Bitcoin,
            ),
            Err(ConclaveError::Bip322(
                Bip322Error::UnsupportedProofOfFundsFormat
            ))
        ));

        assert!(matches!(
            bridge.verify_simple_signature_for_network(
                "Hello World",
                P2WPKH_ADDRESS,
                "pofnot-base64",
                Network::Bitcoin,
            ),
            Err(ConclaveError::InvalidPayload)
        ));
        let invalid_psbt = format!("pof{}", BASE64_STANDARD.encode(b"not a psbt"));
        assert!(matches!(
            bridge.verify_simple_signature_for_network(
                "Hello World",
                P2WPKH_ADDRESS,
                &invalid_psbt,
                Network::Bitcoin,
            ),
            Err(ConclaveError::InvalidPayload)
        ));
    }

    #[test]
    fn test_bip322_malformed_inputs_do_not_panic() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let bridge = Bip322Bridge;
        let mut signatures = vec![
            String::new(),
            "!".to_string(),
            "smp".to_string(),
            "smp!".to_string(),
            "smpAA==".to_string(),
            "fooAA==".to_string(),
            "fulAUDV0w==".to_string(),
        ];

        for raw in [&[0xfd][..], &[0x02, 0x00][..], &[0x01, 0x02, 0x51][..]] {
            signatures.push(format!("smp{}", BASE64_STANDARD.encode(raw)));
        }

        let malformed_witnesses = [
            Witness::default(),
            Witness::from_slice(&[Vec::<u8>::new()]),
            Witness::from_slice(&[vec![0u8; 1], vec![0u8; 1]]),
            Witness::from_slice(&[vec![0u8; 70], vec![0u8; 33]]),
            Witness::from_slice(&[vec![0u8; 64]]),
            Witness::from_slice(&[vec![0u8; 65]]),
            Witness::from_slice(&[vec![0x51], vec![0u8; 32]]),
            Witness::from_slice(&[vec![0x51], vec![0u8; 33]]),
        ];
        for witness in &malformed_witnesses {
            signatures.push(encode_witness(witness));
        }

        let original_ecdsa = decode_witness(P2WPKH_HELLO_SIGNATURE);
        let original_signature = original_ecdsa
            .get(0)
            .expect("official ECDSA signature")
            .to_vec();
        let original_public_key = original_ecdsa
            .get(1)
            .expect("official compressed public key")
            .to_vec();

        let mut malformed_der = original_signature.clone();
        malformed_der[0] ^= 0xff;
        signatures.push(encode_witness(&Witness::from_slice(&[
            malformed_der,
            original_public_key.clone(),
        ])));

        let mut malformed_sighash = original_signature;
        let last = malformed_sighash
            .last_mut()
            .ok_or(())
            .expect("official ECDSA signature is non-empty");
        *last = 0x02;
        signatures.push(encode_witness(&Witness::from_slice(&[
            malformed_sighash,
            original_public_key.clone(),
        ])));

        let mut malformed_public_key = original_public_key.clone();
        malformed_public_key[0] = 0x04;
        signatures.push(encode_witness(&Witness::from_slice(&[
            decode_witness(P2WPKH_HELLO_SIGNATURE)
                .get(0)
                .expect("official ECDSA signature")
                .to_vec(),
            malformed_public_key,
        ])));

        let original_schnorr = decode_witness(GENERATED_P2TR_SIGNATURE);
        let original_schnorr_signature = original_schnorr
            .get(0)
            .expect("official Schnorr signature")
            .to_vec();
        let mut malformed_schnorr = original_schnorr_signature.clone();
        malformed_schnorr[0] ^= 0xff;
        signatures.push(encode_witness(&Witness::from_slice(&[malformed_schnorr])));

        let mut malformed_taproot_sighash = original_schnorr_signature;
        malformed_taproot_sighash.push(0x02);
        signatures.push(encode_witness(&Witness::from_slice(&[
            malformed_taproot_sighash,
        ])));

        let addresses = [
            P2WPKH_ADDRESS,
            P2TR_ADDRESS,
            GENERATED_P2TR_ADDRESS,
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            "",
            "bc1q",
            "not-an-address",
        ];

        for address in addresses {
            for signature in &signatures {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    bridge.verify_simple_signature_for_network(
                        "mutation coverage",
                        address,
                        signature,
                        Network::Bitcoin,
                    )
                }));
                assert!(result.is_ok(), "verification panicked for {address:?}");
            }
        }
    }

    #[test]
    fn test_bip322_official_negative_vectors() {
        let bridge = Bip322Bridge;
        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    "Wrong message that was not signed",
                    P2WPKH_ADDRESS,
                    P2WPKH_EMPTY_SIGNATURE,
                    Network::Bitcoin,
                )
                .expect("wrong-message vector is structurally valid"),
            Bip322Verification::Invalid
        );

        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    GENERATED_P2WPKH_MESSAGE,
                    GENERATED_P2WPKH_WRONG_SIGNER_ADDRESS,
                    GENERATED_P2WPKH_SIGNATURE,
                    Network::Bitcoin,
                )
                .expect("wrong-address vector is structurally valid"),
            Bip322Verification::Invalid
        );

        assert!(matches!(
            bridge.verify_simple_signature_for_network("", P2WPKH_ADDRESS, "", Network::Bitcoin,),
            Err(ConclaveError::InvalidPayload)
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

        // Unknown textual prefixes are treated as unprefixed Simple data and
        // must still fail through strict Base64/witness validation.
        assert!(matches!(
            bridge.verify_simple_signature(P2WPKH_ADDRESS, "", "fooAA=="),
            Err(ConclaveError::InvalidPayload)
        ));
        assert!(matches!(
            bridge.verify_simple_signature(P2WPKH_ADDRESS, "", "allAA=="),
            Err(ConclaveError::InvalidPayload)
        ));
        assert!(matches!(
            bridge.verify_simple_signature(
                P2TR_ADDRESS,
                "incorrect prefix",
                OFFICIAL_INCORRECT_FORMAT_SIGNATURE,
            ),
            Err(ConclaveError::InvalidPayload)
        ));
    }

    #[test]
    fn test_bip322_unsupported_address_types_fail_closed() {
        let bridge = Bip322Bridge;
        let signature = P2WPKH_HELLO_SIGNATURE;
        assert!(matches!(
            bridge.verify_simple_signature(
                "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                "hello",
                signature,
            ),
            Err(ConclaveError::Unsupported(_))
        ));
        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    "hello",
                    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                    signature,
                    Network::Bitcoin,
                )
                .expect("legacy boundary is structurally valid"),
            Bip322Verification::Inconclusive {
                reason: Bip322InconclusiveReason::LegacyAddress
            }
        );
        assert!(matches!(
            bridge.verify_simple_signature(
                "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
                "hello",
                signature,
            ),
            Err(ConclaveError::Unsupported(_))
        ));
        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    "hello",
                    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
                    signature,
                    Network::Bitcoin,
                )
                .expect("P2SH boundary is structurally valid"),
            Bip322Verification::Inconclusive {
                reason: Bip322InconclusiveReason::P2shAddress
            }
        );
    }

    #[test]
    fn test_bip322_p2a_and_future_witness_boundaries_are_typed() {
        let bridge = Bip322Bridge;
        let p2a_address = Address::p2a(Network::Bitcoin).to_string();
        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    "Hello World",
                    &p2a_address,
                    P2WPKH_HELLO_SIGNATURE,
                    Network::Bitcoin,
                )
                .expect("P2A address is structurally valid"),
            Bip322Verification::Inconclusive {
                reason: Bip322InconclusiveReason::P2a
            }
        );

        let future_script = ScriptPubKeyBuf::from_bytes({
            let mut script = vec![0x52, 0x14];
            script.extend_from_slice(&[0u8; 20]);
            script
        });
        let future_address = Address::from_script(&future_script, Network::Bitcoin)
            .expect("future witness program is an address")
            .to_string();
        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    "Hello World",
                    &future_address,
                    P2WPKH_HELLO_SIGNATURE,
                    Network::Bitcoin,
                )
                .expect("future witness address is structurally valid"),
            Bip322Verification::Inconclusive {
                reason: Bip322InconclusiveReason::FutureWitnessVersion
            }
        );

        let custom_script = ScriptPubKeyBuf::from_bytes(vec![0x51]);
        assert_eq!(
            Bip322Bridge::challenge_inconclusive_reason(Bip322Bridge::challenge_type(
                &custom_script,
            )),
            Some(Bip322InconclusiveReason::UnsupportedScript)
        );
    }

    #[test]
    fn test_bip322_p2wsh_and_taproot_script_path_are_unsupported() {
        let bridge = Bip322Bridge;
        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    P2WSH_MESSAGE,
                    P2WSH_ADDRESS,
                    P2WSH_SIGNATURE,
                    Network::Bitcoin,
                )
                .expect("official P2WSH vector is structurally valid"),
            Bip322Verification::Inconclusive {
                reason: Bip322InconclusiveReason::P2wshScriptExecution
            }
        );
        assert!(matches!(
            bridge.verify_simple_signature(P2WSH_ADDRESS, P2WSH_MESSAGE, P2WSH_SIGNATURE),
            Err(ConclaveError::Unsupported(_))
        ));

        let (script_path_address, script_path) = taproot_script_path_vector();
        let encoded = encode_witness(&script_path);
        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    "message",
                    &script_path_address,
                    &encoded,
                    Network::Bitcoin,
                )
                .expect("constructed Taproot script path is structurally valid"),
            Bip322Verification::Inconclusive {
                reason: Bip322InconclusiveReason::TaprootScriptPathExecution
            }
        );
        assert!(matches!(
            bridge.verify_simple_signature(&script_path_address, "message", &encoded),
            Err(ConclaveError::Unsupported(_))
        ));

        let original_witness = decode_witness(P2WSH_SIGNATURE);
        let script_index = original_witness.len() - 1;
        let mut malformed_script = original_witness
            .get(script_index)
            .expect("official P2WSH witness script")
            .to_vec();
        malformed_script[0] ^= 1;
        let mut malformed_witness = Witness::default();
        for item in original_witness.iter().take(script_index) {
            malformed_witness.push(item);
        }
        malformed_witness.push(malformed_script);
        assert!(matches!(
            bridge.verify_simple_signature_for_network(
                P2WSH_MESSAGE,
                P2WSH_ADDRESS,
                &encode_witness(&malformed_witness),
                Network::Bitcoin,
            ),
            Err(ConclaveError::InvalidPayload)
        ));

        let control_index = script_path.len() - 1;
        let mut control_block = script_path
            .get(control_index)
            .expect("constructed control block")
            .to_vec();
        control_block[32] ^= 1;
        let mut malformed_control = Witness::default();
        for item in script_path.iter().take(control_index) {
            malformed_control.push(item);
        }
        malformed_control.push(control_block);
        assert!(matches!(
            bridge.verify_simple_signature_for_network(
                "message",
                &script_path_address,
                &encode_witness(&malformed_control),
                Network::Bitcoin,
            ),
            Err(ConclaveError::InvalidPayload)
        ));
    }

    #[test]
    fn test_bip322_taproot_annexes_are_explicitly_unsupported() {
        let bridge = Bip322Bridge;

        let mut key_path = Witness::default();
        key_path.push([0u8; 64]);
        key_path.push([0x50, 0x01]);
        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    "message",
                    P2TR_ADDRESS,
                    &encode_witness(&key_path),
                    Network::Bitcoin,
                )
                .expect("annex witness is structurally valid"),
            Bip322Verification::Inconclusive {
                reason: Bip322InconclusiveReason::TaprootAnnex
            }
        );
        assert!(matches!(
            bridge.verify_simple_signature(P2TR_ADDRESS, "message", &encode_witness(&key_path),),
            Err(ConclaveError::Unsupported(_))
        ));

        let (script_path_address, mut script_path) = taproot_script_path_vector();
        script_path.push([0x50, 0x01]);
        assert_eq!(
            bridge
                .verify_simple_signature_for_network(
                    "message",
                    &script_path_address,
                    &encode_witness(&script_path),
                    Network::Bitcoin,
                )
                .expect("script-path annex witness is structurally valid"),
            Bip322Verification::Inconclusive {
                reason: Bip322InconclusiveReason::TaprootAnnex
            }
        );
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
