use crate::{
    ConclaveError, ConclaveResult,
    enclave::{EnclaveManager, SignRequest, SigningAlgorithm},
};
use bitcoin::XOnlyPublicKey;
use bitcoin::hashes::{HashEngine, sha256t};
use bitcoin::taproot::TapLeafHash;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub struct TaprootManager<'a> {
    enclave: &'a dyn EnclaveManager,
}

impl<'a> TaprootManager<'a> {
    pub fn new(enclave: &'a dyn EnclaveManager) -> Self {
        Self { enclave }
    }

    pub fn sign_taproot_v1(
        &self,
        sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
        merkle_root: Option<[u8; 32]>,
    ) -> ConclaveResult<String> {
        if !derivation_path.contains("86'") {
            return Err(ConclaveError::CryptoError(
                "Taproot requires m/86' derivation path".to_string(),
            ));
        }

        let tweak = self.calculate_taproot_tweak(derivation_path, merkle_root)?;

        let request = SignRequest {
            algorithm: SigningAlgorithm::SchnorrSecp256k1,
            message_hash: sighash.to_vec(),
            derivation_path: derivation_path.to_string(),
            key_id: key_id.to_string(),
            taproot_tweak: Some(tweak),
        };

        let response = self.enclave.sign(request)?;
        Ok(response.signature_hex)
    }

    fn calculate_taproot_tweak(
        &self,
        derivation_path: &str,
        merkle_root: Option<[u8; 32]>,
    ) -> ConclaveResult<Vec<u8>> {
        let pubkey_hex = self.enclave.get_public_key(derivation_path)?;
        let internal_pubkey_bytes =
            hex::decode(pubkey_hex).map_err(|_| ConclaveError::InvalidPayload)?;

        let internal_pubkey = XOnlyPublicKey::from_byte_array(
            internal_pubkey_bytes[..32]
                .try_into()
                .map_err(|_| ConclaveError::InvalidPayload)?,
        )
        .map_err(|e| ConclaveError::CryptoError(format!("Invalid internal pubkey: {}", e)))?;

        let tweak_hash = if let Some(root) = merkle_root {
            let mut engine = sha256t::Hash::<TapTweakTag>::engine();
            engine.input(&internal_pubkey.serialize().0);
            engine.input(&root);
            sha256t::Hash::<TapTweakTag>::from_engine(engine)
        } else {
            let mut engine = sha256t::Hash::<TapTweakTag>::engine();
            engine.input(&internal_pubkey.serialize().0);
            sha256t::Hash::<TapTweakTag>::from_engine(engine)
        };

        Ok(tweak_hash.to_byte_array().to_vec())
    }

    pub fn sign_taproot_sighash(
        &self,
        sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        self.sign_taproot_v1(sighash, derivation_path, key_id, None)
    }

    pub fn sign_tapscript_leaf(
        &self,
        leaf_hash: TapLeafHash,
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        self.sign_taproot_sighash(leaf_hash.to_byte_array(), derivation_path, key_id)
    }

    pub fn sign_bitvm_challenge(
        &self,
        challenge_hash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        self.sign_taproot_sighash(challenge_hash, derivation_path, key_id)
    }
}

pub struct TapTweakTag;
impl sha256t::Tag for TapTweakTag {
    const MIDSTATE: bitcoin::hashes::sha256::Midstate = bitcoin::hashes::sha256::Midstate::new(
        [
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
            0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
            0x90, 0xab, 0xcd, 0xef,
        ],
        0,
    );
}

pub struct BitcoinManager {
    enclave: Arc<dyn EnclaveManager>,
}

impl BitcoinManager {
    pub fn new(enclave: Arc<dyn EnclaveManager>) -> Self {
        Self { enclave }
    }

    pub fn generate_wpkh_descriptor(&self, derivation_path: &str) -> ConclaveResult<String> {
        let pubkey_hex = self.enclave.get_public_key(derivation_path)?;
        Ok(format!("wpkh({})", pubkey_hex))
    }

    pub fn generate_tr_descriptor(&self, derivation_path: &str) -> ConclaveResult<String> {
        let pubkey_hex = self.enclave.get_public_key(derivation_path)?;
        Ok(format!("tr({})", pubkey_hex))
    }

    pub fn taproot(&self) -> TaprootManager<'_> {
        TaprootManager::new(self.enclave.as_ref())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionState {
    Unconfirmed,
    Confirmed { height: u32, timestamp: u64 },
    Reorged,
    Dead,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FeeBumpStrategy {
    None,
    RBF,
    CPFP,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolPolicy {
    pub min_relay_fee: u64,
    pub target_blocks: u32,
    pub fee_bump_strategy: FeeBumpStrategy,
}

impl MempoolPolicy {
    pub fn default_sovereign() -> Self {
        Self {
            min_relay_fee: 1000,
            target_blocks: 3,
            fee_bump_strategy: FeeBumpStrategy::RBF,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinTransactionIntent {
    pub txid: String,
    pub raw_tx: Vec<u8>,
    pub state: TransactionState,
    pub policy: MempoolPolicy,
}

impl BitcoinTransactionIntent {
    pub fn new(txid: String, raw_tx: Vec<u8>, policy: MempoolPolicy) -> Self {
        Self {
            txid,
            raw_tx,
            state: TransactionState::Unconfirmed,
            policy,
        }
    }

    pub fn update_state(&mut self, next_state: TransactionState) {
        self.state = next_state;
    }
}

/// Helpers for constructing OP_CAT (BIP-347) recursive covenants.
pub struct OpCatHelper;

impl OpCatHelper {
    /// Constructs a script fragment for an OP_CAT-based covenant check.
    /// This is used to verify that the spending transaction matches certain constraints.
    pub fn build_recursive_covenant_script(
        pubkey: &XOnlyPublicKey,
        constraints_hash: [u8; 32],
    ) -> Vec<u8> {
        let mut script = Vec::new();
        // 1. Push constraints hash
        script.push(0x20); // OP_PUSHBYTES_32
        script.extend_from_slice(&constraints_hash);

        // 2. OP_CAT with some stack element (e.g. part of sighash)
        script.push(0x7e); // OP_CAT

        // 3. Verify against pubkey
        script.push(0x20); // OP_PUSHBYTES_32
        script.extend_from_slice(&pubkey.serialize().0);
        script.push(0xac); // OP_CHECKSIG

        script
    }

    /// Generates a SIGHASH_EXTERNAL equivalent using OP_CAT.
    pub fn build_sighash_external_script(taproot_internal_key: &XOnlyPublicKey) -> Vec<u8> {
        let mut script = Vec::new();
        // Simplified OP_CAT sighash construction
        script.push(0x7e); // OP_CAT
        script.push(0x7e); // OP_CAT
        script.push(0x20);
        script.extend_from_slice(&taproot_internal_key.serialize().0);
        script.push(0xba); // OP_CHECKSIGVERIFY (v1)
        script
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pubkey() -> XOnlyPublicKey {
        XOnlyPublicKey::from_byte_array(&[1u8; 32]).unwrap()
    }

    #[test]
    fn test_op_cat_covenant_script_generation() {
        let pubkey = dummy_pubkey();
        let hash = [2u8; 32];
        let script = OpCatHelper::build_recursive_covenant_script(&pubkey, hash);

        assert!(script.contains(&0x7e)); // OP_CAT
        assert!(script.contains(&0xac)); // OP_CHECKSIG
    }

    #[test]
    fn test_sighash_external_generation() {
        let pubkey = dummy_pubkey();
        let script = OpCatHelper::build_sighash_external_script(&pubkey);
        assert_eq!(script[0], 0x7e);
    }
}
