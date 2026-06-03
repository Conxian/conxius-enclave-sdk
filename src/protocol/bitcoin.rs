use crate::{
    ConclaveError, ConclaveResult,
    enclave::{EnclaveManager, SignRequest, SigningAlgorithm},
};
use bitcoin::XOnlyPublicKey;
use bitcoin::hashes::{HashEngine, sha256t};
use bitcoin::taproot::TapLeafHash;
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
