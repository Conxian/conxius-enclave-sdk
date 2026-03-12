use crate::{ConclaveResult, ConclaveError, enclave::{SignRequest, EnclaveManager}};
use bitcoin::hashes::{Hash, sha256t, HashEngine};
use bitcoin::taproot::TapLeafHash;
use bitcoin::XOnlyPublicKey;

/// Native Bitcoin Taproot (BIP341) Manager.
/// Superior implementation handling Tweak logic natively within the Conclave ethos.
pub struct TaprootManager<'a> {
    enclave: &'a dyn EnclaveManager,
}

impl<'a> TaprootManager<'a> {
    pub fn new(enclave: &'a dyn EnclaveManager) -> Self {
        Self { enclave }
    }

    /// Sign a Taproot sighash, applying the necessary BIP341 tweak.
    /// Internal Key is derived from the enclave, and the tweak is calculated
    /// based on the Merkle root of the script tree (if any).
    pub fn sign_taproot_v1(
        &self,
        sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
        merkle_root: Option<[u8; 32]>,
    ) -> ConclaveResult<String> {
        if !derivation_path.contains("86'") {
            return Err(ConclaveError::CryptoError("Taproot requires m/86' derivation path".to_string()));
        }

        let tweak = self.calculate_taproot_tweak(derivation_path, merkle_root)?;

        let request = SignRequest {
            message_hash: sighash.to_vec(),
            derivation_path: derivation_path.to_string(),
            key_id: key_id.to_string(),
            taproot_tweak: Some(tweak),
        };

        let response = self.enclave.sign(request)?;
        Ok(response.signature_hex)
    }

    /// Calculates the BIP341 tweak: hash_TapTweak(internal_key || merkle_root)
    fn calculate_taproot_tweak(
        &self,
        derivation_path: &str,
        merkle_root: Option<[u8; 32]>,
    ) -> ConclaveResult<Vec<u8>> {
        let pubkey_hex = self.enclave.get_public_key(derivation_path)?;
        let internal_pubkey_bytes = hex::decode(pubkey_hex).map_err(|_| ConclaveError::InvalidPayload)?;

        let internal_pubkey = XOnlyPublicKey::from_slice(&internal_pubkey_bytes[..32])
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid internal pubkey: {}", e)))?;

        let tweak_hash = if let Some(root) = merkle_root {
            let mut engine = sha256t::Hash::<TapTweakTag>::engine();
            engine.input(&internal_pubkey.serialize());
            engine.input(&root);
            sha256t::Hash::<TapTweakTag>::from_engine(engine)
        } else {
            let mut engine = sha256t::Hash::<TapTweakTag>::engine();
            engine.input(&internal_pubkey.serialize());
            sha256t::Hash::<TapTweakTag>::from_engine(engine)
        };

        Ok(tweak_hash.to_byte_array().to_vec())
    }

    /// Prepares and signs a Taproot (BIP341) Schnorr signature.
    pub fn sign_taproot_sighash(
        &self,
        sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        self.sign_taproot_v1(sighash, derivation_path, key_id, None)
    }

    /// Decoupled Taproot leaf signing for script path spending.
    pub fn sign_tapscript_leaf(
        &self,
        leaf_hash: TapLeafHash,
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        self.sign_taproot_sighash(leaf_hash.to_byte_array(), derivation_path, key_id)
    }
}

pub struct TapTweakTag;
impl sha256t::Tag for TapTweakTag {
    fn engine() -> bitcoin::hashes::sha256::HashEngine {
        let mut engine = bitcoin::hashes::sha256::Hash::engine();
        engine.input(b"TapTweak");
        engine
    }
}
