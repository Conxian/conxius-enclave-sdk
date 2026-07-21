use crate::{
    enclave::{
        sign_value_bearing, EnclaveManager, OperationContext, SignerKeyBinding, SigningAlgorithm,
        TrustRequirement, ValueBearingPurpose, ValueBearingSignRequest, VALUE_BEARING_POLICY_ID,
    },
    ConclaveError, ConclaveResult,
};
use bitcoin::{
    key::PublicKey,
    secp256k1::Scalar,
    taproot::{TapLeafHash, TapNodeHash, TapTweakHash},
    XOnlyPublicKey,
};
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
        self.sign_taproot_operation(
            sighash,
            derivation_path,
            key_id,
            merkle_root,
            ValueBearingPurpose::Transaction,
            "conxian/bitcoin/taproot",
        )
    }

    fn sign_taproot_operation(
        &self,
        sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
        merkle_root: Option<[u8; 32]>,
        purpose: ValueBearingPurpose,
        domain: &str,
    ) -> ConclaveResult<String> {
        Self::validate_bip86_path(derivation_path)?;

        let tweak = self.calculate_taproot_tweak(derivation_path, merkle_root)?;
        let tweak_scalar = Self::tweak_scalar(&tweak)?;
        let internal_key = self.internal_key(derivation_path)?;
        let operation_pubkey = internal_key.add_tweak(&tweak_scalar).map_err(|error| {
            ConclaveError::CryptoError(format!("Taproot key tweak failed: {error}"))
        })?;
        let request = ValueBearingSignRequest::new(
            OperationContext::new(domain, purpose, sighash.to_vec())?,
            SigningAlgorithm::SchnorrSecp256k1,
            TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID)?,
            sighash,
            SignerKeyBinding::new(
                key_id,
                derivation_path,
                operation_pubkey.serialize().0.to_vec(),
            )?,
            Some(tweak.to_vec()),
        )?;

        let response = sign_value_bearing(self.enclave, request)?;
        Ok(response.sign_response().signature_hex.clone())
    }

    /// Derives the BIP-341 Taproot output key from the enclave's internal key.
    ///
    /// The internal key may be returned as an x-only key or as a compressed or
    /// uncompressed SEC1 public key. Full public keys are converted to their
    /// canonical x-only representation before the tagged tweak is applied.
    pub fn derive_taproot_output_key(
        &self,
        derivation_path: &str,
        merkle_root: Option<[u8; 32]>,
    ) -> ConclaveResult<XOnlyPublicKey> {
        Self::validate_bip86_path(derivation_path)?;
        let internal_key = self.internal_key(derivation_path)?;
        let tweak_hash = Self::taproot_tweak_hash(internal_key, merkle_root);
        let tweak = Self::tweak_scalar(&tweak_hash.to_byte_array())?;

        internal_key
            .add_tweak(&tweak)
            .map_err(|error| ConclaveError::CryptoError(format!("Taproot tweak failed: {error}")))
    }

    fn calculate_taproot_tweak(
        &self,
        derivation_path: &str,
        merkle_root: Option<[u8; 32]>,
    ) -> ConclaveResult<[u8; 32]> {
        Self::validate_bip86_path(derivation_path)?;
        let internal_key = self.internal_key(derivation_path)?;
        Ok(Self::taproot_tweak_hash(internal_key, merkle_root).to_byte_array())
    }

    fn internal_key(&self, derivation_path: &str) -> ConclaveResult<XOnlyPublicKey> {
        let pubkey_hex = self.enclave.get_public_key(derivation_path)?;
        let public_key_bytes =
            hex::decode(pubkey_hex).map_err(|_| ConclaveError::InvalidPayload)?;

        match public_key_bytes.len() {
            32 => {
                let key_bytes: [u8; 32] = public_key_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| ConclaveError::InvalidPayload)?;
                XOnlyPublicKey::from_byte_array(&key_bytes).map_err(|error| {
                    ConclaveError::CryptoError(format!("Invalid internal x-only pubkey: {error}"))
                })
            }
            33 | 65 => PublicKey::from_slice(&public_key_bytes)
                .map(XOnlyPublicKey::from)
                .map_err(|error| {
                    ConclaveError::CryptoError(format!("Invalid internal pubkey: {error}"))
                }),
            _ => Err(ConclaveError::InvalidPayload),
        }
    }

    fn taproot_tweak_hash(
        internal_key: XOnlyPublicKey,
        merkle_root: Option<[u8; 32]>,
    ) -> TapTweakHash {
        TapTweakHash::from_key_and_merkle_root(
            internal_key,
            merkle_root.map(TapNodeHash::from_byte_array),
        )
    }

    fn tweak_scalar(tweak_bytes: &[u8; 32]) -> ConclaveResult<Scalar> {
        Scalar::from_be_bytes(*tweak_bytes).map_err(|error| {
            ConclaveError::CryptoError(format!(
                "Taproot tweak is outside the scalar range: {error}"
            ))
        })
    }

    fn validate_bip86_path(derivation_path: &str) -> ConclaveResult<()> {
        let components: Vec<&str> = derivation_path.split('/').collect();
        if components.len() != 6 || components[0] != "m" || components[1] != "86'" {
            return Err(ConclaveError::CryptoError(
                "Taproot requires a canonical BIP-86 path m/86'/coin_type'/account'/change/index"
                    .to_string(),
            ));
        }

        let coin_type = Self::parse_hardened_path_component(components[2], "coin type")?;
        let _account = Self::parse_hardened_path_component(components[3], "account")?;
        let _change = Self::parse_unhardened_path_component(components[4], "change")?;
        let _index = Self::parse_unhardened_path_component(components[5], "index")?;

        if coin_type != 0 && coin_type != 1 {
            return Err(ConclaveError::CryptoError(
                "Taproot BIP-86 supports only Bitcoin mainnet (coin type 0) or testnet (coin type 1)"
                    .to_string(),
            ));
        }

        Ok(())
    }

    fn parse_hardened_path_component(component: &str, name: &str) -> ConclaveResult<u32> {
        let digits = component
            .strip_suffix('\'')
            .ok_or_else(|| ConclaveError::CryptoError(format!("BIP-86 {name} must be hardened")))?;
        let value = Self::parse_path_number(digits, name)?;
        if value > 0x7fff_ffff {
            return Err(ConclaveError::CryptoError(format!(
                "BIP-86 {name} is outside the hardened index range"
            )));
        }
        Ok(value)
    }

    fn parse_unhardened_path_component(component: &str, name: &str) -> ConclaveResult<u32> {
        if component.ends_with('\'') {
            return Err(ConclaveError::CryptoError(format!(
                "BIP-86 {name} must be unhardened"
            )));
        }
        let value = Self::parse_path_number(component, name)?;
        if value > 0x7fff_ffff {
            return Err(ConclaveError::CryptoError(format!(
                "BIP-86 {name} is outside the unhardened index range"
            )));
        }
        Ok(value)
    }

    fn parse_path_number(digits: &str, name: &str) -> ConclaveResult<u32> {
        if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
            return Err(ConclaveError::CryptoError(format!(
                "BIP-86 {name} must be a canonical decimal index"
            )));
        }
        digits.parse::<u32>().map_err(|_| {
            ConclaveError::CryptoError(format!("BIP-86 {name} must be a decimal index"))
        })
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
        self.sign_taproot_operation(
            challenge_hash,
            derivation_path,
            key_id,
            None,
            ValueBearingPurpose::Authorization,
            "conxian/bitcoin/bitvm-challenge",
        )
    }
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
    use crate::enclave::{SignRequest, SignResponse};

    struct TestEnclave {
        public_key_hex: String,
    }

    impl EnclaveManager for TestEnclave {
        fn initialize(&self) -> ConclaveResult<()> {
            Ok(())
        }

        fn generate_key(&self, _key_id: &str) -> ConclaveResult<String> {
            Err(ConclaveError::Unsupported(
                "test enclave does not generate keys".to_string(),
            ))
        }

        fn get_public_key(&self, _derivation_path: &str) -> ConclaveResult<String> {
            Ok(self.public_key_hex.clone())
        }

        fn sign(&self, _request: SignRequest) -> ConclaveResult<SignResponse> {
            Err(ConclaveError::Unsupported(
                "test enclave does not sign".to_string(),
            ))
        }
    }

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

    #[test]
    fn test_bip86_tap_tweak_matches_reference_vector() {
        let internal_key = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115";
        let enclave = TestEnclave {
            public_key_hex: internal_key.to_string(),
        };
        let manager = TaprootManager::new(&enclave);

        let tweak = manager
            .calculate_taproot_tweak("m/86'/0'/0'/0/0", None)
            .expect("BIP-86 tweak derivation");
        assert_eq!(
            hex::encode(tweak),
            "2ca01ed85cf6b6526f73d39a1111cd80333bfdc00ce98992859848a90a6f0258"
        );

        let output_key = manager
            .derive_taproot_output_key("m/86'/0'/0'/0/0", None)
            .expect("BIP-86 output key derivation");
        let address = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .expect("BIP-86 reference address")
            .assume_checked();
        assert_eq!(
            &address.script_pubkey().as_bytes()[2..],
            &output_key.serialize().0
        );
    }

    #[test]
    fn test_taproot_rejects_noncanonical_paths_and_keys() {
        let enclave = TestEnclave {
            public_key_hex: "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
                .to_string(),
        };
        let manager = TaprootManager::new(&enclave);

        assert!(manager
            .calculate_taproot_tweak("m/186'/0'/0'/0/0", None)
            .is_err());
        assert!(manager
            .calculate_taproot_tweak("m/86'/2'/0'/0/0", None)
            .is_err());

        let malformed_enclave = TestEnclave {
            public_key_hex: "00".to_string(),
        };
        let malformed_manager = TaprootManager::new(&malformed_enclave);
        assert!(malformed_manager
            .calculate_taproot_tweak("m/86'/0'/0'/0/0", None)
            .is_err());
    }
}
