use crate::{
    enclave::{
        sign_value_bearing, EnclaveManager, OperationContext, SignerKeyBinding, SigningAlgorithm,
        TrustRequirement, ValueBearingPurpose, ValueBearingSignRequest, VALUE_BEARING_POLICY_ID,
    },
    ConclaveError, ConclaveResult,
};
use bitcoin::{
    key::PublicKey,
    secp256k1::{self, Scalar},
    taproot::{TapLeafHash, TapNodeHash, TapTweakHash},
    XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Verify a BIP-340 Schnorr signature over a pre-hashed message digest.
///
/// This boundary intentionally accepts byte slices so callers cannot silently
/// truncate or pad malformed inputs. BIP-340 verification returns `Ok(false)`
/// for a well-encoded but invalid signature; malformed lengths or public-key
/// encodings return typed errors instead.
pub fn verify_bip340_signature(
    message_digest: &[u8],
    x_only_public_key: &[u8],
    signature: &[u8],
) -> ConclaveResult<bool> {
    let message: [u8; 32] = message_digest
        .try_into()
        .map_err(|_| ConclaveError::InvalidPayload)?;
    let public_key_bytes: [u8; 32] = x_only_public_key
        .try_into()
        .map_err(|_| ConclaveError::InvalidPayload)?;
    let signature_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| ConclaveError::InvalidPayload)?;

    let public_key =
        secp256k1::XOnlyPublicKey::from_byte_array(public_key_bytes).map_err(|error| {
            ConclaveError::CryptoError(format!("Invalid BIP-340 x-only public key: {error}"))
        })?;
    let signature = secp256k1::schnorr::Signature::from_byte_array(signature_bytes);

    Ok(secp256k1::schnorr::verify(&signature, &message, &public_key).is_ok())
}

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

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        hex::decode(value)
            .expect("test vector hex")
            .try_into()
            .expect("test vector length")
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
        // Source: BIP-0086 reference wallet vector.
        // https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
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
    fn test_bip341_tap_tweak_matches_wallet_vector_with_merkle_root() {
        // Source: official BIP-0341 wallet test vectors.
        // https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json
        let enclave = TestEnclave {
            public_key_hex: "93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820"
                .to_string(),
        };
        let manager = TaprootManager::new(&enclave);
        let merkle_root = Some(decode_hex::<32>(
            "c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b",
        ));

        let tweak = manager
            .calculate_taproot_tweak("m/86'/0'/0'/0/0", merkle_root)
            .expect("BIP-341 tweak derivation");
        assert_eq!(
            hex::encode(tweak),
            "6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30"
        );

        let output_key = manager
            .derive_taproot_output_key("m/86'/0'/0'/0/0", merkle_root)
            .expect("BIP-341 output key derivation");
        assert_eq!(
            hex::encode(output_key.serialize().0),
            "e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e"
        );
    }

    #[test]
    fn test_bip340_verification_matches_official_valid_vector() {
        // Source: official BIP-0340 test vector 0.
        // https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
        let message = [0u8; 32];
        let public_key =
            decode_hex::<32>("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
        let signature = decode_hex::<64>(concat!(
            "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215",
            "25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
        ));

        assert_eq!(
            verify_bip340_signature(&message, &public_key, &signature),
            Ok(true)
        );
    }

    #[test]
    fn test_bip340_verification_rejects_official_invalid_vectors() {
        // Source: official BIP-0340 test vectors 7, 12, and 13.
        // https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
        let message =
            decode_hex::<32>("243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89");
        let public_key =
            decode_hex::<32>("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659");

        let wrong_message_signature = decode_hex::<64>(concat!(
            "1fa62e331edbc21c394792d2ab1100a7b432b013df3f6ff4f99fcb33e0e1515f",
            "28890b3edb6e7189b630448b515ce4f8622a954cfe545735aaea5134fccdb2bd"
        ));
        assert_eq!(
            verify_bip340_signature(&message, &public_key, &wrong_message_signature),
            Ok(false)
        );

        let r_equal_field_size = decode_hex::<64>(concat!(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            "69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b"
        ));
        assert_eq!(
            verify_bip340_signature(&message, &public_key, &r_equal_field_size),
            Ok(false)
        );

        let s_equal_curve_order = decode_hex::<64>(concat!(
            "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        ));
        assert_eq!(
            verify_bip340_signature(&message, &public_key, &s_equal_curve_order),
            Ok(false)
        );

        let valid_signature = decode_hex::<64>(concat!(
            "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215",
            "25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
        ));
        let wrong_key =
            decode_hex::<32>("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659");
        assert_eq!(
            verify_bip340_signature(&[0u8; 32], &wrong_key, &valid_signature),
            Ok(false)
        );
    }

    #[test]
    fn test_bip340_verification_rejects_malformed_lengths_and_keys() {
        let message = [0u8; 32];
        let public_key =
            decode_hex::<32>("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
        let signature = decode_hex::<64>(concat!(
            "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215",
            "25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
        ));

        assert!(matches!(
            verify_bip340_signature(&message[..31], &public_key, &signature),
            Err(ConclaveError::InvalidPayload)
        ));
        assert!(matches!(
            verify_bip340_signature(&message, &public_key[..31], &signature),
            Err(ConclaveError::InvalidPayload)
        ));
        assert!(matches!(
            verify_bip340_signature(&message, &public_key, &signature[..63]),
            Err(ConclaveError::InvalidPayload)
        ));

        assert!(matches!(
            verify_bip340_signature(&message, &[0xff; 32], &signature),
            Err(ConclaveError::CryptoError(_))
        ));
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
