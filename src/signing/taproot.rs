//! Taproot utility functions (SDK-008).
//!
//! Extracted common BIP-341/BIP-342 taproot helpers used across signing
//! operations. These are pure functions with no enclave dependency.
//!
//! # SDK-008
//! See `docs/PHASE1_ISSUES_ROADMAP.md` for acceptance criteria.

use bitcoin::key::XOnlyPublicKey;
use bitcoin::taproot::{TapLeafHash, TapNodeHash, TapTweakHash};
use secp256k1::Scalar;

use crate::{ConclaveError, ConclaveResult};

/// Compute the BIP-341 taproot tweak from an internal key and optional
/// merkle root (script tree).
pub fn compute_taproot_tweak(
    internal_key: &XOnlyPublicKey,
    merkle_root: Option<[u8; 32]>,
) -> [u8; 32] {
    let merkle_root = merkle_root.map(TapNodeHash::from_byte_array);
    TapTweakHash::from_key_and_merkle_root(*internal_key, merkle_root).to_byte_array()
}

/// Compute the taproot output key (Q = P + t*G) by tweaking the internal
/// public key.
pub fn taproot_output_key(
    internal_key: &XOnlyPublicKey,
    merkle_root: Option<[u8; 32]>,
) -> ConclaveResult<XOnlyPublicKey> {
    let tweak_bytes = compute_taproot_tweak(internal_key, merkle_root);
    let tweak = Scalar::from_be_bytes(tweak_bytes)
        .map_err(|_| ConclaveError::CryptoError("invalid taproot tweak scalar".into()))?;
    internal_key
        .add_tweak(&tweak)
        .map_err(|_| ConclaveError::CryptoError("taproot output key derivation failed".into()))
}

/// Compute a tapleaf hash from a script.
pub fn tapleaf_hash(script: &[u8]) -> TapLeafHash {
    TapLeafHash::from_byte_array(bitcoin::hashes::sha256::Hash::hash(script).to_byte_array())
}

/// Validate a BIP-86 derivation path (no script path, single key spend).
pub fn is_bip86_path(path: &str) -> bool {
    path.starts_with("m/86'")
}

/// Validate a BIP-44 legacy derivation path.
pub fn is_bip44_path(path: &str) -> bool {
    path.starts_with("m/44'")
}

/// Validate a BIP-84 native segwit derivation path.
pub fn is_bip84_path(path: &str) -> bool {
    path.starts_with("m/84'")
}

/// Classify a derivation path into its BIP standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BipStandard {
    /// BIP-44: Legacy
    Bip44,
    /// BIP-84: Native SegWit (P2WPKH)
    Bip84,
    /// BIP-86: Taproot (P2TR)
    Bip86,
    /// Unknown or custom path
    Unknown,
}

/// Classify a derivation path by its BIP purpose field.
pub fn classify_derivation_path(path: &str) -> BipStandard {
    if is_bip86_path(path) {
        BipStandard::Bip86
    } else if is_bip84_path(path) {
        BipStandard::Bip84
    } else if is_bip44_path(path) {
        BipStandard::Bip44
    } else {
        BipStandard::Unknown
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn compute_taproot_tweak_default_merkle_root() {
        // Valid x-only public key (already on curve, even y)
        let key = XOnlyPublicKey::from_str(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let tweak = compute_taproot_tweak(&key, None);
        assert_eq!(tweak.len(), 32);
    }

    #[test]
    fn taproot_output_key_no_script_path() {
        let key = XOnlyPublicKey::from_str(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let output_key = taproot_output_key(&key, None).expect("taproot tweak must succeed");
        // Output key should differ from internal key after tweaking
        assert_ne!(output_key, key);
    }

    #[test]
    fn classify_bip86_path() {
        assert_eq!(
            classify_derivation_path("m/86'/0'/0'/0/0"),
            BipStandard::Bip86
        );
    }

    #[test]
    fn classify_bip84_path() {
        assert_eq!(
            classify_derivation_path("m/84'/0'/0'/0/0"),
            BipStandard::Bip84
        );
    }

    #[test]
    fn classify_bip44_path() {
        assert_eq!(
            classify_derivation_path("m/44'/0'/0'/0/0"),
            BipStandard::Bip44
        );
    }

    #[test]
    fn classify_unknown_path() {
        assert_eq!(
            classify_derivation_path("m/123'/0'/0'/0/0"),
            BipStandard::Unknown
        );
    }

    #[test]
    fn tapleaf_hash_of_empty_script() {
        let hash = tapleaf_hash(&[]);
        assert_eq!(hash.as_byte_array().len(), 32);
    }
}
