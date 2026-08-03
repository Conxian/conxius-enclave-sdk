//! FROST cryptographic execution backend.
//!
//! This module provides real threshold signing operations backed by the
//! Zcash Foundation FROST library (`frost-secp256k1-tr` v3.0.0, RFC 9591).
//! It is gated behind the `frost-crypto` feature flag.
//!
//! Follows the same pattern as [`super::musig2`]: imports the external
//! crypto crate directly and wraps operations in ConclaveResult.
//!
//! ## Safety note (Session 52.5.4)
//!
//! This implementation is **beta-quality**. Enclave-SDK issues #195–#202
//! remain open. Do not enable value-bearing production signing without
//! completing the attestation qualification gates.

use std::collections::BTreeMap;

use frost_core::{
    self as frost,
    keys::{self, PublicKeyPackage, SecretShare, SigningShare},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Ciphersuite, Identifier, SigningPackage,
};
use frost_secp256k1_tr::Secp256K1Sha256TR;
use rand_core::OsRng;

use crate::{ConclaveError, ConclaveResult};

type E = Secp256K1Sha256TR;

// ── Core FROST operations ────────────────────────────────────────────

/// Generate a t-of-n FROST key using a trusted dealer.
///
/// Returns a map of participant identifier → secret share, plus the
/// public key package. Each share is a serialized [`SecretShare`].
pub fn trusted_dealer_keygen(
    min_signers: u16,
    max_signers: u16,
) -> ConclaveResult<(BTreeMap<Vec<u8>, Vec<u8>>, Vec<u8>)> {
    let mut rng = OsRng;

    let (shares_map, pubkey_package): (
        BTreeMap<Identifier<E>, SecretShare<E>>,
        PublicKeyPackage<E>,
    ) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .map_err(|e| ConclaveError::CryptoError(format!("FROST keygen failed: {e:?}")))?;

    let verifying_key = pubkey_package.verifying_key().serialize();

    let shares: BTreeMap<Vec<u8>, Vec<u8>> = shares_map
        .into_iter()
        .map(|(id, share)| {
            let id_bytes: u16 = id.try_into().unwrap_or(0);
            (id_bytes.to_be_bytes().to_vec(), share.serialize())
        })
        .collect();

    Ok((shares, verifying_key))
}

/// Create signing nonces and commitments for a FROST signing round.
///
/// Returns `(nonces_bytes, commitments_bytes)` where:
/// - `nonces_bytes` — serialized [`SigningNonces`] (keep secret)
/// - `commitments_bytes` — serialized [`SigningCommitments`] (broadcast)
pub fn create_nonces_and_commitments(
    secret_share_bytes: &[u8],
) -> ConclaveResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = OsRng;

    let signing_share = SigningShare::<E>::deserialize(secret_share_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("FROST share deser: {e:?}")))?;

    let (nonces, commitments) = frost::round1::commit(&signing_share, &mut rng);

    let nonces_bytes = nonces
        .serialize()
        .map_err(|e| ConclaveError::CryptoError(format!("FROST nonce ser: {e:?}")))?;

    let commitments_bytes = commitments
        .serialize()
        .map_err(|e| ConclaveError::CryptoError(format!("FROST commitment ser: {e:?}")))?;

    Ok((nonces_bytes, commitments_bytes))
}

/// Produce a partial signature share for a FROST signing session.
pub fn produce_signature_share(
    secret_share_bytes: &[u8],
    nonces_bytes: &[u8],
    signing_package_bytes: &[u8],
) -> ConclaveResult<Vec<u8>> {
    let key_package = keys::KeyPackage::<E>::deserialize(secret_share_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("FROST keypkg deser: {e:?}")))?;

    let signer_nonces = SigningNonces::<E>::deserialize(nonces_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("FROST nonce deser: {e:?}")))?;

    let signing_package = SigningPackage::<E>::deserialize(signing_package_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("FROST sigpkg deser: {e:?}")))?;

    let sig_share = frost::round2::sign(&signing_package, &signer_nonces, &key_package)
        .map_err(|e| ConclaveError::CryptoError(format!("FROST sign failed: {e:?}")))?;

    Ok(sig_share.serialize())
}

/// Aggregate t-of-n partial signature shares into a single Schnorr signature.
///
/// Takes:
/// - `share_map`: participant_id_bytes → signature_share_bytes
/// - `commitment_map`: participant_id_bytes → commitment_bytes
/// - `message`: the message that was signed
/// - `pubkey_package_bytes`: serialized [`PublicKeyPackage`]
///
/// Returns the hex-encoded aggregated Schnorr signature.
pub fn aggregate(
    share_map: &BTreeMap<Vec<u8>, Vec<u8>>,
    commitment_map: &BTreeMap<Vec<u8>, Vec<u8>>,
    message: &[u8],
    pubkey_package_bytes: &[u8],
) -> ConclaveResult<String> {
    let pubkey_package = PublicKeyPackage::<E>::deserialize(pubkey_package_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("FROST pubkey deser: {e:?}")))?;

    let mut signing_commitments: BTreeMap<Identifier<E>, SigningCommitments<E>> = BTreeMap::new();
    let mut signature_shares: BTreeMap<Identifier<E>, SignatureShare<E>> = BTreeMap::new();

    for (id_bytes, commitment_bytes) in commitment_map {
        let id = identifier_from_bytes(id_bytes)?;
        let commitment = SigningCommitments::<E>::deserialize(commitment_bytes)
            .map_err(|e| ConclaveError::CryptoError(format!("FROST commitment deser: {e:?}")))?;
        signing_commitments.insert(id, commitment);
    }

    for (id_bytes, share_bytes) in share_map {
        let id = identifier_from_bytes(id_bytes)?;
        let share = SignatureShare::<E>::deserialize(share_bytes)
            .map_err(|e| ConclaveError::CryptoError(format!("FROST share deser: {e:?}")))?;
        signature_shares.insert(id, share);
    }

    let signing_package = SigningPackage::new(signing_commitments, message);

    let signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)
        .map_err(|e| ConclaveError::CryptoError(format!("FROST aggregate failed: {e:?}")))?;

    Ok(hex::encode(signature.serialize()))
}

// ── Helpers ──────────────────────────────────────────────────────────

fn identifier_from_bytes(bytes: &[u8]) -> ConclaveResult<Identifier<E>> {
    let raw = if bytes.len() >= 2 {
        u16::from_be_bytes([bytes[0], bytes[1]])
    } else {
        bytes.iter().fold(0u16, |acc, &b| (acc << 8) | b as u16)
    };
    if raw == 0 {
        raw.checked_add(1).ok_or_else(|| {
            ConclaveError::CryptoError("FROST identifier 0 invalid".into())
        })?;
    }
    Identifier::<E>::try_from(raw).map_err(|_| {
        ConclaveError::CryptoError(format!("FROST identifier {raw} out of range"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trusted_dealer_keygen_2_of_3() {
        let result = trusted_dealer_keygen(2, 3);
        assert!(result.is_ok());
        let (shares, vk) = result.unwrap();
        assert_eq!(shares.len(), 3);
        assert!(!vk.is_empty());
    }

    #[test]
    fn test_nonces_and_commitments() {
        let (shares, _vk) = trusted_dealer_keygen(2, 2).unwrap();
        let (_id, share_bytes) = shares.first_key_value().unwrap();
        let result = create_nonces_and_commitments(share_bytes);
        assert!(result.is_ok());
        let (nonces, commitments) = result.unwrap();
        assert!(!nonces.is_empty());
        assert!(!commitments.is_empty());
    }
}

