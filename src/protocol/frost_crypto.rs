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

// ── DKG (Distributed Key Generation) ────────────────────────────────
//
// ZF FROST v3.0.0 includes a full Pedersen DKG implementation
// (frost-core/src/keys/dkg.rs). These wrappers expose the 3-part
// protocol: each participant runs part1, broadcasts the package,
// collects all round-1 packages, runs part2, sends encrypted shares
// to each peer, collects all round-2 packages, then runs part3 to
// compute the final KeyPackage + PublicKeyPackage.

use frost::keys::dkg;
use std::collections::BTreeMap as StdBTreeMap;

/// DKG Part 1: Generate secret polynomial + public commitment.
///
/// Returns `(secret_package_bytes, package_bytes)` where:
/// - `secret_package_bytes` — serialized [`dkg::round1::SecretPackage`] (keep private)
/// - `package_bytes` — serialized [`dkg::round1::Package`] (broadcast to all peers)
pub fn dkg_part1(
    participant_id_bytes: &[u8],
    max_signers: u16,
    min_signers: u16,
) -> ConclaveResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = OsRng;
    let id = identifier_from_bytes(participant_id_bytes)?;

    let (secret_package, package) =
        dkg::part1::<E, _>(id, max_signers, min_signers, &mut rng)
            .map_err(|e| ConclaveError::CryptoError(format!("FROST DKG part1: {e:?}")))?;

    let secret_bytes = secret_package
        .serialize()
        .map_err(|e| ConclaveError::CryptoError(format!("DKG secret ser: {e:?}")))?;

    let package_bytes = package
        .serialize()
        .map_err(|e| ConclaveError::CryptoError(format!("DKG package ser: {e:?}")))?;

    Ok((secret_bytes, package_bytes))
}

/// DKG Part 2: Verify all round-1 packages, produce encrypted shares for peers.
///
/// Takes:
/// - `secret_package_bytes` — serialized secret package from part1
/// - `round1_packages` — map of participant_id_bytes → package_bytes from all peers
///
/// Returns:
/// - `secret_package_bytes` — updated secret state for part3
/// - Map of participant_id_bytes → package_bytes to send to each peer
pub fn dkg_part2(
    secret_package_bytes: &[u8],
    round1_packages: &StdBTreeMap<Vec<u8>, Vec<u8>>,
) -> ConclaveResult<(Vec<u8>, StdBTreeMap<Vec<u8>, Vec<u8>>)> {
    let secret_package = dkg::round1::SecretPackage::<E>::deserialize(secret_package_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("DKG part2 secret deser: {e:?}")))?;

    let mut r1_packages: BTreeMap<Identifier<E>, dkg::round1::Package<E>> = BTreeMap::new();
    for (id_bytes, pkg_bytes) in round1_packages {
        let id = identifier_from_bytes(id_bytes)?;
        let pkg = dkg::round1::Package::<E>::deserialize(pkg_bytes)
            .map_err(|e| ConclaveError::CryptoError(format!("DKG part2 pkg deser: {e:?}")))?;
        r1_packages.insert(id, pkg);
    }

    let (round2_secret, round2_packages) =
        dkg::part2::<E>(secret_package, &r1_packages)
            .map_err(|e| ConclaveError::CryptoError(format!("FROST DKG part2: {e:?}")))?;

    let secret_bytes = round2_secret
        .serialize()
        .map_err(|e| ConclaveError::CryptoError(format!("DKG r2 secret ser: {e:?}")))?;

    let mut outgoing: StdBTreeMap<Vec<u8>, Vec<u8>> = StdBTreeMap::new();
    for (id, pkg) in round2_packages {
        let id_bytes: u16 = id.try_into().unwrap_or(0);
        let pkg_bytes = pkg
            .serialize()
            .map_err(|e| ConclaveError::CryptoError(format!("DKG r2 pkg ser: {e:?}")))?;
        outgoing.insert(id_bytes.to_be_bytes().to_vec(), pkg_bytes);
    }

    Ok((secret_bytes, outgoing))
}

/// DKG Part 3: Verify received shares, compute final KeyPackage + PublicKeyPackage.
///
/// Takes:
/// - `round2_secret_bytes` — serialized secret package from part2
/// - `round1_packages` — all round-1 packages (same map as part2)
/// - `round2_packages` — map of sender_id_bytes → package_bytes received from peers
///
/// Returns:
/// - `key_package_bytes` — serialized [`KeyPackage`] for this participant
/// - `pubkey_package_bytes` — serialized [`PublicKeyPackage`] (shared with all)
pub fn dkg_part3(
    round2_secret_bytes: &[u8],
    round1_packages: &StdBTreeMap<Vec<u8>, Vec<u8>>,
    round2_packages: &StdBTreeMap<Vec<u8>, Vec<u8>>,
) -> ConclaveResult<(Vec<u8>, Vec<u8>)> {
    let round2_secret = dkg::round2::SecretPackage::<E>::deserialize(round2_secret_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("DKG part3 secret deser: {e:?}")))?;

    let mut r1_packages: BTreeMap<Identifier<E>, dkg::round1::Package<E>> = BTreeMap::new();
    for (id_bytes, pkg_bytes) in round1_packages {
        let id = identifier_from_bytes(id_bytes)?;
        let pkg = dkg::round1::Package::<E>::deserialize(pkg_bytes)
            .map_err(|e| ConclaveError::CryptoError(format!("DKG part3 r1 deser: {e:?}")))?;
        r1_packages.insert(id, pkg);
    }

    let mut r2_packages: BTreeMap<Identifier<E>, dkg::round2::Package<E>> = BTreeMap::new();
    for (id_bytes, pkg_bytes) in round2_packages {
        let id = identifier_from_bytes(id_bytes)?;
        let pkg = dkg::round2::Package::<E>::deserialize(pkg_bytes)
            .map_err(|e| ConclaveError::CryptoError(format!("DKG part3 r2 deser: {e:?}")))?;
        r2_packages.insert(id, pkg);
    }

    let (key_package, pubkey_package) =
        dkg::part3::<E>(&round2_secret, &r1_packages, &r2_packages)
            .map_err(|e| ConclaveError::CryptoError(format!("FROST DKG part3: {e:?}")))?;

    let key_bytes = key_package
        .serialize()
        .map_err(|e| ConclaveError::CryptoError(format!("DKG keypkg ser: {e:?}")))?;

    let pubkey_bytes = pubkey_package
        .serialize()
        .map_err(|e| ConclaveError::CryptoError(format!("DKG pubkey ser: {e:?}")))?;

    Ok((key_bytes, pubkey_bytes))
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

    #[test]
    fn test_dkg_3_of_5_full_ceremony() {
        let n: u16 = 5;
        let t: u16 = 3;

        // Each participant runs part1
        let mut r1_secrets: StdBTreeMap<Vec<u8>, Vec<u8>> = StdBTreeMap::new();
        let mut all_r1_packages: StdBTreeMap<Vec<u8>, Vec<u8>> = StdBTreeMap::new();

        for i in 1..=n {
            let id = i.to_be_bytes().to_vec();
            let (secret, package) = dkg_part1(&id, n, t).unwrap();
            r1_secrets.insert(id.clone(), secret);
            all_r1_packages.insert(id, package);
        }

        // Each participant runs part2 (needs n-1 packages, excluding self)
        let mut r2_secrets: StdBTreeMap<Vec<u8>, Vec<u8>> = StdBTreeMap::new();
        let mut all_r2_out: StdBTreeMap<Vec<u8>, StdBTreeMap<Vec<u8>, Vec<u8>>> = StdBTreeMap::new();

        for i in 1..=n {
            let my_id = i.to_be_bytes().to_vec();
            let secret = r1_secrets.get(&my_id).unwrap();

            // Exclude self from r1 packages
            let mut peer_r1: StdBTreeMap<Vec<u8>, Vec<u8>> = StdBTreeMap::new();
            for (id, pkg) in &all_r1_packages {
                if *id != my_id {
                    peer_r1.insert(id.clone(), pkg.clone());
                }
            }

            let (r2_secret, r2_out) = dkg_part2(secret, &peer_r1).unwrap();
            r2_secrets.insert(my_id, r2_secret);
            all_r2_out.insert(my_id, r2_out);
        }

        // Each participant runs part3
        for i in 1..=n {
            let my_id = i.to_be_bytes().to_vec();
            let r2_secret = r2_secrets.get(&my_id).unwrap();

            // Exclude self from r1 packages
            let mut peer_r1: StdBTreeMap<Vec<u8>, Vec<u8>> = StdBTreeMap::new();
            for (id, pkg) in &all_r1_packages {
                if *id != my_id {
                    peer_r1.insert(id.clone(), pkg.clone());
                }
            }

            // Collect round2 packages sent TO this participant from each peer
            let mut my_r2_packages: StdBTreeMap<Vec<u8>, Vec<u8>> = StdBTreeMap::new();
            for (sender_id, r2_out) in &all_r2_out {
                if *sender_id == my_id {
                    continue;
                }
                if let Some(pkg) = r2_out.get(&my_id) {
                    my_r2_packages.insert(sender_id.clone(), pkg.clone());
                }
            }

            let result = dkg_part3(r2_secret, &peer_r1, &my_r2_packages);
            assert!(result.is_ok(), "DKG part3 failed for participant {i}");
            let (key_pkg, pubkey_pkg) = result.unwrap();
            assert!(!key_pkg.is_empty());
            assert!(!pubkey_pkg.is_empty());
        }
    }
}

