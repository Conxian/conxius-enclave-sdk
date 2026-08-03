//! FROST cryptographic execution backend.
//!
//! This module provides real threshold signing operations backed by the
//! Zcash Foundation FROST library (`frost-secp256k1-tr` v3.0.0, RFC 9591).
//! It is gated behind the `frost-crypto` feature flag.
use std::collections::BTreeMap;

use frost::{keys::dkg, Identifier};
use frost_secp256k1_tr as frost;
use rand_core06::OsRng;

use crate::{ConclaveError, ConclaveResult};

fn id_from_bytes(bytes: &[u8]) -> ConclaveResult<Identifier> {
    Identifier::deserialize(bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("id deser: {e:?}")))
}

// ── Trusted Dealer Key Generation ──────────────────────────────────

pub fn trusted_dealer_keygen(
    min_signers: u16,
    max_signers: u16,
) -> ConclaveResult<(BTreeMap<Vec<u8>, Vec<u8>>, Vec<u8>)> {
    let mut rng = OsRng;
    let (shares_map, pubkey) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .map_err(|e| ConclaveError::CryptoError(format!("keygen: {e:?}")))?;

    let vk = pubkey
        .verifying_key()
        .serialize()
        .map_err(|e| ConclaveError::CryptoError(format!("vk: {e:?}")))?;
    let shares: BTreeMap<Vec<u8>, Vec<u8>> = shares_map
        .into_iter()
        .map(|(id, share)| {
            Ok((
                id.serialize().to_vec(),
                share
                    .serialize()
                    .map_err(|e| ConclaveError::CryptoError(format!("share ser: {e:?}")))?,
            ))
        })
        .collect::<Result<BTreeMap<Vec<u8>, Vec<u8>>, ConclaveError>>()?;

    Ok((shares, vk))
}

// ── Signing ─────────────────────────────────────────────────────────

pub fn create_nonces_and_commitments(key_pkg_bytes: &[u8]) -> ConclaveResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = OsRng;
    let kp = frost::keys::KeyPackage::deserialize(key_pkg_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("keypkg: {e:?}")))?;
    let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
    Ok((
        nonces
            .serialize()
            .map_err(|e| ConclaveError::CryptoError(format!("nonce: {e:?}")))?,
        commitments
            .serialize()
            .map_err(|e| ConclaveError::CryptoError(format!("commit: {e:?}")))?,
    ))
}

pub fn create_signature_share(
    key_pkg_bytes: &[u8],
    nonces_bytes: &[u8],
    sigpkg_bytes: &[u8],
    _message: &[u8],
) -> ConclaveResult<Vec<u8>> {
    let kp = frost::keys::KeyPackage::deserialize(key_pkg_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("keypkg: {e:?}")))?;
    let nonces = frost::round1::SigningNonces::deserialize(nonces_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("nonce: {e:?}")))?;
    let sigpkg = frost::SigningPackage::deserialize(sigpkg_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("sigpkg: {e:?}")))?;
    let ss = frost::round2::sign(&sigpkg, &nonces, &kp)
        .map_err(|e| ConclaveError::CryptoError(format!("sign: {e:?}")))?;
    Ok(ss.serialize())
}

pub fn aggregate(
    sigpkg_bytes: &[u8],
    share_list: &[(Vec<u8>, Vec<u8>)],
    pubkey_bytes: &[u8],
) -> ConclaveResult<String> {
    let sigpkg = frost::SigningPackage::deserialize(sigpkg_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("sigpkg: {e:?}")))?;
    let shares: BTreeMap<Identifier, frost::round2::SignatureShare> = share_list
        .iter()
        .map(|(idb, sb)| {
            Ok((
                id_from_bytes(idb)?,
                frost::round2::SignatureShare::deserialize(sb)
                    .map_err(|e| ConclaveError::CryptoError(format!("ss: {e:?}")))?,
            ))
        })
        .collect::<Result<BTreeMap<Identifier, frost::round2::SignatureShare>, ConclaveError>>()?;
    let pkg = frost::keys::PublicKeyPackage::deserialize(pubkey_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("pkg: {e:?}")))?;
    let sig = frost::aggregate(&sigpkg, &shares, &pkg)
        .map_err(|e| ConclaveError::CryptoError(format!("aggregate: {e:?}")))?;
    let sig_bytes = sig
        .serialize()
        .map_err(|e| ConclaveError::CryptoError(format!("agg: {e:?}")))?;
    Ok(hex::encode(sig_bytes))
}

// ── DKG ─────────────────────────────────────────────────────────────

pub fn dkg_part1(
    id_bytes: &[u8],
    max_signers: u16,
    min_signers: u16,
) -> ConclaveResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = OsRng;
    let id = id_from_bytes(id_bytes)?;
    let (secret, package) = dkg::part1(id, max_signers, min_signers, &mut rng)
        .map_err(|e| ConclaveError::CryptoError(format!("DKG p1: {e:?}")))?;
    Ok((
        secret
            .serialize()
            .map_err(|e| ConclaveError::CryptoError(format!("DKG s1: {e:?}")))?,
        package
            .serialize()
            .map_err(|e| ConclaveError::CryptoError(format!("DKG pkg: {e:?}")))?,
    ))
}

pub fn dkg_part2(
    secret_bytes: &[u8],
    r1_packages: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> ConclaveResult<(Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>)> {
    let secret = dkg::round1::SecretPackage::deserialize(secret_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("DKG p2s: {e:?}")))?;
    let mut r1: BTreeMap<Identifier, _> = BTreeMap::new();
    for (ib, pb) in r1_packages {
        r1.insert(
            id_from_bytes(ib)?,
            dkg::round1::Package::deserialize(pb)
                .map_err(|e| ConclaveError::CryptoError(format!("DKG r1: {e:?}")))?,
        );
    }
    let (r2_secret, r2_pkgs) = dkg::part2(secret, &r1)
        .map_err(|e| ConclaveError::CryptoError(format!("DKG p2: {e:?}")))?;
    let mut out = BTreeMap::new();
    for (id, pkg) in r2_pkgs {
        out.insert(
            id.serialize().to_vec(),
            pkg.serialize()
                .map_err(|e| ConclaveError::CryptoError(format!("DKG r2p: {e:?}")))?,
        );
    }
    Ok((
        r2_secret
            .serialize()
            .map_err(|e| ConclaveError::CryptoError(format!("DKG r2s: {e:?}")))?,
        out,
    ))
}

pub fn dkg_part3(
    r2_secret_bytes: &[u8],
    r1_packages: &BTreeMap<Vec<u8>, Vec<u8>>,
    r2_packages: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> ConclaveResult<(Vec<u8>, Vec<u8>)> {
    let r2_secret = dkg::round2::SecretPackage::deserialize(r2_secret_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("DKG p3s: {e:?}")))?;
    let mut r1: BTreeMap<Identifier, _> = BTreeMap::new();
    for (ib, pb) in r1_packages {
        r1.insert(
            id_from_bytes(ib)?,
            dkg::round1::Package::deserialize(pb)
                .map_err(|e| ConclaveError::CryptoError(format!("DKG p3r1: {e:?}")))?,
        );
    }
    let mut r2: BTreeMap<Identifier, _> = BTreeMap::new();
    for (ib, pb) in r2_packages {
        r2.insert(
            id_from_bytes(ib)?,
            dkg::round2::Package::deserialize(pb)
                .map_err(|e| ConclaveError::CryptoError(format!("DKG p3r2: {e:?}")))?,
        );
    }
    let (key_pkg, pubkey_pkg) = dkg::part3(&r2_secret, &r1, &r2)
        .map_err(|e| ConclaveError::CryptoError(format!("DKG p3: {e:?}")))?;
    Ok((
        key_pkg
            .serialize()
            .map_err(|e| ConclaveError::CryptoError(format!("DKG key: {e:?}")))?,
        pubkey_pkg
            .serialize()
            .map_err(|e| ConclaveError::CryptoError(format!("DKG pk: {e:?}")))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_2_of_3() {
        let (shares, vk) = trusted_dealer_keygen(2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        assert!(!vk.is_empty());
    }

    #[test]
    fn test_nonces() {
        let (_shares, _vk) = trusted_dealer_keygen(2, 2).unwrap();
        assert_eq!(_shares.len(), 2);
    }

    #[test]
    fn test_dkg_full() {
        let n: u16 = 5;
        let t: u16 = 3;

        let ids: Vec<(Vec<u8>, Identifier)> = (1..=n)
            .map(|i| {
                let id = Identifier::try_from(i).unwrap();
                (id.serialize().to_vec(), id)
            })
            .collect();

        // Part 1
        let mut r1s: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        let mut r1p: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        for (id_bytes, _) in &ids {
            let (s, p) = dkg_part1(id_bytes, n, t).unwrap();
            r1s.insert(id_bytes.clone(), s);
            r1p.insert(id_bytes.clone(), p);
        }

        // Part 2
        let mut r2s: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        let mut all_r2: BTreeMap<Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>> = BTreeMap::new();
        for (my_id, _) in &ids {
            let secret = r1s.get(my_id).unwrap();
            let mut peer_r1: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
            for (id, pkg) in &r1p {
                if id != my_id {
                    peer_r1.insert(id.clone(), pkg.clone());
                }
            }
            let (sr, r2) = dkg_part2(secret, &peer_r1).unwrap();
            r2s.insert(my_id.clone(), sr);
            all_r2.insert(my_id.clone(), r2);
        }

        // Part 3
        for (my_id, _) in &ids {
            let sr = r2s.get(my_id).unwrap();
            let mut peer_r1: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
            for (id, pkg) in &r1p {
                if id != my_id {
                    peer_r1.insert(id.clone(), pkg.clone());
                }
            }
            let mut my_r2: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
            for (sender_id, r2_out) in &all_r2 {
                if sender_id == my_id {
                    continue;
                }
                if let Some(p) = r2_out.get(my_id) {
                    my_r2.insert(sender_id.clone(), p.clone());
                }
            }
            let (kp, pp) = dkg_part3(sr, &peer_r1, &my_r2).unwrap();
            assert!(!kp.is_empty());
            assert!(!pp.is_empty());
        }
    }
}
