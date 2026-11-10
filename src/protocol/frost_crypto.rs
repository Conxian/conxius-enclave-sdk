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
) -> ConclaveResult<(Vec<Vec<u8>>, Vec<u8>)> {
    let rng = OsRng;
    let (shares_map, pubkey) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        rng,
    )
    .map_err(|e| ConclaveError::CryptoError(format!("keygen: {e:?}")))?;

    let vk = pubkey
        .serialize()
        .map_err(|e| ConclaveError::CryptoError(format!("pkpkg: {e:?}")))?;
    // IdentifierList::Default produces Identifiers 1, 2, 3, ...
    // Return shares in sorted order by identifier, matching the positional IDs
    let shares: Vec<Vec<u8>> = (1..=max_signers)
        .map(|i| {
            let id = Identifier::try_from(i)
                .map_err(|e| ConclaveError::CryptoError(format!("kp id: {e:?}")))?;
            let share = shares_map
                .get(&id)
                .ok_or_else(|| ConclaveError::CryptoError(format!("FROST: missing share {i}")))?;
            let key_pkg = frost::keys::KeyPackage::try_from(share.clone())
                .map_err(|e| ConclaveError::CryptoError(format!("kp: {e:?}")))?;
            key_pkg
                .serialize()
                .map_err(|e| ConclaveError::CryptoError(format!("kp ser: {e:?}")))
        })
        .collect::<Result<Vec<Vec<u8>>, ConclaveError>>()?;

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

pub fn create_signing_package(
    message: &[u8],
    commitment_list: &[Vec<u8>],
) -> ConclaveResult<Vec<u8>> {
    let mut sig_commitments = BTreeMap::new();
    for (i, c_bytes) in commitment_list.iter().enumerate() {
        let id = Identifier::try_from((i + 1) as u16)
            .map_err(|e| ConclaveError::CryptoError(format!("sigpkg id: {e:?}")))?;
        let sc = frost::round1::SigningCommitments::deserialize(c_bytes)
            .map_err(|e| ConclaveError::CryptoError(format!("sigpkg commit: {e:?}")))?;
        sig_commitments.insert(id, sc);
    }
    let sigpkg = frost::SigningPackage::new(sig_commitments, message);
    sigpkg
        .serialize()
        .map_err(|e| ConclaveError::CryptoError(format!("sigpkg ser: {e:?}")))
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
    share_list: &[(u16, Vec<u8>)],
    pubkey_bytes: &[u8],
) -> ConclaveResult<String> {
    let sigpkg = frost::SigningPackage::deserialize(sigpkg_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("sigpkg: {e:?}")))?;
    let shares: BTreeMap<Identifier, frost::round2::SignatureShare> = share_list
        .iter()
        .map(|(id_val, sb)| {
            let id = Identifier::try_from(*id_val)
                .map_err(|e| ConclaveError::CryptoError(format!("agg id: {e:?}")))?;
            Ok((
                id,
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

/// Derive the aggregated Schnorr x-only public key from a serialized
/// [`frost::keys::PublicKeyPackage`]. This is the key that the aggregated
/// threshold signature verifies against.
pub fn public_key_x_only(pubkey_package_bytes: &[u8]) -> ConclaveResult<Vec<u8>> {
    let pkg = frost::keys::PublicKeyPackage::deserialize(pubkey_package_bytes)
        .map_err(|e| ConclaveError::CryptoError(format!("pkg: {e:?}")))?;
    let vk = pkg.verifying_key();
    let mut key = vk
        .serialize()
        .map_err(|e| ConclaveError::CryptoError(format!("vk: {e:?}")))?;
    // SEC1 compressed form (33 bytes) -> BIP-340 x-only key (32 bytes):
    // drop the 0x02/0x03 parity prefix.
    if key.len() == 33 {
        key.remove(0);
    }
    Ok(key)
}

// ── DKG ─────────────────────────────────────────────────────────────

pub fn dkg_part1(
    id_bytes: &[u8],
    max_signers: u16,
    min_signers: u16,
) -> ConclaveResult<(Vec<u8>, Vec<u8>)> {
    let rng = OsRng;
    let id = id_from_bytes(id_bytes)?;
    let (secret, package) = dkg::part1(id, max_signers, min_signers, rng)
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

#[allow(clippy::type_complexity)]
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

/// Verify that a raw DKG Round 1 package deserializes cleanly.
///
/// Structural check only: the embedded proof of knowledge is *not* checked
/// here; it is verified later by `dkg_part2` when a peer consumes the
/// package (upstream `frost_core::keys::dkg::part2`).
pub fn verify_dkg_round1_package(pkg_bytes: &[u8]) -> ConclaveResult<bool> {
    match dkg::round1::Package::deserialize(pkg_bytes) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify that a raw DKG Round 2 package deserializes cleanly and passes
/// structural/point checks.
pub fn verify_dkg_round2_package(pkg_bytes: &[u8]) -> ConclaveResult<bool> {
    match dkg::round2::Package::deserialize(pkg_bytes) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
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
    fn test_keygen_and_aggregate_2_of_3() {
        let (shares, vk) = trusted_dealer_keygen(2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        assert!(!vk.is_empty());

        // Shares are in identifier order: shares[0] = Identifier(1), shares[1] = Identifier(2)
        let kp1 = &shares[0];
        let kp2 = &shares[1];

        let (n1, c1) = create_nonces_and_commitments(kp1).unwrap();
        let (n2, c2) = create_nonces_and_commitments(kp2).unwrap();

        let sigpkg_bytes = create_signing_package(b"test msg", &[c1, c2]).unwrap();

        let s1 = create_signature_share(kp1, &n1, &sigpkg_bytes, b"test msg").unwrap();
        let s2 = create_signature_share(kp2, &n2, &sigpkg_bytes, b"test msg").unwrap();

        let sig = aggregate(&sigpkg_bytes, &[(1, s1), (2, s2)], &vk).unwrap();
        assert!(!sig.is_empty());
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

    // ── Issue #726 independent-review characterization tests ─────────────

    type SField = frost::Secp256K1ScalarField;
    type SScalar = <SField as frost::Field>::Scalar;

    fn scalar_from32(bytes: &[u8]) -> SScalar {
        let arr: [u8; 32] = bytes.try_into().expect("32-byte scalar serialization");
        <SField as frost::Field>::deserialize(&arr).expect("scalar deserialization")
    }

    #[test]
    fn dkg_round2_publication_leaks_every_participant_secret_coefficient() {
        // Finding F1: ceremony/README.md tells operators to publish their
        // round-2 packages ("publish round2/pN.pkg"), but the pinned frost-core
        // documents round-2 packages as requiring a *confidential* channel
        // (frost-core/src/keys/dkg.rs: "The package must be sent on an
        // *confidential* and *authenticated* channel") because each package
        // carries a raw per-recipient signing share. At t=2, n=3 an observer
        // holding only the published round-2 files recovers every operator's
        // full secret polynomial, hence the group secret s = s1 + s2 + s3.
        let n: u16 = 3;
        let t: u16 = 2;
        let id_bytes: Vec<Vec<u8>> = (1..=n)
            .map(|i| Identifier::try_from(i).unwrap().serialize().to_vec())
            .collect();

        let mut r1s = BTreeMap::new();
        let mut r1p = BTreeMap::new();
        for ib in &id_bytes {
            let (s, p) = dkg_part1(ib, n, t).unwrap();
            r1s.insert(ib.clone(), s);
            r1p.insert(ib.clone(), p);
        }
        let mut all_r2: BTreeMap<Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>> = BTreeMap::new();
        for my_id in &id_bytes {
            let mut peer_r1 = BTreeMap::new();
            for (id, pkg) in &r1p {
                if id != my_id {
                    peer_r1.insert(id.clone(), pkg.clone());
                }
            }
            let (_sr, r2map) = dkg_part2(r1s.get(my_id).unwrap(), &peer_r1).unwrap();
            all_r2.insert(my_id.clone(), r2map);
        }

        // Schema drift: the API yields n-1 distinct per-recipient packages per
        // operator, while the ceremony docs describe a single "pN.pkg" file.
        for my_id in &id_bytes {
            let pkgs = all_r2.get(my_id).unwrap();
            assert_eq!(pkgs.len(), usize::from(n - 1));
            let mut it = pkgs.values();
            assert_ne!(it.next().unwrap(), it.next().unwrap());
        }

        // Observer view: the published share for recipient j is the trailing
        // 32-byte big-endian scalar of the serialized round-2 package.
        let mut secrets = Vec::new();
        for sender in &id_bytes {
            let pts: Vec<(SScalar, SScalar)> = all_r2[sender]
                .iter()
                .map(|(rid, pkg)| (scalar_from32(rid), scalar_from32(&pkg[pkg.len() - 32..])))
                .collect();
            // BTreeMap iteration is identifier-ordered; big-endian identifier
            // bytes sort with the numeric identifier, so pts is already ordered.
            // Two points determine the linear polynomial f_sender.
            let dx = pts[1].0 - pts[0].0;
            let inv = <SField as frost::Field>::invert(&dx).unwrap();
            let a = (pts[1].1 - pts[0].1) * inv;
            let s = pts[0].1 - a * pts[0].0;
            // Consistency with both published shares.
            assert_eq!(s + a * pts[0].0, pts[0].1);
            assert_eq!(s + a * pts[1].0, pts[1].1);
            secrets.push(s);
        }

        // The recovered coefficients are non-trivial and pairwise distinct, so
        // the observer holds real per-operator secrets, not zeros.
        let zero = <SField as frost::Field>::zero();
        for (i, si) in secrets.iter().enumerate() {
            assert_ne!(*si, zero);
            for sj in &secrets[i + 1..] {
                assert_ne!(si, sj);
            }
        }
        let group_secret = secrets.iter().fold(zero, |acc, s| acc + *s);
        assert_ne!(group_secret, zero);
    }

    #[test]
    fn forged_round1_proof_of_knowledge_passes_verify_but_fails_part2() {
        // Finding F2: `verify_dkg_round1_package` only deserializes. A round-1
        // package whose proof-of-knowledge scalar is forged passes the CI
        // pickup check and is rejected only later, inside `dkg_part2`.
        let n: u16 = 3;
        let t: u16 = 2;
        let id_bytes: Vec<Vec<u8>> = (1..=n)
            .map(|i| Identifier::try_from(i).unwrap().serialize().to_vec())
            .collect();
        let mut r1s = BTreeMap::new();
        let mut r1p = BTreeMap::new();
        for ib in &id_bytes {
            let (s, p) = dkg_part1(ib, n, t).unwrap();
            r1s.insert(ib.clone(), s);
            r1p.insert(ib.clone(), p);
        }

        // Flip one bit of the trailing proof-of-knowledge scalar mu of operator 1's package.
        let mut forged = r1p[&id_bytes[0]].clone();
        let last = forged.len() - 1;
        forged[last] ^= 0x01;
        assert_ne!(forged, r1p[&id_bytes[0]]);

        assert!(verify_dkg_round1_package(&r1p[&id_bytes[0]]).unwrap());
        assert!(
            verify_dkg_round1_package(&forged).unwrap(),
            "F2: a forged proof of knowledge still passes verify_dkg_round1_package"
        );

        let mut peer_r1 = BTreeMap::new();
        peer_r1.insert(id_bytes[0].clone(), forged);
        peer_r1.insert(id_bytes[2].clone(), r1p[&id_bytes[2]].clone());
        let err = dkg_part2(r1s.get(&id_bytes[1]).unwrap(), &peer_r1)
            .expect_err("dkg_part2 must reject a forged proof of knowledge");
        assert!(
            format!("{err:?}").contains("InvalidProofOfKnowledge"),
            "unexpected part2 rejection reason: {err:?}"
        );
    }

    #[test]
    fn custom_dkg_identifiers_construct_but_positional_signing_breaks() {
        // Finding F7: `create_signing_package` assigns participant identifiers
        // positionally (i + 1), so a ceremony that runs DKG with custom
        // identifiers constructs cleanly but fails at first signing.
        let n: u16 = 3;
        let t: u16 = 2;
        let ids: Vec<Vec<u8>> = [10u16, 11, 12]
            .iter()
            .map(|i| Identifier::try_from(*i).unwrap().serialize().to_vec())
            .collect();

        let mut r1s = BTreeMap::new();
        let mut r1p = BTreeMap::new();
        for ib in &ids {
            let (s, p) = dkg_part1(ib, n, t).unwrap();
            r1s.insert(ib.clone(), s);
            r1p.insert(ib.clone(), p);
        }
        let mut r2s = BTreeMap::new();
        let mut all_r2: BTreeMap<Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>> = BTreeMap::new();
        for my_id in &ids {
            let mut peer_r1 = BTreeMap::new();
            for (id, pkg) in &r1p {
                if id != my_id {
                    peer_r1.insert(id.clone(), pkg.clone());
                }
            }
            let (sr, r2map) = dkg_part2(r1s.get(my_id).unwrap(), &peer_r1).unwrap();
            r2s.insert(my_id.clone(), sr);
            all_r2.insert(my_id.clone(), r2map);
        }
        let mut key_packages = Vec::new();
        for my_id in &ids {
            let mut peer_r1 = BTreeMap::new();
            for (id, pkg) in &r1p {
                if id != my_id {
                    peer_r1.insert(id.clone(), pkg.clone());
                }
            }
            let mut my_r2 = BTreeMap::new();
            for (sender_id, r2_out) in &all_r2 {
                if sender_id == my_id {
                    continue;
                }
                if let Some(p) = r2_out.get(my_id) {
                    my_r2.insert(sender_id.clone(), p.clone());
                }
            }
            let (kp, pp) = dkg_part3(r2s.get(my_id).unwrap(), &peer_r1, &my_r2).unwrap();
            assert!(!kp.is_empty() && !pp.is_empty());
            key_packages.push(kp);
        }

        // DKG succeeded end-to-end; signing is where the positional assumption bites.
        let (n1, c1) = create_nonces_and_commitments(&key_packages[0]).unwrap();
        let (_n2, c2) = create_nonces_and_commitments(&key_packages[1]).unwrap();
        let sigpkg = create_signing_package(b"custom-id msg", &[c1, c2]).unwrap();
        assert!(
            create_signature_share(&key_packages[0], &n1, &sigpkg, b"custom-id msg").is_err(),
            "F7: a key package with identifier 10 should not sign a positional-identifier package"
        );
    }
}
