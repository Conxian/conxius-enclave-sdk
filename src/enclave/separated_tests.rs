//! Behavioural tests for separated-share threshold signing (Issue #726 F4,
//! #745). These run against the real ZF FROST secp256k1-tr backend.

use super::separated::{ThresholdCoordinator, ThresholdOperator};
use crate::protocol::frost_crypto::{public_key_x_only, trusted_dealer_keygen};
use crate::ConclaveResult;

/// Independent BIP-340 Schnorr verification using the `secp256k1` crate (not
/// FROST types), so a passing test does not merely trust the library that
/// produced the signature. BIP-340 signs the message directly; the tests use
/// 32-byte messages, which the `secp256k1` verifier accepts as a digest.
mod bip340 {
    use secp256k1::schnorr::{verify as schnorr_verify, Signature};
    use secp256k1::XOnlyPublicKey;

    pub fn verify(xonly_pubkey: &[u8], message: &[u8; 32], sig_hex: &str) -> bool {
        let Ok(xonly_arr) = <[u8; 32]>::try_from(xonly_pubkey) else {
            return false;
        };
        let Ok(xonly) = XOnlyPublicKey::from_byte_array(xonly_arr) else {
            return false;
        };
        let digest = *message;
        let Ok(sig_bytes) = hex::decode(sig_hex) else {
            return false;
        };
        let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
            return false;
        };
        let sig = Signature::from_byte_array(sig_arr);
        schnorr_verify(&sig, &digest, &xonly).is_ok()
    }
}

fn ceremony() -> (Vec<Vec<u8>>, Vec<u8>) {
    trusted_dealer_keygen(2, 3).expect("trusted-dealer keygen")
}

/// Sign with an explicit participant subset, each operator holding only its own
/// share, exactly as production does.
fn sign_with_subset(
    key_packages: &[Vec<u8>],
    public_key_package: &[u8],
    subset: &[u16],
    message: &[u8; 32],
) -> ConclaveResult<(String, Vec<u8>)> {
    let mut operators: Vec<ThresholdOperator> = subset
        .iter()
        .map(|id| {
            ThresholdOperator::from_key_package(*id, key_packages[(*id - 1) as usize].clone())
        })
        .collect::<ConclaveResult<_>>()?;

    let coordinator = ThresholdCoordinator::new(public_key_package.to_vec(), 2)?;
    let aggregated = coordinator.aggregated_public_key()?;

    let commitments: Vec<(u16, Vec<u8>)> = operators
        .iter_mut()
        .map(|op| op.commit().map(|(_, c)| (op.identifier(), c)))
        .collect::<ConclaveResult<_>>()?;

    let signing_package = coordinator.signing_package(message, &commitments)?;

    let shares: Vec<(u16, Vec<u8>)> = operators
        .iter_mut()
        .map(|op| op.sign(&signing_package).map(|s| (op.identifier(), s)))
        .collect::<ConclaveResult<_>>()?;

    let signature = coordinator.aggregate(&signing_package, &shares)?;
    Ok((signature, aggregated))
}

#[test]
fn signs_with_non_contiguous_subset_one_and_three() {
    // The historical positional-id bug only worked for {1,2}; {1,3} must work.
    let (key_packages, public_key_package) = ceremony();
    let message = &[0x13u8; 32];
    let (signature, aggregated) =
        sign_with_subset(&key_packages, &public_key_package, &[1, 3], message)
            .expect("subset {1,3} must sign");
    assert_eq!(signature.len(), 128, "Schnorr signature is 64 bytes");
    assert!(
        bip340::verify(&aggregated, message, &signature),
        "signature from subset {{1,3}} must verify under the aggregated key"
    );
}

#[test]
fn signs_with_subset_two_and_three() {
    let (key_packages, public_key_package) = ceremony();
    let message = &[0x23u8; 32];
    let (signature, aggregated) =
        sign_with_subset(&key_packages, &public_key_package, &[2, 3], message)
            .expect("subset {2,3} must sign");
    assert!(bip340::verify(&aggregated, message, &signature));
}

#[test]
fn coordinator_holds_no_secret_and_aggregated_key_matches_ceremony() {
    let (_key_packages, public_key_package) = ceremony();
    let coordinator = ThresholdCoordinator::new(public_key_package.clone(), 2).unwrap();
    // The coordinator only ever exposes the public key.
    assert_eq!(
        coordinator.aggregated_public_key().unwrap(),
        public_key_x_only(&public_key_package).unwrap()
    );
    assert_eq!(coordinator.min_signers(), 2);
}

#[test]
fn offline_operator_does_not_halt_signing() {
    // F4 availability: with t=2 of n=3, losing operator 2 must still allow the
    // remaining {1,3} to produce a valid signature.
    let (key_packages, public_key_package) = ceremony();
    let message = &[0x0Fu8; 32];
    let (signature, aggregated) =
        sign_with_subset(&key_packages, &public_key_package, &[1, 3], message)
            .expect("2 of 3 available operators must still sign");
    assert!(bip340::verify(&aggregated, message, &signature));
}

#[test]
fn forged_signature_share_is_rejected() {
    let (key_packages, public_key_package) = ceremony();
    let message = &[0xF0u8; 32];
    let mut operators = [
        ThresholdOperator::from_key_package(1, key_packages[0].clone()).unwrap(),
        ThresholdOperator::from_key_package(3, key_packages[2].clone()).unwrap(),
    ];
    let coordinator = ThresholdCoordinator::new(public_key_package, 2).unwrap();
    let commitments: Vec<(u16, Vec<u8>)> = operators
        .iter_mut()
        .map(|op| op.commit().map(|(_, c)| (op.identifier(), c)))
        .collect::<ConclaveResult<_>>()
        .unwrap();
    let signing_package = coordinator.signing_package(message, &commitments).unwrap();
    let s1 = operators[0].sign(&signing_package).unwrap();
    let s3 = operators[1].sign(&signing_package).unwrap();
    // Present operator 1's share under operator 3's identifier.
    let err = coordinator
        .aggregate(&signing_package, &[(1, s1.clone()), (3, s1.clone())])
        .expect_err("a mislabelled share must not aggregate");
    assert!(
        format!("{err:?}").contains("InvalidSignatureShare"),
        "unexpected error: {err:?}"
    );
    // The honest share set still aggregates.
    assert!(coordinator
        .aggregate(&signing_package, &[(1, s1), (3, s3)])
        .is_ok());
}

#[test]
fn signing_package_requires_threshold_participants() {
    let (_key_packages, public_key_package) = ceremony();
    let coordinator = ThresholdCoordinator::new(public_key_package, 2).unwrap();
    let op = ThresholdOperator::from_key_package(1, ceremony().0[0].clone()).unwrap();
    let mut op = op;
    let (_, c1) = op.commit().unwrap();
    let err = coordinator
        .signing_package(b"too-few", &[(1, c1)])
        .expect_err("one commitment is below the threshold");
    assert!(format!("{err:?}").contains("at least 2"));
}

#[test]
fn duplicate_participant_is_rejected() {
    let (_key_packages, public_key_package) = ceremony();
    let coordinator = ThresholdCoordinator::new(public_key_package, 2).unwrap();
    let (kps, _) = ceremony();
    let mut a = ThresholdOperator::from_key_package(1, kps[0].clone()).unwrap();
    let mut b = ThresholdOperator::from_key_package(2, kps[1].clone()).unwrap();
    let (_, ca) = a.commit().unwrap();
    let (_, cb) = b.commit().unwrap();
    let err = coordinator
        .signing_package(b"dup", &[(1, ca), (1, cb)])
        .expect_err("duplicate identifier must be rejected");
    assert!(format!("{err:?}").contains("duplicate participant id"));
}

#[test]
fn operator_rejects_mismatched_identifier() {
    let (kps, _) = ceremony();
    // Share 1 filed under identifier 2 must not load.
    let result = ThresholdOperator::from_key_package(2, kps[0].clone());
    assert!(
        matches!(result, Err(crate::ConclaveError::InvalidPayload)),
        "identifier mismatch must be rejected"
    );
}

#[test]
fn nonce_is_single_use() {
    let (kps, _) = ceremony();
    let mut op = ThresholdOperator::from_key_package(1, kps[0].clone()).unwrap();
    let _ = op.commit().unwrap();
    // Signing consumes the nonce; a second sign without a new commit fails.
    let _ = op.sign(b"not-a-real-sigpkg");
    assert!(op.sign(b"reuse").is_err(), "nonce must not be reusable");
}
