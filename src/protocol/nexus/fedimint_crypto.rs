//! Real BLS12-381 Fedimint e-cash primitives: message blinding and
//! Chaum-Pedersen DLEQ (discrete-log equality) proof verification.
//!
//! Gated behind the `fedimint-crypto` feature. Without the feature this module
//! is not compiled, and the Fedimint boundary types in `fedimint.rs` validate
//! structurally but return `ProtocolUnsupported` for cryptographic execution
//! paths (fail closed).
//!
//! # Security notes
//!
//! * `blind_message`/`unblind_signature` operate on arbitrary G1 points; the
//!   caller is responsible for hash-to-curve of the message itself (not
//!   provided by `bls12_381`). This module is the group-arithmetic and
//!   DLEQ-verification layer only.
//! * DLEQ proof generation uses a deterministic RFC 6979-style nonce derived
//!   from the secret and the blinded message, so nonce reuse cannot leak the
//!   mint secret.

use crate::{ConclaveError, ConclaveResult};
use bls12_381::{G1Affine, G1Projective, Scalar};
use sha2::{Digest, Sha256};

/// Domain separator for the Fiat-Shamir challenge.
const DLEQ_DOMAIN: &[u8] = b"CONXIAN-FEDIMINT-DLEQ-v1";
/// Domain separator for the deterministic proof nonce.
const NONCE_DOMAIN: &[u8] = b"CONXIAN-FEDIMINT-DLEQ-NONCE-v1";

/// A compressed BLS12-381 G1 point (48 bytes, compressed encoding).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FedimintG1Point(pub [u8; 48]);

impl FedimintG1Point {
    pub fn new(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(self) -> [u8; 48] {
        self.0
    }

    /// Decompress and validate on-curve + prime-order subgroup membership.
    /// Rejects the identity point. Fails closed on any malformed encoding.
    fn to_affine(self) -> ConclaveResult<G1Affine> {
        let point = G1Affine::from_compressed(&self.0)
            .into_option()
            .ok_or_else(|| {
                ConclaveError::CryptoError("Fedimint e-cash: invalid G1 point encoding".to_string())
            })?;
        if bool::from(point.is_identity()) {
            return Err(ConclaveError::CryptoError(
                "Fedimint e-cash: identity G1 point".to_string(),
            ));
        }
        Ok(point)
    }
}

/// A BLS12-381 scalar (`Fr`), 32 bytes little-endian.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FedimintScalar(pub [u8; 32]);

impl FedimintScalar {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Decode a scalar, rejecting out-of-range encodings (fail closed).
    fn to_scalar(self) -> ConclaveResult<Scalar> {
        Scalar::from_bytes(&self.0).into_option().ok_or_else(|| {
            ConclaveError::CryptoError("Fedimint e-cash: scalar out of range".to_string())
        })
    }
}

/// A Chaum-Pedersen DLEQ proof: proves that `signed_message = x · blinded_message`
/// and `public_key = x · G` use the same secret `x`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FedimintDleqProof {
    /// Mint public key `X = x·G`.
    pub public_key: FedimintG1Point,
    /// The blinded message `B = r·M`.
    pub blinded_message: FedimintG1Point,
    /// The signed blinded message `A = x·B`.
    pub signed_message: FedimintG1Point,
    /// Fiat-Shamir challenge `c`.
    pub challenge: FedimintScalar,
    /// Response `s = r + c·x`.
    pub response: FedimintScalar,
}

impl FedimintDleqProof {
    /// Verify the DLEQ proof. Returns `Ok(true)` only when the proof is valid;
    /// any malformed point/scalar or equation mismatch yields `Ok(false)`.
    pub fn verify(&self) -> ConclaveResult<bool> {
        let x = match self.public_key.to_affine() {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };
        let b = match self.blinded_message.to_affine() {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };
        let a = match self.signed_message.to_affine() {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };
        let c = match self.challenge.to_scalar() {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };
        let s = match self.response.to_scalar() {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };

        let xp = G1Projective::from(x);
        let bp = G1Projective::from(b);
        let ap = G1Projective::from(a);

        // Recomputed commitments: R1' = s·G - c·X and R2' = s·B - c·A.
        let r1 = G1Affine::from(G1Projective::generator() * s - xp * c);
        let r2 = G1Affine::from(bp * s - ap * c);

        let expected = compute_challenge(&x, &b, &a, &r1, &r2);
        Ok(expected == c)
    }
}

/// Blind a message point with a blinding factor: `B = r · M`.
pub fn blind_message(
    message: FedimintG1Point,
    blinding: FedimintScalar,
) -> ConclaveResult<FedimintG1Point> {
    let m = message.to_affine()?;
    let r = blinding.to_scalar()?;
    if r.to_bytes() == [0u8; 32] {
        return Err(ConclaveError::CryptoError(
            "Fedimint e-cash: zero blinding factor".to_string(),
        ));
    }
    let blinded = G1Affine::from(G1Projective::from(m) * r);
    Ok(FedimintG1Point(blinded.to_compressed()))
}

/// Unblind a signed blinded message: `S = r^{-1} · A`.
pub fn unblind_signature(
    signed: FedimintG1Point,
    blinding: FedimintScalar,
) -> ConclaveResult<FedimintG1Point> {
    let a = signed.to_affine()?;
    let r = blinding.to_scalar()?;
    let r_inv = r.invert().into_option().ok_or_else(|| {
        ConclaveError::CryptoError("Fedimint e-cash: zero blinding factor".to_string())
    })?;
    let unblinded = G1Affine::from(G1Projective::from(a) * r_inv);
    Ok(FedimintG1Point(unblinded.to_compressed()))
}

/// Generate a DLEQ proof (mint/provider side). Uses a deterministic RFC 6979-
/// style nonce derived from the secret and the blinded message, so nonce reuse
/// cannot leak the mint secret.
pub fn generate_dleq_proof(
    secret: FedimintScalar,
    blinded_message: FedimintG1Point,
) -> ConclaveResult<FedimintDleqProof> {
    let x = secret.to_scalar()?;
    let b = blinded_message.to_affine()?;
    let bp = G1Projective::from(b);

    let a = G1Affine::from(bp * x);
    let xp = G1Affine::from(G1Projective::generator() * x);

    let r = deterministic_nonce(&secret, &blinded_message)?;
    let r1 = G1Affine::from(G1Projective::generator() * r);
    let r2 = G1Affine::from(bp * r);

    let c = compute_challenge(&xp, &b, &a, &r1, &r2);
    let s = r + c * x;

    Ok(FedimintDleqProof {
        public_key: FedimintG1Point(xp.to_compressed()),
        blinded_message,
        signed_message: FedimintG1Point(a.to_compressed()),
        challenge: FedimintScalar(c.to_bytes()),
        response: FedimintScalar(s.to_bytes()),
    })
}

/// Fiat-Shamir challenge: `H(domain || X || B || A || R1 || R2) mod r`.
fn compute_challenge(
    x: &G1Affine,
    b: &G1Affine,
    a: &G1Affine,
    r1: &G1Affine,
    r2: &G1Affine,
) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(DLEQ_DOMAIN);
    hasher.update(x.to_compressed());
    hasher.update(b.to_compressed());
    hasher.update(a.to_compressed());
    hasher.update(r1.to_compressed());
    hasher.update(r2.to_compressed());
    let digest: [u8; 32] = hasher.finalize().into();
    hash_to_scalar(&digest)
}

/// Deterministic proof nonce: `H(nonce_domain || secret || blinded) mod r`.
fn deterministic_nonce(
    secret: &FedimintScalar,
    blinded: &FedimintG1Point,
) -> ConclaveResult<Scalar> {
    let mut hasher = Sha256::new();
    hasher.update(NONCE_DOMAIN);
    hasher.update(secret.0);
    hasher.update(blinded.0);
    let digest: [u8; 32] = hasher.finalize().into();
    let r = hash_to_scalar(&digest);
    if r.to_bytes() == [0u8; 32] {
        return Err(ConclaveError::CryptoError(
            "Fedimint DLEQ: zero nonce".to_string(),
        ));
    }
    Ok(r)
}

/// Reduce a 32-byte digest to a scalar via 64-byte wide reduction.
fn hash_to_scalar(digest: &[u8; 32]) -> Scalar {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(digest);
    Scalar::from_bytes_wide(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::Scalar as BlsScalar;

    fn scalar_from_u64(n: u64) -> FedimintScalar {
        FedimintScalar(BlsScalar::from(n).to_bytes())
    }

    fn scaled_generator(n: u64) -> FedimintG1Point {
        let p = G1Projective::generator() * BlsScalar::from(n);
        FedimintG1Point(G1Affine::from(p).to_compressed())
    }

    #[test]
    fn genuine_dleq_proof_verifies() {
        let secret = scalar_from_u64(11);
        let blinded = scaled_generator(5); // B = 5·G
        let proof = generate_dleq_proof(secret, blinded).unwrap();
        assert!(proof.verify().unwrap());
    }

    #[test]
    fn dleq_proof_rejects_tampered_response() {
        let secret = scalar_from_u64(11);
        let blinded = scaled_generator(5);
        let mut proof = generate_dleq_proof(secret, blinded).unwrap();
        proof.response = scalar_from_u64(99); // tamper s
        assert!(!proof.verify().unwrap());
    }

    #[test]
    fn dleq_proof_rejects_tampered_public_key() {
        let secret = scalar_from_u64(11);
        let blinded = scaled_generator(5);
        let mut proof = generate_dleq_proof(secret, blinded).unwrap();
        proof.public_key = scaled_generator(13); // different X = 13·G
        assert!(!proof.verify().unwrap());
    }

    #[test]
    fn dleq_proof_rejects_invalid_point_encoding() {
        let secret = scalar_from_u64(11);
        let blinded = scaled_generator(5);
        let mut proof = generate_dleq_proof(secret, blinded).unwrap();
        proof.blinded_message = FedimintG1Point([0u8; 48]); // all-zero encoding
        assert!(!proof.verify().unwrap());
    }

    #[test]
    fn dleq_proof_rejects_out_of_range_scalar() {
        let secret = scalar_from_u64(11);
        let blinded = scaled_generator(5);
        let mut proof = generate_dleq_proof(secret, blinded).unwrap();
        proof.challenge = FedimintScalar([0xff; 32]); // >= r, out of range
        assert!(!proof.verify().unwrap());
    }

    #[test]
    fn blind_unblind_roundtrip_matches_direct_signature() {
        let secret = scalar_from_u64(7);
        let message = scaled_generator(3); // M = 3·G
        let blinding = scalar_from_u64(17); // r

        // User blinds, mint signs, user unblinds.
        let blinded = blind_message(message, blinding).unwrap();
        let signed = generate_dleq_proof(secret, blinded).unwrap();
        let unblinded = unblind_signature(signed.signed_message, blinding).unwrap();

        // Unblinded signature must equal x·M = x·(3·G).
        let expected = G1Projective::from(message.to_affine().unwrap()) * BlsScalar::from(7u64);
        let expected = FedimintG1Point(G1Affine::from(expected).to_compressed());
        assert_eq!(unblinded, expected);
    }

    #[test]
    fn blind_message_rejects_zero_blinding_factor() {
        let message = scaled_generator(3);
        let zero = scalar_from_u64(0);
        assert!(blind_message(message, zero).is_err());
    }

    #[test]
    fn generate_dleq_proof_uses_deterministic_nonce() {
        let secret = scalar_from_u64(11);
        let blinded = scaled_generator(5);
        let p1 = generate_dleq_proof(secret, blinded).unwrap();
        let p2 = generate_dleq_proof(secret, blinded).unwrap();
        assert_eq!(p1, p2);
    }
}
