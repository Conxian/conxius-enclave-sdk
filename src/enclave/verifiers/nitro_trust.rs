//! Production AWS Nitro certificate trust boundary.
//!
//! Implements `NitroCertificateTrustBoundary` with real certificate chain
//! validation against the AWS Nitro Root CA. This is the P0 gate that
//! unblocks `AwsNitroVerifier` for production use.
//!
//! # Certificate chain validation
//! 1. Verify the embedded AWS Nitro Root CA (G1) against its pinned SHA-256
//!    fingerprint.
//! 2. Parse the attestation document's leaf certificate and CA bundle.
//!    AWS encodes the bundle root-first: `[root, intermediate_N, ..., intermediate_1]`.
//! 3. Require the supplied root to byte-match the pinned root (fail closed on
//!    root substitution).
//! 4. Build the leaf-first chain `[leaf, intermediate_1, ..., intermediate_N, root]`
//!    and cryptographically verify every link's ECDSA P-384 signature over the
//!    DER-encoded TBS, with `ecdsa-with-SHA384` as the only accepted algorithm.

use crate::enclave::nitro::{
    NitroAttestationDocument, NitroCertificateTrustBoundary, NitroError, NitroTrustDecision,
};
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

/// `ecdsa-with-SHA384` — the signature algorithm used by the AWS Nitro PKI.
const ECDSA_WITH_SHA384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// Production AWS Nitro certificate trust boundary.
///
/// Validates the attestation document's certificate chain against
/// the embedded AWS Nitro Root CA (G1). The root CA DER is embedded
/// at compile time and its SHA-256 fingerprint is pinned.
pub struct AwsNitroTrustBoundary {
    root_ca_der: Vec<u8>,
}

impl AwsNitroTrustBoundary {
    /// AWS Nitro Root CA SHA-256 fingerprint (official AWS root G1).
    pub const ROOT_CA_FINGERPRINT: &str =
        "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";

    /// Create a new trust boundary with the embedded AWS Nitro Root CA.
    pub fn new() -> Self {
        Self {
            root_ca_der: include_bytes!("aws_nitro_root_g1.der").to_vec(),
        }
    }

    /// Create with a custom root CA (GovCloud, China partition, etc.).
    pub fn with_root_ca(root_ca_der: Vec<u8>) -> Self {
        Self { root_ca_der }
    }

    /// Verify that the embedded root CA matches the pinned fingerprint.
    fn verify_root_fingerprint(&self) -> Result<(), NitroError> {
        let hash = Sha256::digest(&self.root_ca_der);
        let fp = hex::encode(hash);
        if fp != Self::ROOT_CA_FINGERPRINT {
            return Err(NitroError::InvalidCaBundle);
        }
        Ok(())
    }
}

impl Default for AwsNitroTrustBoundary {
    fn default() -> Self {
        Self::new()
    }
}

impl NitroCertificateTrustBoundary for AwsNitroTrustBoundary {
    fn verify_certificate_path(
        &self,
        document: &NitroAttestationDocument,
    ) -> Result<NitroTrustDecision, NitroError> {
        self.verify_root_fingerprint()?;

        let root =
            Certificate::from_der(&self.root_ca_der).map_err(|_| NitroError::InvalidCaBundle)?;
        let leaf = Certificate::from_der(document.certificate_der())
            .map_err(|_| NitroError::InvalidCertificate)?;

        // AWS encodes the CA bundle root-first: [root, intermediate_N, ..., intermediate_1].
        let mut bundle: Vec<Certificate> = document
            .ca_bundle_root_first()
            .map(Certificate::from_der)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| NitroError::InvalidCaBundle)?;

        // Root + at least one intermediate is the minimum for a non-degenerate
        // production chain. (A single self-signed leaf is not an AWS PKI chain.)
        if bundle.len() < 2 {
            return Err(NitroError::InvalidCaBundle);
        }

        // The supplied root must byte-match the pinned embedded root. This is
        // the actual root-of-trust pin; the fingerprint check above is defense
        // in depth against an incorrectly embedded root.
        let bundle_root = bundle.remove(0);
        if bundle_root
            .to_der()
            .map_err(|_| NitroError::InvalidCaBundle)?
            != self.root_ca_der
        {
            return Err(NitroError::InvalidCaBundle);
        }

        // Remaining entries are intermediates, root-first → reverse to leaf-first.
        bundle.reverse();

        let mut chain = Vec::with_capacity(bundle.len() + 2);
        chain.push(leaf);
        chain.extend(bundle);
        chain.push(root);

        for pair in chain.windows(2) {
            verify_certificate_signature(&pair[0], &pair[1])?;
        }

        Ok(NitroTrustDecision::Verified)
    }
}

/// Cryptographically verify `child` was signed by `parent` (ECDSA P-384 over
/// the DER-encoded TBS, `ecdsa-with-SHA384` only).
fn verify_certificate_signature(
    child: &Certificate,
    parent: &Certificate,
) -> Result<(), NitroError> {
    if child.signature_algorithm().oid != ECDSA_WITH_SHA384_OID {
        return Err(NitroError::InvalidCertificate);
    }

    let tbs_der = child
        .tbs_certificate()
        .to_der()
        .map_err(|_| NitroError::InvalidCertificate)?;
    let signature_bytes = child
        .signature()
        .as_bytes()
        .ok_or(NitroError::SignatureInvalid)?;
    let parent_spki = parent.tbs_certificate().subject_public_key_info();
    let parent_key = parent_spki
        .subject_public_key
        .as_bytes()
        .ok_or(NitroError::InvalidCertificate)?;
    let verifying_key =
        VerifyingKey::from_sec1_bytes(parent_key).map_err(|_| NitroError::InvalidCertificate)?;
    // X.509 stores the ECDSA signature as a DER-encoded `SEQUENCE { r, s }`;
    // `Signature::from_der` parses that (unlike `from_slice`, which expects the
    // fixed 96-byte raw r||s form).
    let signature =
        Signature::from_der(signature_bytes).map_err(|_| NitroError::SignatureInvalid)?;

    verifying_key
        .verify(&tbs_der, &signature)
        .map_err(|_| NitroError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_boundary_constructs() {
        let tb = AwsNitroTrustBoundary::new();
        assert!(tb.verify_root_fingerprint().is_ok());
    }

    #[test]
    fn root_ca_fingerprint_self_consistent() {
        let tb = AwsNitroTrustBoundary::new();
        let hash = Sha256::digest(&tb.root_ca_der);
        assert_eq!(
            hex::encode(hash),
            AwsNitroTrustBoundary::ROOT_CA_FINGERPRINT
        );
    }

    #[test]
    fn custom_root_ca_works() {
        let custom = vec![0x30, 0x00]; // Invalid DER, but fine for construction
        let tb = AwsNitroTrustBoundary::with_root_ca(custom);
        assert!(tb.verify_root_fingerprint().is_err()); // Won't match pinned fingerprint
    }

    #[test]
    fn default_uses_embedded_root() {
        let tb = AwsNitroTrustBoundary::default();
        assert!(tb.verify_root_fingerprint().is_ok());
    }

    #[test]
    fn embedded_root_is_self_signed_es384() {
        // The AWS Nitro Root CA G1 is self-signed: its own signature must
        // verify against its own public key. This exercises the cryptographic
        // chain-verification path against a real (AWS) certificate.
        let tb = AwsNitroTrustBoundary::new();
        let root = Certificate::from_der(&tb.root_ca_der).expect("embedded root parses");
        assert_eq!(
            root.signature_algorithm().oid,
            ECDSA_WITH_SHA384_OID,
            "root signature algorithm must be ecdsa-with-SHA384"
        );
        verify_certificate_signature(&root, &root).expect("root self-signature verifies");
    }
}
