use crate::enclave::{
    nitro::{
        NitroAttestationDocument, NitroAttestationPolicy, NitroError, NitroPcrPolicy,
        NitroReleaseBinding,
    },
    proofs::{
        ProofEnvelope, ProofKind, ProofVerificationContext, ProofVerifier, ProofVerifierStatus,
        VerifiedProofReceipt,
    },
    verifiers::nitro_trust::AwsNitroTrustBoundary,
};
use crate::{ConclaveError, ConclaveResult};
use sha2::{Digest, Sha256};

/// Production AWS Nitro attestation verifier.
///
/// Plugs into the `ProofVerifierRegistry` for TEE proof kinds.
/// Uses the production `AwsNitroTrustBoundary` for certificate chain
/// validation against the AWS Nitro Root CA.
///
/// # Verification flow
/// 1. Extract evidence from `ProofEnvelope.evidence`
/// 2. Parse as CBOR/COSE attestation document
/// 3. Construct release binding from verification context
/// 4. Call `verify_offline()` — COSE signature + PCRs + freshness + trust chain
/// 5. Build `VerifiedProofReceipt`
pub struct AwsNitroVerifier {
    policy: NitroAttestationPolicy,
    trust_boundary: AwsNitroTrustBoundary,
    root_ca_der: Vec<u8>,
    verifier_id: String,
    kms_key_identifier_hash: [u8; 32],
    #[allow(dead_code)]
    max_age_ms: u64,
}

impl AwsNitroVerifier {
    pub const ROOT_CA_FINGERPRINT: &str = AwsNitroTrustBoundary::ROOT_CA_FINGERPRINT;
    pub const PCR_BYTES: usize = 48;

    pub fn new(expected_pcrs: Vec<(u8, [u8; Self::PCR_BYTES])>) -> Result<Self, NitroError> {
        let pcr_policy = NitroPcrPolicy::new(expected_pcrs)?;
        let policy = NitroAttestationPolicy::new(pcr_policy);
        Ok(Self {
            policy,
            trust_boundary: AwsNitroTrustBoundary::new(),
            root_ca_der: Self::embedded_root_ca(),
            verifier_id: "conxian.trust.aws.nitro.v1".into(),
            kms_key_identifier_hash: [0u8; 32],
            max_age_ms: 300_000,
        })
    }

    /// Configure explicit KMS key identifier hash for release key authorization binding.
    pub fn with_kms_key_identifier_hash(mut self, hash: [u8; 32]) -> Self {
        self.kms_key_identifier_hash = hash;
        self
    }

    /// Returns configured KMS key identifier hash.
    pub fn kms_key_identifier_hash(&self) -> &[u8; 32] {
        &self.kms_key_identifier_hash
    }

    pub fn verify_root_ca_fingerprint(&self) -> ConclaveResult<()> {
        let hash = Sha256::digest(&self.root_ca_der);
        let fp = hex::encode(hash);
        if fp != Self::ROOT_CA_FINGERPRINT {
            return Err(ConclaveError::Attestation(format!(
                "Root CA fingerprint mismatch: expected {}, got {}",
                Self::ROOT_CA_FINGERPRINT,
                fp
            )));
        }
        Ok(())
    }

    fn embedded_root_ca() -> Vec<u8> {
        include_bytes!("aws_nitro_root_g1.der").to_vec()
    }
}

impl ProofVerifier for AwsNitroVerifier {
    fn kind(&self) -> ProofKind {
        ProofKind::Tee
    }

    fn verifier_id(&self) -> &str {
        &self.verifier_id
    }

    fn status(&self) -> ProofVerifierStatus {
        ProofVerifierStatus::Available
    }

    fn verify(
        &self,
        envelope: &ProofEnvelope,
        context: &ProofVerificationContext,
    ) -> ConclaveResult<VerifiedProofReceipt> {
        let doc = NitroAttestationDocument::parse(&envelope.evidence).map_err(|e| {
            ConclaveError::Attestation(format!("Failed to parse Nitro attestation document: {e:?}"))
        })?;

        self.verify_root_ca_fingerprint()?;

        let now_ms = context.now_secs * 1000;
        let max_age_ms = context.max_age_secs * 1000;

        let release_binding = NitroReleaseBinding::new(
            context.operation_digest,
            context.purpose.clone(),
            self.kms_key_identifier_hash,
            1, // policy_version
            Sha256::digest(b"aws-nitro-v1").into(),
            now_ms + max_age_ms,
            Sha256::digest(&context.nonce).into(),
        )
        .map_err(|e| {
            ConclaveError::Attestation(format!("Failed to construct release binding: {e:?}"))
        })?;

        doc.verify_offline(
            &self.policy,
            &self.trust_boundary,
            now_ms,
            &context.nonce,
            context.operation_digest,
            &release_binding,
        )
        .map_err(|e| ConclaveError::Attestation(format!("Nitro attestation rejected: {e:?}")))?;

        VerifiedProofReceipt::from_verified_envelope(envelope, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nitro_verifier_constructs() {
        let pcr0_val = [0xABu8; 48];
        let v = AwsNitroVerifier::new(vec![(0u8, pcr0_val)]).expect("verifier constructs");
        assert_eq!(v.status(), ProofVerifierStatus::Available);
        assert_eq!(v.kind(), ProofKind::Tee);
        assert_eq!(v.verifier_id(), "conxian.trust.aws.nitro.v1");
        assert_eq!(v.kms_key_identifier_hash(), &[0u8; 32]);
    }

    #[test]
    fn nitro_verifier_binds_kms_key_hash() {
        let pcr0_val = [0xABu8; 48];
        let v_default = AwsNitroVerifier::new(vec![(0u8, pcr0_val)]).expect("verifier constructs");
        assert_eq!(v_default.kms_key_identifier_hash(), &[0u8; 32]);

        let custom_hash = [0x42u8; 32];
        let v_custom = v_default.with_kms_key_identifier_hash(custom_hash);
        assert_eq!(v_custom.kms_key_identifier_hash(), &custom_hash);
    }

    #[test]
    fn root_ca_fingerprint_matches() {
        let ca = AwsNitroVerifier::embedded_root_ca();
        let hash = Sha256::digest(&ca);
        assert_eq!(hex::encode(hash), AwsNitroVerifier::ROOT_CA_FINGERPRINT);
    }
}
