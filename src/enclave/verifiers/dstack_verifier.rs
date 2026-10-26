//! Phala dstack TEE Attestation Verifier (Phase 3).
//!
//! Provides hardware-backed confidential computing attestation verification
//! for Intel SGX / TDX and AMD SEV-SNP workloads running inside Phala's
//! open-source dstack TEE framework.
//!
//! # References
//! - Phala dstack OS: https://github.com/Phala-Network/dstack
//! - Intel SGX DCAP Quote Format: https://www.intel.com/content/www/us/en/developer/articles/technical/quote-verification-in-sgx-dcap.html

use crate::enclave::proofs::{
    ProofEnvelope, ProofKind, ProofVerificationContext, ProofVerifier, ProofVerifierStatus,
    VerifiedProofReceipt,
};
use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PHALA_DSTACK_VERIFIER_ID: &str = "conxian.trust.phala.dstack.v1";
pub const DSTACK_BINDING_DOMAIN: &str = "CONXIAN-DSTACK-BINDING/v1";

/// Parsed dstack TEE attestation document representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DstackAttestationDocument {
    pub app_id: String,
    pub mrenclave: [u8; 32],
    pub mrsigner: [u8; 32],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtmr0: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtmr1: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtmr2: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtmr3: Option<Vec<u8>>,
    pub report_data: Vec<u8>,
    pub quote_bytes: Vec<u8>,
    pub timestamp: u64,
}

impl DstackAttestationDocument {
    /// Parse dstack attestation document from JSON bytes.
    pub fn parse(bytes: &[u8]) -> ConclaveResult<Self> {
        if bytes.is_empty() {
            return Err(ConclaveError::Attestation(
                "dstack evidence payload is empty".to_string(),
            ));
        }

        serde_json::from_slice::<Self>(bytes).map_err(|e| {
            ConclaveError::Attestation(format!(
                "Failed to parse dstack attestation document JSON: {e}"
            ))
        })
    }

    /// Verifies the structural integrity and minimum header bounds of the attached quote.
    pub fn verify_quote_structure(&self) -> ConclaveResult<()> {
        if self.quote_bytes.is_empty() {
            return Err(ConclaveError::Attestation(
                "dstack quote bytes cannot be empty".to_string(),
            ));
        }

        // Intel DCAP / TDX quotes require at least a 48-byte header
        if self.quote_bytes.len() < 48 {
            return Err(ConclaveError::Attestation(format!(
                "dstack quote too short: expected at least 48 bytes, got {}",
                self.quote_bytes.len()
            )));
        }

        // Verify quote version (version 4 for SGX DCAP or version 5 for TDX)
        let version = u16::from_le_bytes([self.quote_bytes[0], self.quote_bytes[1]]);
        if version != 4 && version != 5 {
            return Err(ConclaveError::Attestation(format!(
                "Unsupported dstack quote version: {version}"
            )));
        }

        Ok(())
    }
}

/// Measurement and policy constraints for dstack container applications.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DstackAppPolicy {
    pub expected_mrenclave: Option<[u8; 32]>,
    pub expected_mrsigner: Option<[u8; 32]>,
    pub min_isv_svn: u16,
    pub expected_isv_prod_id: Option<u16>,
    pub expected_rtmr0: Option<Vec<u8>>,
}

impl Default for DstackAppPolicy {
    fn default() -> Self {
        Self {
            expected_mrenclave: None,
            expected_mrsigner: None,
            min_isv_svn: 1,
            expected_isv_prod_id: None,
            expected_rtmr0: None,
        }
    }
}

impl DstackAppPolicy {
    pub fn evaluate(&self, doc: &DstackAttestationDocument) -> ConclaveResult<()> {
        if doc.isv_svn < self.min_isv_svn {
            return Err(ConclaveError::Attestation(format!(
                "dstack ISV SVN too low: required min {}, got {}",
                self.min_isv_svn, doc.isv_svn
            )));
        }

        if let Some(expected_prod) = self.expected_isv_prod_id {
            if doc.isv_prod_id != expected_prod {
                return Err(ConclaveError::Attestation(format!(
                    "dstack ISV product ID mismatch: expected {expected_prod}, got {}",
                    doc.isv_prod_id
                )));
            }
        }

        if let Some(expected_mrenclave) = self.expected_mrenclave {
            if doc.mrenclave != expected_mrenclave {
                return Err(ConclaveError::Attestation(format!(
                    "dstack MRENCLAVE mismatch: expected {}, got {}",
                    hex::encode(expected_mrenclave),
                    hex::encode(doc.mrenclave)
                )));
            }
        }

        if let Some(expected_mrsigner) = self.expected_mrsigner {
            if doc.mrsigner != expected_mrsigner {
                return Err(ConclaveError::Attestation(format!(
                    "dstack MRSIGNER mismatch: expected {}, got {}",
                    hex::encode(expected_mrsigner),
                    hex::encode(doc.mrsigner)
                )));
            }
        }

        if let Some(expected_rtmr0) = &self.expected_rtmr0 {
            match &doc.rtmr0 {
                Some(rtmr0) if rtmr0 == expected_rtmr0 => {}
                _ => {
                    return Err(ConclaveError::Attestation(
                        "dstack RTMR0 measurement mismatch".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Release binding connecting operation context, purpose, audience, and nonce
/// to dstack report_data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DstackReleaseBinding {
    pub operation_digest: [u8; 32],
    pub purpose: String,
    pub audience: String,
    pub expiration_secs: u64,
    pub nonce_hash: [u8; 32],
}

impl DstackReleaseBinding {
    pub fn new(
        operation_digest: [u8; 32],
        purpose: impl Into<String>,
        audience: impl Into<String>,
        expiration_secs: u64,
        nonce_hash: [u8; 32],
    ) -> ConclaveResult<Self> {
        let purpose = purpose.into();
        let audience = audience.into();
        if purpose.is_empty() || audience.is_empty() {
            return Err(ConclaveError::InvalidPayload);
        }

        Ok(Self {
            operation_digest,
            purpose,
            audience,
            expiration_secs,
            nonce_hash,
        })
    }

    pub fn canonical_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(DSTACK_BINDING_DOMAIN.as_bytes());
        hasher.update(self.operation_digest);
        hasher.update((self.purpose.len() as u32).to_be_bytes());
        hasher.update(self.purpose.as_bytes());
        hasher.update((self.audience.len() as u32).to_be_bytes());
        hasher.update(self.audience.as_bytes());
        hasher.update(self.expiration_secs.to_be_bytes());
        hasher.update(self.nonce_hash);
        hasher.finalize().into()
    }
}

/// Production Phala dstack TEE attestation verifier.
pub struct PhalaDstackVerifier {
    policy: DstackAppPolicy,
    verifier_id: String,
}

impl PhalaDstackVerifier {
    pub fn new(policy: DstackAppPolicy) -> Self {
        Self {
            policy,
            verifier_id: PHALA_DSTACK_VERIFIER_ID.to_string(),
        }
    }

    pub fn policy(&self) -> &DstackAppPolicy {
        &self.policy
    }
}

impl Default for PhalaDstackVerifier {
    fn default() -> Self {
        Self::new(DstackAppPolicy::default())
    }
}

impl ProofVerifier for PhalaDstackVerifier {
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
        let doc = DstackAttestationDocument::parse(&envelope.evidence)?;

        // Verify quote structure
        doc.verify_quote_structure()?;

        // Evaluate application policy
        self.policy.evaluate(&doc)?;

        // Freshness check
        if context.now_secs > doc.timestamp + context.max_age_secs {
            return Err(ConclaveError::Attestation(
                "dstack attestation report expired".to_string(),
            ));
        }
        if doc.timestamp > context.now_secs + context.max_future_skew_secs {
            return Err(ConclaveError::Attestation(
                "dstack attestation report timestamp from the future".to_string(),
            ));
        }

        // Construct expected release binding and compare against report_data
        let nonce_hash: [u8; 32] = Sha256::digest(&context.nonce).into();
        let release_binding = DstackReleaseBinding::new(
            context.operation_digest,
            context.purpose.clone(),
            context.audience.clone(),
            context.now_secs + context.max_age_secs,
            nonce_hash,
        )?;

        let expected_digest = release_binding.canonical_digest();
        if doc.report_data.len() < 32 || doc.report_data[..32] != expected_digest {
            return Err(ConclaveError::Attestation(
                "dstack report_data does not match operation release binding".to_string(),
            ));
        }

        VerifiedProofReceipt::from_verified_envelope(envelope, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_valid_doc(now_secs: u64, report_data_digest: [u8; 32]) -> DstackAttestationDocument {
        let mut quote_bytes = vec![0u8; 64];
        // Version 4 header (0x0004 LE)
        quote_bytes[0] = 4;
        quote_bytes[1] = 0;

        let mut report_data = vec![0u8; 64];
        report_data[..32].copy_from_slice(&report_data_digest);

        DstackAttestationDocument {
            app_id: "app_0x42".to_string(),
            mrenclave: [0x11u8; 32],
            mrsigner: [0x22u8; 32],
            isv_prod_id: 1,
            isv_svn: 2,
            rtmr0: Some(vec![0x33u8; 48]),
            rtmr1: None,
            rtmr2: None,
            rtmr3: None,
            report_data,
            quote_bytes,
            timestamp: now_secs,
        }
    }

    #[test]
    fn verifier_constructs() {
        let verifier = PhalaDstackVerifier::default();
        assert_eq!(verifier.kind(), ProofKind::Tee);
        assert_eq!(verifier.verifier_id(), PHALA_DSTACK_VERIFIER_ID);
        assert_eq!(verifier.status(), ProofVerifierStatus::Available);
    }

    #[test]
    fn successful_verification() {
        let now_secs = 1_700_000_000;
        let context = ProofVerificationContext {
            operation_digest: [0xA5u8; 32],
            purpose: "TRANSACTION".to_string(),
            audience: "conxian".to_string(),
            nonce: vec![0x12u8; 32],
            now_secs,
            max_age_secs: 300,
            max_future_skew_secs: 60,
        };

        let nonce_hash: [u8; 32] = Sha256::digest(&context.nonce).into();
        let release_binding = DstackReleaseBinding::new(
            context.operation_digest,
            context.purpose.clone(),
            context.audience.clone(),
            now_secs + context.max_age_secs,
            nonce_hash,
        )
        .unwrap();

        let doc = sample_valid_doc(now_secs, release_binding.canonical_digest());
        let evidence = serde_json::to_vec(&doc).unwrap();

        let envelope = ProofEnvelope {
            version: 1,
            kind: ProofKind::Tee,
            proof_id: "test-dstack-proof-1".to_string(),
            verifier_id: PHALA_DSTACK_VERIFIER_ID.to_string(),
            operation_digest: context.operation_digest,
            purpose: context.purpose.clone(),
            audience: context.audience.clone(),
            nonce: context.nonce.clone(),
            issued_at: now_secs,
            expires_at: now_secs + 300,
            evidence,
        };

        let policy = DstackAppPolicy {
            expected_mrenclave: Some([0x11u8; 32]),
            expected_mrsigner: Some([0x22u8; 32]),
            min_isv_svn: 1,
            expected_isv_prod_id: Some(1),
            expected_rtmr0: Some(vec![0x33u8; 48]),
        };

        let verifier = PhalaDstackVerifier::new(policy);
        let receipt = verifier.verify(&envelope, &context).unwrap();
        assert_eq!(receipt.proof_id(), "test-dstack-proof-1");
    }

    #[test]
    fn policy_mrenclave_mismatch_fails() {
        let now_secs = 1_700_000_000;
        let mut doc = sample_valid_doc(now_secs, [0u8; 32]);
        doc.mrenclave = [0xFFu8; 32];

        let policy = DstackAppPolicy {
            expected_mrenclave: Some([0x11u8; 32]),
            ..Default::default()
        };

        assert!(policy.evaluate(&doc).is_err());
    }

    #[test]
    fn expired_timestamp_fails() {
        let now_secs = 1_700_000_000;
        let context = ProofVerificationContext {
            operation_digest: [0xA5u8; 32],
            purpose: "TRANSACTION".to_string(),
            audience: "conxian".to_string(),
            nonce: vec![0x12u8; 32],
            now_secs,
            max_age_secs: 300,
            max_future_skew_secs: 60,
        };

        let expired_doc = sample_valid_doc(now_secs - 500, [0u8; 32]);
        let evidence = serde_json::to_vec(&expired_doc).unwrap();

        let envelope = ProofEnvelope {
            version: 1,
            kind: ProofKind::Tee,
            proof_id: "test-expired".to_string(),
            verifier_id: PHALA_DSTACK_VERIFIER_ID.to_string(),
            operation_digest: context.operation_digest,
            purpose: context.purpose.clone(),
            audience: context.audience.clone(),
            nonce: context.nonce.clone(),
            issued_at: now_secs - 500,
            expires_at: now_secs,
            evidence,
        };

        let verifier = PhalaDstackVerifier::default();
        assert!(verifier.verify(&envelope, &context).is_err());
    }
}
