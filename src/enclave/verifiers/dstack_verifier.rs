//! Unavailable adapter and untrusted diagnostic types for Phala dstack research.
//!
//! Parsing and comparing claims never establishes hardware provenance. No DCAP
//! signature, collateral, TCB or dstack event-log backend is installed here.
//! See `docs/architecture/PHALA_DSTACK_INTEGRATION.md` for qualification gates.

use crate::enclave::proofs::{
    proof_verifier_unavailable, ProofEnvelope, ProofKind, ProofVerificationContext, ProofVerifier,
    ProofVerifierStatus, VerifiedProofReceipt,
};
use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Diagnostic limits match the proof envelope bounds; no production evidence is accepted.
const MAX_PROOF_EVIDENCE_BYTES: usize = 16 * 1024;
const MAX_PROOF_IDENTIFIER_BYTES: usize = 256;

pub const PHALA_DSTACK_VERIFIER_ID: &str = "conxian.trust.phala.dstack.v1";
pub const DSTACK_BINDING_DOMAIN: &str = "CONXIAN-DSTACK-BINDING/v1";

/// Local diagnostic schema, not an authenticated upstream dstack wire format.
/// All fields are untrusted caller claims, including measurements and time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    /// Parse bounded diagnostic JSON. Success does not verify attestation.
    pub fn parse(bytes: &[u8]) -> ConclaveResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PROOF_EVIDENCE_BYTES {
            return Err(ConclaveError::InvalidPayload);
        }
        let doc: Self = serde_json::from_slice(bytes).map_err(|_| ConclaveError::InvalidPayload)?;
        if !valid_identifier(&doc.app_id)
            || doc.report_data.len() != 64
            || doc.quote_bytes.len() < 48
            || doc.quote_bytes.len() > MAX_PROOF_EVIDENCE_BYTES
            || [&doc.rtmr0, &doc.rtmr1, &doc.rtmr2, &doc.rtmr3]
                .iter()
                .any(|rtmr| rtmr.as_ref().is_some_and(|value| value.len() != 48))
        {
            return Err(ConclaveError::InvalidPayload);
        }
        Ok(doc)
    }

    /// Diagnostic header check only; never verifies a quote or its body.
    /// Versions 3, 4 and 5 do not alone identify the hardware provider.
    pub fn verify_quote_structure(&self) -> ConclaveResult<()> {
        if self.quote_bytes.len() < 48 || self.quote_bytes.len() > MAX_PROOF_EVIDENCE_BYTES {
            return Err(ConclaveError::InvalidPayload);
        }
        let version = u16::from_le_bytes([self.quote_bytes[0], self.quote_bytes[1]]);
        if !matches!(version, 3..=5) {
            return Err(ConclaveError::InvalidPayload);
        }
        Ok(())
    }
}

/// Diagnostic constraints on untrusted claims; not an authorization policy.
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
    /// Compare local claims only. Success is not attestation verification.
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
/// to a candidate report_data digest. This does not authenticate report_data.
/// Expiration must be the fixed envelope expiry, never a moving verifier clock.
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
        if !valid_identifier(&purpose) || !valid_identifier(&audience) {
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

/// Reserved verifier route. Always unavailable until independently qualified.
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
        ProofVerifierStatus::Unavailable
    }

    fn verify(
        &self,
        _envelope: &ProofEnvelope,
        _context: &ProofVerificationContext,
    ) -> ConclaveResult<VerifiedProofReceipt> {
        Err(proof_verifier_unavailable())
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROOF_IDENTIFIER_BYTES
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_diagnostic_doc(
        now_secs: u64,
        report_data_digest: [u8; 32],
    ) -> DstackAttestationDocument {
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
    fn diagnostic_parser_enforces_bounds() {
        let doc = sample_diagnostic_doc(1, [0; 32]);
        let bytes = serde_json::to_vec(&doc).unwrap();
        assert_eq!(DstackAttestationDocument::parse(&bytes).unwrap(), doc);
        assert!(
            DstackAttestationDocument::parse(&vec![b' '; MAX_PROOF_EVIDENCE_BYTES + 1]).is_err()
        );
        for length in [0, 47, 49] {
            let mut invalid = doc.clone();
            invalid.rtmr3 = Some(vec![0; length]);
            assert!(
                DstackAttestationDocument::parse(&serde_json::to_vec(&invalid).unwrap()).is_err()
            );
        }
        let mut invalid = doc.clone();
        invalid.report_data.truncate(32);
        assert!(DstackAttestationDocument::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
        let mut value = serde_json::to_value(&doc).unwrap();
        value["unknown"] = true.into();
        assert!(DstackAttestationDocument::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn binding_rejects_unbounded_or_control_identifiers() {
        for purpose in [
            String::new(),
            "a".repeat(MAX_PROOF_IDENTIFIER_BYTES + 1),
            "sign\n".into(),
        ] {
            assert!(DstackReleaseBinding::new([0; 32], purpose, "audience", 1, [0; 32]).is_err());
        }
    }

    #[test]
    fn verifier_constructs() {
        let verifier = PhalaDstackVerifier::default();
        assert_eq!(verifier.kind(), ProofKind::Tee);
        assert_eq!(verifier.verifier_id(), PHALA_DSTACK_VERIFIER_ID);
        assert_eq!(verifier.status(), ProofVerifierStatus::Unavailable);
    }

    #[test]
    fn unavailable_adapter_never_issues_receipt() {
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

        let doc = sample_diagnostic_doc(now_secs, release_binding.canonical_digest());
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
        assert_eq!(verifier.status(), ProofVerifierStatus::Unavailable);
        assert!(matches!(
            verifier.verify(&envelope, &context),
            Err(ConclaveError::Unsupported(_))
        ));
    }

    #[test]
    fn policy_mrenclave_mismatch_fails() {
        let now_secs = 1_700_000_000;
        let mut doc = sample_diagnostic_doc(now_secs, [0u8; 32]);
        doc.mrenclave = [0xFFu8; 32];

        let policy = DstackAppPolicy {
            expected_mrenclave: Some([0x11u8; 32]),
            ..Default::default()
        };

        assert!(policy.evaluate(&doc).is_err());
    }

    #[test]
    fn unavailable_adapter_rejects_expired_input() {
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

        let expired_doc = sample_diagnostic_doc(now_secs - 500, [0u8; 32]);
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
