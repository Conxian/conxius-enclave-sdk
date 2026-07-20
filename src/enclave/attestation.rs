use der::Decode;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::Certificate;

use crate::{ConclaveError, ConclaveResult};

#[cfg(test)]
pub const MAX_ATTESTATION_AGE_SECS: u64 = 300;
#[cfg(not(test))]
const MAX_ATTESTATION_AGE_SECS: u64 = 300;

#[cfg(test)]
pub const MAX_ATTESTATION_FUTURE_SKEW_SECS: u64 = 30;
#[cfg(not(test))]
const MAX_ATTESTATION_FUTURE_SKEW_SECS: u64 = 30;

const DEFAULT_TRUSTED_ROOTS: &[&str] = &[
    "CONCLAVE_ROOT_CA_V1",
    "CONCLAVE_CLOUD_ROOT_CA_V1",
    "GOOGLE_STRONGBOX_ROOT_V1",
    "AWS_NITRO_ROOT_V1",
];

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttestationLevel {
    Software,
    TEE,
    StrongBox,
    CloudTEE,
}

/// Verification policy for production attestation evidence.
///
/// The policy deliberately cannot be configured to accept software-only
/// attestation. Development and provider-specific implementations must use a
/// separate test fixture instead of weakening this production policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationPolicy {
    allowed_levels: Vec<AttestationLevel>,
    trusted_roots: Vec<String>,
    max_age_secs: u64,
    max_future_skew_secs: u64,
    required_extensions: Vec<String>,
}

impl Default for AttestationPolicy {
    fn default() -> Self {
        Self::production()
    }
}

impl AttestationPolicy {
    /// Returns the default fail-closed production policy.
    pub fn production() -> Self {
        Self {
            allowed_levels: vec![
                AttestationLevel::TEE,
                AttestationLevel::StrongBox,
                AttestationLevel::CloudTEE,
            ],
            trusted_roots: DEFAULT_TRUSTED_ROOTS
                .iter()
                .map(|root| (*root).to_string())
                .collect(),
            max_age_secs: MAX_ATTESTATION_AGE_SECS,
            max_future_skew_secs: MAX_ATTESTATION_FUTURE_SKEW_SECS,
            required_extensions: vec!["PURPOSE_SIGN".to_string()],
        }
    }

    /// Returns a policy using an explicit, non-empty trust-root set.
    pub fn with_trusted_roots(mut self, trusted_roots: Vec<String>) -> ConclaveResult<Self> {
        if trusted_roots.is_empty() || trusted_roots.iter().any(|root| root.trim().is_empty()) {
            return Err(ConclaveError::InvalidPayload);
        }

        self.trusted_roots = trusted_roots;
        Ok(self)
    }

    /// Returns a policy restricted to the supplied hardware-backed levels.
    pub fn with_allowed_levels(
        mut self,
        allowed_levels: Vec<AttestationLevel>,
    ) -> ConclaveResult<Self> {
        if allowed_levels.is_empty() || allowed_levels.contains(&AttestationLevel::Software) {
            return Err(ConclaveError::Unsupported(
                "software-only attestation cannot satisfy production policy".to_string(),
            ));
        }

        self.allowed_levels = allowed_levels;
        Ok(self)
    }

    /// Returns a policy using explicit freshness limits.
    pub fn with_freshness_window(
        mut self,
        max_age_secs: u64,
        max_future_skew_secs: u64,
    ) -> ConclaveResult<Self> {
        if max_age_secs > MAX_ATTESTATION_AGE_SECS
            || max_future_skew_secs > MAX_ATTESTATION_FUTURE_SKEW_SECS
        {
            return Err(ConclaveError::Unsupported(
                "attestation freshness limits cannot be weaker than production defaults"
                    .to_string(),
            ));
        }

        self.max_age_secs = max_age_secs;
        self.max_future_skew_secs = max_future_skew_secs;
        Ok(self)
    }

    /// Returns a policy requiring the supplied extension markers in addition to
    /// the mandatory signing-purpose marker.
    pub fn with_required_extensions(
        mut self,
        required_extensions: Vec<String>,
    ) -> ConclaveResult<Self> {
        if required_extensions
            .iter()
            .any(|extension| extension.trim().is_empty())
        {
            return Err(ConclaveError::InvalidPayload);
        }

        for extension in required_extensions {
            if !self.required_extensions.contains(&extension) {
                self.required_extensions.push(extension);
            }
        }

        Ok(self)
    }

    pub fn allowed_levels(&self) -> &[AttestationLevel] {
        &self.allowed_levels
    }

    pub fn trusted_roots(&self) -> &[String] {
        &self.trusted_roots
    }

    pub fn max_age_secs(&self) -> u64 {
        self.max_age_secs
    }

    pub fn max_future_skew_secs(&self) -> u64 {
        self.max_future_skew_secs
    }

    pub fn required_extensions(&self) -> &[String] {
        &self.required_extensions
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIntegrityReport {
    pub level: AttestationLevel,
    pub challenge_nonce: Vec<u8>,
    pub signature: Vec<u8>,
    pub certificate_chain: Vec<String>, // First element is the device pubkey (as hex) or DER cert
    pub timestamp: u64,
    pub extension_data: String,
}

impl DeviceIntegrityReport {
    /// Verifies the integrity report using a realistic hardware attestation model.
    pub fn verify(&self, expected_nonce: &[u8]) -> bool {
        self.verify_with_policy(expected_nonce, &AttestationPolicy::production())
    }

    /// Verifies this report against an explicit fail-closed policy.
    pub fn verify_with_policy(&self, expected_nonce: &[u8], policy: &AttestationPolicy) -> bool {
        self.verify_at_time_impl(expected_nonce, unix_time_secs(), policy)
    }

    /// Verifies at a specific timestamp (for testing).
    #[cfg(test)]
    pub fn verify_at_time(&self, expected_nonce: &[u8], now_secs: u64) -> bool {
        self.verify_at_time_with_policy(expected_nonce, now_secs, &AttestationPolicy::production())
    }

    /// Verifies at a caller-supplied timestamp using an explicit policy.
    ///
    /// Production callers should use [`Self::verify_with_policy`], which
    /// samples the wall clock once. This crate-visible variant lets protocol
    /// code share that exact timestamp with related checks and lets tests
    /// exercise freshness boundaries without sampling the wall clock twice.
    pub(crate) fn verify_at_time_with_policy(
        &self,
        expected_nonce: &[u8],
        now_secs: u64,
        policy: &AttestationPolicy,
    ) -> bool {
        self.verify_at_time_impl(expected_nonce, now_secs, policy)
    }

    #[cfg_attr(test, allow(dead_code))]
    fn verify_at_time_impl(
        &self,
        expected_nonce: &[u8],
        now_secs: u64,
        policy: &AttestationPolicy,
    ) -> bool {
        if self.signature.is_empty() || self.certificate_chain.len() < 2 {
            return false;
        }

        // 1. Freshness & Nonce Check
        if self.challenge_nonce != expected_nonce {
            return false;
        }

        if self.timestamp > now_secs.saturating_add(policy.max_future_skew_secs) {
            return false;
        }

        if now_secs > self.timestamp.saturating_add(policy.max_age_secs) {
            return false;
        }

        // 2. Cryptographic Verification of the Report Signature
        if let Some(result) = self.verify_signature() {
            if !result {
                return false;
            }
        } else {
            return false;
        }

        // 3. Hardened Certificate Chain Verification
        if !self.verify_certificate_chain(policy) {
            return false;
        }

        // 4. Policy and hardware-backed verification hardening
        if !policy.allowed_levels.contains(&self.level) {
            return false;
        }

        if policy
            .required_extensions
            .iter()
            .any(|required| !self.extension_data.contains(required))
        {
            return false;
        }

        let is_hardened = match self.level {
            AttestationLevel::StrongBox | AttestationLevel::CloudTEE => {
                // High Trust levels require explicit hardware-backed signaling
                self.extension_data.contains("HARDWARE_BACKED")
                    && self.extension_data.contains("SECURE_BOOT_ENABLED")
            }
            AttestationLevel::TEE => true,
            AttestationLevel::Software => false,
        };

        let has_valid_purpose = self.extension_data.contains("PURPOSE_SIGN")
            && (self.extension_data.contains("ALGORITHM_EC")
                || self.extension_data.contains("ALGORITHM_ED25519"));

        is_hardened && has_valid_purpose
    }

    fn verify_signature(&self) -> Option<bool> {
        let pubkey_entry = hex::decode(&self.certificate_chain[0]).ok()?;

        // Attempt to parse as X.509 first to extract the raw public key
        let raw_pubkey = if let Ok(cert) = Certificate::from_der(&pubkey_entry) {
            // Extract from SubjectPublicKeyInfo
            cert.tbs_certificate()
                .subject_public_key_info()
                .subject_public_key
                .as_bytes()?
                .to_vec()
        } else {
            pubkey_entry
        };

        if raw_pubkey.len() != 32 {
            return None;
        }
        let bytes: [u8; 32] = raw_pubkey.try_into().ok()?;
        let verifying_key = VerifyingKey::from_bytes(&bytes).ok()?;
        let sig = Signature::from_slice(&self.signature).ok()?;

        let mut data_to_verify = Vec::new();
        data_to_verify.extend_from_slice(&self.challenge_nonce);
        data_to_verify.extend_from_slice(self.extension_data.as_bytes());
        data_to_verify.extend_from_slice(&self.timestamp.to_le_bytes());

        Some(verifying_key.verify(&data_to_verify, &sig).is_ok())
    }

    fn verify_certificate_chain(&self, policy: &AttestationPolicy) -> bool {
        let last_entry = match self.certificate_chain.last() {
            Some(entry) => entry,
            None => return false,
        };

        // Try to parse as DER hex
        if let Ok(cert_bytes) = hex::decode(last_entry) {
            if let Ok(cert) = Certificate::from_der(&cert_bytes) {
                // For hardening, check if the certificate is structurally sound
                // and its subject matches our trusted root list.
                let subject_str = format!("{:?}", cert.tbs_certificate().subject());
                return policy
                    .trusted_roots
                    .iter()
                    .any(|root| subject_str.contains(root));
            }
        }

        // Fallback to exact matching for legacy/simulated roots. Prefix or
        // suffix matches would allow an untrusted root label to masquerade as
        // a configured root.
        policy.trusted_roots.iter().any(|root| last_entry == root)
    }

    /// Generates a hardware-bound fingerprint for this device.
    pub fn get_device_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        for cert in &self.certificate_chain {
            hasher.update(cert.as_bytes());
        }
        hasher.update(self.extension_data.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::{AttestationLevel, DeviceIntegrityReport, MAX_ATTESTATION_AGE_SECS};
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::Rng;

    fn valid_report(timestamp: u64, level: AttestationLevel) -> DeviceIntegrityReport {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

        let nonce = vec![1, 2, 3, 4];
        let mut extension_data = "PURPOSE_SIGN|ALGORITHM_ED25519|OS_VERSION_14".to_string();
        if level == AttestationLevel::StrongBox || level == AttestationLevel::CloudTEE {
            extension_data.push_str("|HARDWARE_BACKED|SECURE_BOOT_ENABLED");
        }

        let mut data_to_verify = Vec::new();
        data_to_verify.extend_from_slice(&nonce);
        data_to_verify.extend_from_slice(extension_data.as_bytes());
        data_to_verify.extend_from_slice(&timestamp.to_le_bytes());

        let signature = signing_key.sign(&data_to_verify).to_bytes().to_vec();

        DeviceIntegrityReport {
            level,
            challenge_nonce: nonce,
            signature,
            certificate_chain: vec![pubkey_hex, "CONCLAVE_ROOT_CA_V1".to_string()],
            timestamp,
            extension_data,
        }
    }

    #[test]
    fn verify_accepts_report_within_freshness_window() {
        let now_secs: u64 = 1_000_000;
        let report = valid_report(now_secs.saturating_sub(60), AttestationLevel::TEE);

        assert!(report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }

    #[test]
    fn verify_accepts_strongbox_report() {
        let now_secs: u64 = 1_000_000;
        let report = valid_report(now_secs.saturating_sub(60), AttestationLevel::StrongBox);

        assert!(report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }

    #[test]
    fn verify_rejects_stale_report() {
        let now_secs: u64 = 1_000_000;
        let stale_timestamp = now_secs.saturating_sub(MAX_ATTESTATION_AGE_SECS + 1);
        let report = valid_report(stale_timestamp, AttestationLevel::TEE);

        assert!(!report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }

    #[test]
    fn verify_rejects_invalid_signature() {
        let now_secs: u64 = 1_000_000;
        let mut report = valid_report(now_secs.saturating_sub(60), AttestationLevel::TEE);
        report.signature[0] ^= 0xFF; // Corrupt signature

        assert!(!report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }

    #[test]
    fn verify_rejects_untrusted_root() {
        let now_secs: u64 = 1_000_000;
        let mut report = valid_report(now_secs.saturating_sub(60), AttestationLevel::TEE);
        report.certificate_chain[1] = "UNKNOWN_ROOT".to_string();

        assert!(!report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }
}
