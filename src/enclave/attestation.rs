use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_ATTESTATION_AGE_SECS: u64 = 300;
const MAX_ATTESTATION_FUTURE_SKEW_SECS: u64 = 30;

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttestationLevel {
    Software,
    TEE,
    StrongBox,
    CloudTEE,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIntegrityReport {
    pub level: AttestationLevel,
    pub challenge_nonce: Vec<u8>,
    pub signature: Vec<u8>,
    pub certificate_chain: Vec<String>, // First element is usually the device pubkey (as hex)
    pub timestamp: u64,
    pub extension_data: String,
}

impl DeviceIntegrityReport {
    /// Verifies the integrity report using a realistic hardware attestation model.
    pub fn verify(&self, expected_nonce: &[u8]) -> bool {
        self.verify_at_time(expected_nonce, unix_time_secs())
    }

    fn verify_at_time(&self, expected_nonce: &[u8], now_secs: u64) -> bool {
        if self.signature.is_empty() || self.certificate_chain.len() < 2 {
            return false;
        }

        // 1. Freshness & Nonce Check
        if self.challenge_nonce != expected_nonce {
            return false;
        }

        if self.timestamp > now_secs.saturating_add(MAX_ATTESTATION_FUTURE_SKEW_SECS) {
            return false;
        }

        if now_secs > self.timestamp.saturating_add(MAX_ATTESTATION_AGE_SECS) {
            return false;
        }

        // 2. Cryptographic Verification of the Report Signature
        // We assume the first entry in certificate_chain is the Hex-encoded Ed25519 public key of the device.
        if let Some(result) = self.verify_signature() {
            if !result {
                return false;
            }
        } else {
            return false;
        }

        // 3. Certificate Chain Verification (Simulated Root of Trust)
        let has_root_trust = self
            .certificate_chain
            .iter()
            .any(|c| c.contains("CONCLAVE_ROOT_CA") || c.contains("CONCLAVE_CLOUD_ROOT_CA"));
        if !has_root_trust {
            return false;
        }

        // 4. Hardware-backed verification
        let is_hardened = matches!(
            self.level,
            AttestationLevel::StrongBox | AttestationLevel::CloudTEE | AttestationLevel::TEE
        );
        let has_valid_extension = self.extension_data.contains("PURPOSE_SIGN")
            && (self.extension_data.contains("ALGORITHM_EC")
                || self.extension_data.contains("ALGORITHM_ED25519"));

        is_hardened && has_valid_extension
    }

    fn verify_signature(&self) -> Option<bool> {
        let pubkey_bytes = hex::decode(&self.certificate_chain[0]).ok()?;
        if pubkey_bytes.len() != 32 {
            return None;
        }
        let bytes: [u8; 32] = pubkey_bytes.try_into().ok()?;
        let verifying_key = VerifyingKey::from_bytes(&bytes).ok()?;
        let sig = Signature::from_slice(&self.signature).ok()?;

        let mut data_to_verify = Vec::new();
        data_to_verify.extend_from_slice(&self.challenge_nonce);
        data_to_verify.extend_from_slice(self.extension_data.as_bytes());
        data_to_verify.extend_from_slice(&self.timestamp.to_le_bytes());

        Some(verifying_key.verify(&data_to_verify, &sig).is_ok())
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

    fn valid_report(timestamp: u64) -> DeviceIntegrityReport {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

        let nonce = vec![1, 2, 3, 4];
        let extension_data = "PURPOSE_SIGN|ALGORITHM_ED25519|OS_VERSION_14".to_string();

        let mut data_to_verify = Vec::new();
        data_to_verify.extend_from_slice(&nonce);
        data_to_verify.extend_from_slice(extension_data.as_bytes());
        data_to_verify.extend_from_slice(&timestamp.to_le_bytes());

        let signature = signing_key.sign(&data_to_verify).to_bytes().to_vec();

        DeviceIntegrityReport {
            level: AttestationLevel::TEE,
            challenge_nonce: nonce,
            signature,
            certificate_chain: vec![pubkey_hex, "CONCLAVE_ROOT_CA_01".to_string()],
            timestamp,
            extension_data,
        }
    }

    #[test]
    fn verify_accepts_report_within_freshness_window() {
        let now_secs: u64 = 1_000_000;
        let report = valid_report(now_secs.saturating_sub(60));

        assert!(report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }

    #[test]
    fn verify_rejects_stale_report() {
        let now_secs: u64 = 1_000_000;
        let stale_timestamp = now_secs.saturating_sub(MAX_ATTESTATION_AGE_SECS + 1);
        let report = valid_report(stale_timestamp);

        assert!(!report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }

    #[test]
    fn verify_rejects_invalid_signature() {
        let now_secs: u64 = 1_000_000;
        let mut report = valid_report(now_secs.saturating_sub(60));
        report.signature[0] ^= 0xFF; // Corrupt signature

        assert!(!report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }
}
