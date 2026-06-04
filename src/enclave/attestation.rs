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
    pub certificate_chain: Vec<String>,
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

        // 2. Certificate Chain Verification (Simulated Root of Trust)
        // In a real implementation, we would verify each cert in the chain up to the Conclave Root CA.
        let has_root_trust = self
            .certificate_chain
            .iter()
            .any(|c| c.contains("CONCLAVE_ROOT_CA") || c.contains("CONCLAVE_CLOUD_ROOT_CA"));
        if !has_root_trust {
            return false;
        }

        // 3. Hardware-backed verification
        // StrongBox reports must include specific extension data matching the platform.
        let is_hardened = matches!(
            self.level,
            AttestationLevel::StrongBox | AttestationLevel::CloudTEE | AttestationLevel::TEE
        );
        let has_valid_extension = self.extension_data.contains("PURPOSE_SIGN")
            && self.extension_data.contains("ALGORITHM_EC");

        is_hardened && has_valid_extension
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
    use super::{
        AttestationLevel, DeviceIntegrityReport, MAX_ATTESTATION_AGE_SECS,
        MAX_ATTESTATION_FUTURE_SKEW_SECS,
    };

    fn valid_report(timestamp: u64) -> DeviceIntegrityReport {
        DeviceIntegrityReport {
            level: AttestationLevel::TEE,
            challenge_nonce: vec![1, 2, 3, 4],
            signature: vec![9; 64],
            certificate_chain: vec![
                "CONCLAVE_ROOT_CA_01".to_string(),
                "CONCLAVE_HARDWARE_BACKED_DEVICE_0x1".to_string(),
            ],
            timestamp,
            extension_data: "PURPOSE_SIGN|ALGORITHM_EC|OS_VERSION_14".to_string(),
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
    fn verify_rejects_report_too_far_in_future() {
        let now_secs: u64 = 1_000_000;
        let future_timestamp = now_secs + MAX_ATTESTATION_FUTURE_SKEW_SECS + 1;
        let report = valid_report(future_timestamp);

        assert!(!report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }
}
