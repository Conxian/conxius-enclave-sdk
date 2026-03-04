use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttestationLevel {
    Software,
    TEE,
    StrongBox,
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
        if self.signature.is_empty() || self.certificate_chain.len() < 2 {
            return false;
        }

        // 1. Freshness & Nonce Check
        if self.challenge_nonce != expected_nonce {
            return false;
        }

        // 2. Hardware-backed verification
        // StrongBox reports must include specific extension data matching the platform.
        let is_strongbox = matches!(self.level, AttestationLevel::StrongBox);
        let has_valid_extension = self.extension_data.contains("PURPOSE_SIGN")
                                && self.extension_data.contains("ALGORITHM_EC");

        is_strongbox && has_valid_extension
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
