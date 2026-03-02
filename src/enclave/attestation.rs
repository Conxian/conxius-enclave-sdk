use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

impl DeviceIntegrityReport {
    pub fn verify(&self) -> bool {
        // Real implementation would verify the certificate chain and signature against root CAs
        !self.signature.is_empty()
    }
}
