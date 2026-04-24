use crate::enclave::EnclaveManager;
use crate::ConclaveResult;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Personal Sovereign Identity (PSI) service for hardware-backed user identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProfile {
    pub did: String,
    pub public_key: String,
    pub hardware_attestation: String,
}

pub struct IdentityManager {
    enclave: Arc<dyn EnclaveManager>,
}

impl IdentityManager {
    pub fn new(enclave: Arc<dyn EnclaveManager>) -> Self {
        Self { enclave }
    }

    /// Generates a hardware-backed personal identity (DID).
    pub fn create_identity(&self) -> ConclaveResult<IdentityProfile> {
        let public_key = self.enclave.get_public_key("m/44'/5757'/0'/0/identity")?;

        // Simple DID format: did:conxian:<pubkey_hex>
        let did = format!("did:conxian:{}", public_key);

        Ok(IdentityProfile {
            did,
            public_key,
            hardware_attestation: "HW_TEE_v1".to_string(),
        })
    }
}
