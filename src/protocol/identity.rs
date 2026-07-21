use crate::enclave::EnclaveManager;
use crate::{ConclaveError, ConclaveResult};
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
    _enclave: Arc<dyn EnclaveManager>,
}

impl IdentityManager {
    pub fn new(enclave: Arc<dyn EnclaveManager>) -> Self {
        Self { _enclave: enclave }
    }

    /// Returns an identity only after provider-verified identity attestation
    /// can bind the generated key to a verified `DeviceIntegrityReport`.
    pub fn create_identity(&self) -> ConclaveResult<IdentityProfile> {
        Err(ConclaveError::Unsupported(
            "provider-verified identity attestation is unavailable".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::{android_strongbox::CoreEnclaveManager, cloud::CloudEnclave};

    #[test]
    fn software_and_development_managers_cannot_create_hardware_identity(
    ) -> crate::ConclaveResult<()> {
        let cloud_enclave = Arc::new(CloudEnclave::new(
            "https://vault.conxian-labs.com".to_string(),
        )?);
        let core_enclave = Arc::new(CoreEnclaveManager::new());

        for enclave in [
            cloud_enclave as Arc<dyn EnclaveManager>,
            core_enclave as Arc<dyn EnclaveManager>,
        ] {
            assert!(matches!(
                IdentityManager::new(enclave).create_identity(),
                Err(ConclaveError::Unsupported(message))
                    if message == "provider-verified identity attestation is unavailable"
            ));
        }

        Ok(())
    }
}
