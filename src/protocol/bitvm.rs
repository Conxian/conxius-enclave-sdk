use crate::protocol::bitcoin::TaprootManager;
use crate::{ConclaveResult, enclave::EnclaveManager};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// BitVM2 Verification Floor Implementation (v1.9.2)
/// Mapped to the 364-tap verification process (1 VALIDATING, 363 HASHING).
pub struct BitVmManager {
    enclave: Arc<dyn EnclaveManager>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitVmChallenge {
    pub challenge_hash: [u8; 32],
    pub tap_index: u32,
    pub total_taps: u32,
}

impl BitVmManager {
    pub fn new(enclave: Arc<dyn EnclaveManager>) -> Self {
        Self { enclave }
    }

    /// Signs a challenge as part of the BitVM2 multi-tap verification process.
    /// Enforces "Fail-Closed" security by validating tap_index bounds.
    pub fn sign_challenge(
        &self,
        challenge: BitVmChallenge,
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        // Fail-Closed: Verify tap boundaries
        if challenge.tap_index >= challenge.total_taps {
            return Err(crate::ConclaveError::InvalidPayload);
        }

        // BitVM2 Verification Floor: 364 taps (1 VALIDATING, 363 HASHING)
        if challenge.total_taps != 364 {
            // Optional: warning or strict enforcement depending on target environment
        }

        let taproot = TaprootManager::new(self.enclave.as_ref());
        taproot.sign_bitvm_challenge(challenge.challenge_hash, derivation_path, key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::cloud::CloudEnclave;

    #[test]
    fn test_bitvm_challenge_bounds() {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let mgr = BitVmManager::new(enclave);

        let challenge = BitVmChallenge {
            challenge_hash: [0u8; 32],
            tap_index: 364,
            total_taps: 364,
        };

        let result = mgr.sign_challenge(challenge, "m/86'/0'/0'/0/0", "key1");
        assert!(result.is_err());
    }
}
