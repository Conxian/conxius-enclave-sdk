use crate::{ConclaveResult, enclave::EnclaveManager};
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Ark V-UTXO Protocol Implementation (v1.9.2)
/// Native derivation and forfeit signing for stateless Bitcoin L2 scalability.
pub struct ArkManager {
    enclave: Arc<dyn EnclaveManager>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VUtxoDescriptor {
    pub vutxo_id: String,
    pub amount: u64,
    pub derivation_index: u32,
}

impl ArkManager {
    pub fn new(enclave: Arc<dyn EnclaveManager>) -> Self {
        Self { enclave }
    }

    /// Derives a deterministic V-UTXO key using Blake2s PRF.
    /// Enables the stateless restore model from a master seed.
    pub fn derive_vutxo_key(&self, master_seed: &[u8], index: u32) -> [u8; 32] {
        let mut hasher = Blake2s256::new();
        hasher.update(master_seed);
        hasher.update(index.to_le_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Signs a forfeit transaction to enable exiting an Ark ASP.
    pub fn sign_forfeit_transaction(
        &self,
        tx_hash: [u8; 32],
        derivation_path: &str,
    ) -> ConclaveResult<String> {
        // In a real Ark implementation, this would involve specific forfeit
        // logic and potentially MuSig2 for multi-party signatures.
        // Here we provide the core signing hook.
        let pubkey = self.enclave.get_public_key(derivation_path)?;

        // Mocking the forfeit signing flow using the enclave's default signing
        let request = crate::enclave::SignRequest {
            algorithm: crate::enclave::SigningAlgorithm::EcdsaSecp256k1,
            message_hash: tx_hash.to_vec(),
            derivation_path: derivation_path.to_string(),
            key_id: pubkey,
            taproot_tweak: None,
        };

        let response = self.enclave.sign(request)?;
        Ok(response.signature_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::cloud::CloudEnclave;

    #[test]
    fn test_vutxo_derivation_determinism() {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let mgr = ArkManager::new(enclave);

        let seed = [1u8; 32];
        let key1 = mgr.derive_vutxo_key(&seed, 0);
        let key2 = mgr.derive_vutxo_key(&seed, 0);
        let key3 = mgr.derive_vutxo_key(&seed, 1);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }
}
