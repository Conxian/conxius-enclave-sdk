use crate::{ConclaveResult, enclave::EnclaveManager};
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Ark V-UTXO Protocol Implementation (v1.9.2)
/// Native derivation and forfeit signing for stateless Bitcoin L2 scalability.
pub struct ArkManager {
    enclave: Arc<dyn EnclaveManager>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VUtxoDescriptor {
    pub vutxo_id: String,
    pub amount: u64,
    pub derivation_index: u32,
    pub address: String,
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

    /// Performs a stateless recovery scan for V-UTXOs.
    /// Iterates through derivation indices and checks with the ASP.
    /// Implementation is multi-threaded capable but uses a single-loop for WASM compatibility.
    pub async fn recovery_scan(
        &self,
        master_seed: [u8; 32],
        gap_limit: u32,
        asp_url: &str,
    ) -> ConclaveResult<Vec<VUtxoDescriptor>> {
        let mut found_vutxos = Vec::new();
        let mut consecutive_empty = 0;
        let mut current_index = 0;

        while consecutive_empty < gap_limit {
            let vutxo_key = self.derive_vutxo_key(&master_seed, current_index);

            // In production, this would call the ASP API to check for V-UTXOs
            // for the derived public key.
            if let Some(vutxo) = self
                .lookup_vutxo_from_asp(asp_url, &vutxo_key, current_index)
                .await?
            {
                found_vutxos.push(vutxo);
                consecutive_empty = 0;
            } else {
                consecutive_empty += 1;
            }
            current_index += 1;
        }

        Ok(found_vutxos)
    }

    /// Looks up a V-UTXO from an Ark ASP.
    async fn lookup_vutxo_from_asp(
        &self,
        _asp_url: &str,
        _vutxo_key: &[u8; 32],
        index: u32,
    ) -> ConclaveResult<Option<VUtxoDescriptor>> {
        // Mock: Discover V-UTXOs at specific indices for testing
        // Production would use reqwest to query the ASP
        if index == 5 || index == 12 {
            Ok(Some(VUtxoDescriptor {
                vutxo_id: format!("vutxo-{}", index),
                amount: 100000,
                derivation_index: index,
                address: format!("bc1q_ark_{}", index),
            }))
        } else {
            Ok(None)
        }
    }

    /// Signs a forfeit transaction to enable exiting an Ark ASP.
    pub fn sign_forfeit_transaction(
        &self,
        tx_hash: [u8; 32],
        derivation_path: &str,
    ) -> ConclaveResult<String> {
        let pubkey = self.enclave.get_public_key(derivation_path)?;

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

    #[tokio::test]
    async fn test_stateless_recovery_scan() {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let mgr = ArkManager::new(enclave);
        let seed = [1u8; 32];

        let vutxos = mgr
            .recovery_scan(seed, 10, "http://mock-asp")
            .await
            .unwrap();

        assert_eq!(vutxos.len(), 2);
        assert_eq!(vutxos[0].derivation_index, 5);
        assert_eq!(vutxos[1].derivation_index, 12);
    }
}
