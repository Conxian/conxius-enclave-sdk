use crate::{
    enclave::EnclaveManager, protocol_unsupported, ConclaveResult, UnsupportedOperation,
    UnsupportedProtocol,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Ark V-UTXO API boundary.
///
/// Value-bearing derivation, recovery, tree construction, and forfeit-signing
/// operations remain explicitly unsupported until an audited implementation is
/// available.
pub struct ArkManager {
    #[allow(dead_code)]
    enclave: Arc<dyn EnclaveManager>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VUtxoDescriptor {
    pub vutxo_id: String,
    pub amount: u64,
    pub derivation_index: u32,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtxoTreeNode {
    pub tx_id: String,
    pub left: Option<Box<VtxoTreeNode>>,
    pub right: Option<Box<VtxoTreeNode>>,
    pub is_leaf: bool,
}

impl ArkManager {
    pub fn new(enclave: Arc<dyn EnclaveManager>) -> Self {
        Self { enclave }
    }

    /// V-UTXO key derivation is unavailable until an audited Ark implementation exists.
    pub fn derive_vutxo_key(&self, _master_seed: &[u8], _index: u32) -> ConclaveResult<[u8; 32]> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Ark,
            UnsupportedOperation::VutxoKeyDerivation,
        ))
    }

    /// Retrieves the public key for a provider-owned V-UTXO derivation path.
    ///
    /// The provider owns the private key. This capability intentionally does
    /// not accept a seed and never returns private key bytes.
    pub fn derive_vutxo_public_key(&self, index: u32) -> ConclaveResult<String> {
        self.enclave.get_public_key(&format!("m/ark/vutxo/{index}"))
    }

    /// Signs a V-UTXO operation through the provider-owned enclave key.
    pub fn sign_vutxo(&self, tx_hash: [u8; 32], index: u32) -> ConclaveResult<String> {
        self.sign_forfeit_transaction(tx_hash, &format!("m/ark/vutxo/{index}"))
    }

    /// Performs a stateless recovery scan for V-UTXOs.
    pub async fn recovery_scan(
        &self,
        _master_seed: [u8; 32],
        _gap_limit: u32,
        _asp_url: &str,
    ) -> ConclaveResult<Vec<VUtxoDescriptor>> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Ark,
            UnsupportedOperation::RecoveryScan,
        ))
    }

    /// Constructs a vTXO tree for multi-party exits.
    pub fn construct_vtxo_tree(
        &self,
        _leaves: Vec<VUtxoDescriptor>,
    ) -> ConclaveResult<VtxoTreeNode> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Ark,
            UnsupportedOperation::VtxoTreeConstruction,
        ))
    }

    /// Signs a forfeit transaction to enable exiting an Ark ASP.
    pub fn sign_forfeit_transaction(
        &self,
        _tx_hash: [u8; 32],
        _derivation_path: &str,
    ) -> ConclaveResult<String> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Ark,
            UnsupportedOperation::ForfeitSigning,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::cloud::CloudEnclave;
    use crate::ConclaveError;

    #[test]
    fn test_ark_operations_are_explicitly_unsupported() {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let mgr = ArkManager::new(enclave);

        let seed = [1u8; 32];
        let leaves = vec![
            VUtxoDescriptor {
                vutxo_id: "leaf1".to_string(),
                amount: 100,
                derivation_index: 0,
                address: "addr1".into(),
            },
            VUtxoDescriptor {
                vutxo_id: "leaf2".to_string(),
                amount: 100,
                derivation_index: 1,
                address: "addr2".into(),
            },
            VUtxoDescriptor {
                vutxo_id: "leaf3".to_string(),
                amount: 100,
                derivation_index: 2,
                address: "addr3".into(),
            },
            VUtxoDescriptor {
                vutxo_id: "leaf4".to_string(),
                amount: 100,
                derivation_index: 3,
                address: "addr4".into(),
            },
        ];

        assert_unsupported(
            mgr.derive_vutxo_key(&seed, 0),
            UnsupportedOperation::VutxoKeyDerivation,
        );
        assert_unsupported(
            mgr.construct_vtxo_tree(leaves),
            UnsupportedOperation::VtxoTreeConstruction,
        );
        assert_unsupported(
            mgr.sign_forfeit_transaction([0u8; 32], "m/84'/0'/0'"),
            UnsupportedOperation::ForfeitSigning,
        );
    }

    #[tokio::test]
    async fn test_ark_recovery_scan_is_explicitly_unsupported() {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let mgr = ArkManager::new(enclave);

        assert_unsupported(
            mgr.recovery_scan([1u8; 32], 20, "http://mock-asp").await,
            UnsupportedOperation::RecoveryScan,
        );
    }

    fn assert_unsupported<T>(result: ConclaveResult<T>, operation: UnsupportedOperation) {
        match result {
            Err(ConclaveError::ProtocolUnsupported {
                protocol: UnsupportedProtocol::Ark,
                operation: actual_operation,
                reason: crate::UnsupportedReason::NoAuditedImplementation,
            }) => assert_eq!(actual_operation, operation),
            _ => panic!("expected typed Ark unsupported error"),
        }
    }

    #[test]
    #[cfg(feature = "bip110_compliant")]
    fn test_bip110_ordered_ark_commitment_segmentation() {
        let commitment: Vec<u8> = (0..777).map(|index| (index % 251) as u8).collect();
        let chunks = crate::protocol::bip110::try_chunk_for_bip110(&commitment, 256)
            .expect("strict chunking succeeds");

        assert_eq!(
            chunks.iter().map(|chunk| chunk.len()).collect::<Vec<_>>(),
            vec![256, 256, 256, 9]
        );
        let reconstructed: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(reconstructed, commitment);
    }
}
