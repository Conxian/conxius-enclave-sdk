//! Ark protocol boundary.
//!
//! Ark implementations and wire formats are still evolving. This module keeps
//! typed identifiers, state, provider, expiry, recovery, and exit contracts,
//! but quarantines key derivation, recovery scans, tree construction, and
//! settlement/forfeit signing behind exact `ProtocolUnsupported` errors.

use crate::{
    enclave::EnclaveManager, protocol_unsupported, BoundaryValidationError, ConclaveError,
    ConclaveResult, UnsupportedOperation, UnsupportedProtocol,
};
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};

pub const ARK_ENCODING_VERSION: u16 = 1;
pub const ARK_MAX_TREE_DEPTH: usize = 32;

fn boundary_error(kind: BoundaryValidationError) -> ConclaveError {
    ConclaveError::BoundaryValidation(kind)
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArkEncodingVersion(u16);

impl ArkEncodingVersion {
    pub fn new(version: u16) -> ConclaveResult<Self> {
        if version == ARK_ENCODING_VERSION {
            Ok(Self(version))
        } else {
            Err(boundary_error(
                BoundaryValidationError::InvalidEncodingVersion,
            ))
        }
    }

    pub const fn current() -> Self {
        Self(ARK_ENCODING_VERSION)
    }

    pub fn validate(self) -> ConclaveResult<()> {
        Self::new(self.0).map(|_| ())
    }
}

impl fmt::Debug for ArkEncodingVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ArkEncodingVersion")
            .field(&self.0)
            .finish()
    }
}

macro_rules! string_identifier {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> ConclaveResult<Self> {
                let value = value.into();
                if value.is_empty() || value.len() > 128 || !value.is_ascii() {
                    return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> ConclaveResult<()> {
                Self::new(self.0.clone()).map(|_| ())
            }
        }
    };
}

string_identifier!(ArkVtxoId);
string_identifier!(ArkTransactionId);
string_identifier!(ArkRoundId);
string_identifier!(ArkServerId);

macro_rules! bytes_identifier {
    ($name:ident, $size:expr) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        pub struct $name([u8; $size]);

        impl $name {
            pub fn new(value: [u8; $size]) -> ConclaveResult<Self> {
                if value == [0; $size] {
                    return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
                }
                Ok(Self(value))
            }

            pub fn validate(self) -> ConclaveResult<()> {
                Self::new(self.0).map(|_| ())
            }

            pub const fn bytes(self) -> [u8; $size] {
                self.0
            }
        }
    };
}

bytes_identifier!(ArkConnectorId, 32);
bytes_identifier!(ArkForfeitId, 32);
bytes_identifier!(ArkOperationId, 16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ArkDerivationIndex(u32);

impl ArkDerivationIndex {
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ArkExpiryHeight(u64);

impl ArkExpiryHeight {
    pub fn new(height: u64) -> ConclaveResult<Self> {
        if height == 0 {
            return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
        }
        Ok(Self(height))
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn validate(self) -> ConclaveResult<()> {
        Self::new(self.0).map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArkOutpoint {
    pub transaction_id: ArkTransactionId,
    pub vout: u32,
}

impl ArkOutpoint {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.transaction_id.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArkBackend {
    Unconfigured,
    ProviderOwned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArkOperationState {
    Proposed,
    Observed,
    RecoveryRequested,
    Expired,
    UnilateralExitRequested,
    Completed,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArkRecoveryMode {
    ProviderOwned,
    ExternalAspObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArkExitMode {
    Cooperative,
    Unilateral,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArkExitRequest {
    pub encoding_version: ArkEncodingVersion,
    pub operation_id: ArkOperationId,
    pub vtxo_id: ArkVtxoId,
    pub expiry: ArkExpiryHeight,
    pub mode: ArkExitMode,
}

impl ArkExitRequest {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        self.operation_id.validate()?;
        self.vtxo_id.validate()?;
        self.expiry.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VUtxoDescriptor {
    pub vutxo_id: ArkVtxoId,
    pub amount: u64,
    pub derivation_index: ArkDerivationIndex,
    pub address: String,
    pub outpoint: Option<ArkOutpoint>,
    pub expiry: Option<ArkExpiryHeight>,
}

impl VUtxoDescriptor {
    pub fn new(
        vutxo_id: ArkVtxoId,
        amount: u64,
        derivation_index: ArkDerivationIndex,
        address: impl Into<String>,
    ) -> ConclaveResult<Self> {
        let descriptor = Self {
            vutxo_id,
            amount,
            derivation_index,
            address: address.into(),
            outpoint: None,
            expiry: None,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        self.vutxo_id.validate()?;
        if self.amount == 0 || self.address.is_empty() {
            return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
        }
        if let Some(outpoint) = &self.outpoint {
            outpoint.validate()?;
        }
        if let Some(expiry) = self.expiry {
            expiry.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VtxoTreeNode {
    pub tx_id: ArkTransactionId,
    pub left: Option<Box<VtxoTreeNode>>,
    pub right: Option<Box<VtxoTreeNode>>,
    pub is_leaf: bool,
}

impl VtxoTreeNode {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.validate_at_depth(0)
    }

    fn validate_at_depth(&self, depth: usize) -> ConclaveResult<()> {
        if depth > ARK_MAX_TREE_DEPTH {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        self.tx_id.validate()?;
        if self.is_leaf {
            if self.left.is_some() || self.right.is_some() {
                return Err(boundary_error(
                    BoundaryValidationError::InvalidStateTransition,
                ));
            }
            return Ok(());
        }
        match (&self.left, &self.right) {
            (Some(left), Some(right)) => {
                left.validate_at_depth(depth + 1)?;
                right.validate_at_depth(depth + 1)
            }
            _ => Err(boundary_error(BoundaryValidationError::InvalidEnvelope)),
        }
    }
}

/// Ark V-UTXO API boundary. The backend remains unconfigured until an audited
/// protocol implementation and provider are selected.
pub struct ArkManager {
    #[allow(dead_code)]
    enclave: Arc<dyn EnclaveManager>,
    backend: ArkBackend,
}

impl ArkManager {
    pub fn new(enclave: Arc<dyn EnclaveManager>) -> Self {
        Self {
            enclave,
            backend: ArkBackend::Unconfigured,
        }
    }

    /// Construct an Ark manager only for a backend that is currently safe to
    /// expose. Provider-owned operation requires the hardware/provider and
    /// attestation evidence tracked by issue #195, so it cannot be selected
    /// through this boundary yet.
    pub fn try_with_backend(
        enclave: Arc<dyn EnclaveManager>,
        backend: ArkBackend,
    ) -> ConclaveResult<Self> {
        match backend {
            ArkBackend::Unconfigured => Ok(Self::new(enclave)),
            ArkBackend::ProviderOwned => Err(protocol_unsupported(
                UnsupportedProtocol::Ark,
                UnsupportedOperation::VutxoKeyDerivation,
            )),
        }
    }

    /// Compatibility-named alias for [`Self::try_with_backend`]. The return
    /// type is fallible so callers cannot silently construct provider-owned
    /// state before the enabling evidence exists.
    pub fn with_backend(
        enclave: Arc<dyn EnclaveManager>,
        backend: ArkBackend,
    ) -> ConclaveResult<Self> {
        Self::try_with_backend(enclave, backend)
    }

    pub fn backend(&self) -> ArkBackend {
        self.backend
    }

    /// Generic seed/index derivation is quarantined; seeds never enter a
    /// provider-facing production boundary in this implementation.
    pub fn derive_vutxo_key(&self, _master_seed: &[u8], _index: u32) -> ConclaveResult<[u8; 32]> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Ark,
            UnsupportedOperation::VutxoKeyDerivation,
        ))
    }

    /// Public-key derivation is also quarantined until the selected Ark backend
    /// defines canonical derivation paths and evidence.
    pub fn derive_vutxo_public_key(&self, _index: u32) -> ConclaveResult<String> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Ark,
            UnsupportedOperation::VutxoKeyDerivation,
        ))
    }

    /// Sign a VTXO using FROST threshold signing.
    ///
    /// When the `frost-crypto` feature is enabled, this delegates to the
    /// `FrostSigningContext` for threshold signing of Ark round transactions.
    /// Each VTXO is signed by a threshold of ASP participants.
    #[cfg(feature = "frost-crypto")]
    pub fn sign_vutxo_with_context(
        &self,
        ctx: &crate::protocol::frost::FrostSigningContext,
        key_package: &crate::protocol::frost::FrostKeyPackage,
        shares: &[crate::protocol::frost::FrostSignatureShare],
    ) -> ConclaveResult<String> {
        ctx.aggregate_signatures(key_package, shares)
    }

    /// Sign a VTXO spend transaction.
    ///
    /// Without `frost-crypto`, signing is quarantined until the provider
    /// attestation chain is complete.
    #[cfg(not(feature = "frost-crypto"))]
    pub fn sign_vutxo_with_context(
        &self,
        _ctx: &crate::protocol::frost::FrostSigningContext,
        _key_package: &crate::protocol::frost::FrostKeyPackage,
        _shares: &[crate::protocol::frost::FrostSignatureShare],
    ) -> ConclaveResult<String> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Ark,
            UnsupportedOperation::ForfeitSigning,
        ))
    }

    pub fn sign_vutxo(&self, _tx_hash: [u8; 32], _index: u32) -> ConclaveResult<String> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Ark,
            UnsupportedOperation::ForfeitSigning,
        ))
    }

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

    /// Construct a VTXO Merkle tree from leaf descriptors.
    ///
    /// Builds a binary Merkle tree over the VTXO leaf hashes. Each leaf is
    /// hashed with SHA-256, then paired and hashed up to the root.
    pub fn construct_vtxo_tree(
        &self,
        leaves: Vec<VUtxoDescriptor>,
    ) -> ConclaveResult<VtxoTreeNode> {
        if leaves.is_empty() {
            return Err(ConclaveError::InvalidConfiguration(
                "VTXO tree requires at least one leaf".into(),
            ));
        }

        use sha2::{Digest, Sha256};

        fn hash_node(left: &[u8], right: &[u8]) -> (String, [u8; 32]) {
            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);
            let hash: [u8; 32] = hasher.finalize().into();
            (hex::encode(hash), hash)
        }

        fn build_level(nodes: Vec<VtxoTreeNode>) -> VtxoTreeNode {
            if nodes.len() == 1 {
                return nodes.into_iter().next().unwrap();
            }
            let mut parent_level = Vec::new();
            for chunk in nodes.chunks(2) {
                let left = &chunk[0];
                let right = chunk.get(1).unwrap_or(left);
                let left_hash = hex::decode(left.tx_id.as_str()).unwrap_or_default();
                let right_hash = hex::decode(right.tx_id.as_str()).unwrap_or_default();
                let (tx_id_hex, _) = hash_node(&left_hash, &right_hash);
                parent_level.push(VtxoTreeNode {
                    tx_id: ArkTransactionId::new(tx_id_hex).unwrap_or_else(|_| {
                        ArkTransactionId::new("0000000000000000000000000000000000000000000000000000000000000000").unwrap()
                    }),
                    left: Some(Box::new(left.clone())),
                    right: Some(Box::new(right.clone())),
                    is_leaf: false,
                });
            }
            build_level(parent_level)
        }

        let leaf_nodes: Vec<VtxoTreeNode> = leaves
            .iter()
            .map(|vutxo| {
                let mut hasher = Sha256::new();
                hasher.update(&vutxo.amount.to_be_bytes());
                hasher.update(vutxo.address.as_bytes());
                hasher.update(vutxo.vutxo_id.as_str().as_bytes());
                let leaf_hash: [u8; 32] = hasher.finalize().into();
                VtxoTreeNode {
                    tx_id: ArkTransactionId::new(hex::encode(leaf_hash)).unwrap_or_else(|_| {
                        ArkTransactionId::new("0000000000000000000000000000000000000000000000000000000000000000").unwrap()
                    }),
                    left: None,
                    right: None,
                    is_leaf: true,
                }
            })
            .collect();

        Ok(build_level(leaf_nodes))
    }

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
    use crate::{enclave::cloud::CloudEnclave, UnsupportedReason};

    fn manager() -> ArkManager {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        ArkManager::new(enclave)
    }

    fn descriptor() -> VUtxoDescriptor {
        VUtxoDescriptor::new(
            ArkVtxoId::new("vtxo-1").expect("valid vtxo id"),
            100,
            ArkDerivationIndex::new(0),
            "bc1q-example",
        )
        .expect("valid descriptor")
    }

    #[test]
    fn validates_typed_ids_versions_expiry_and_tree_shape() {
        assert!(matches!(
            ArkEncodingVersion::new(2),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidEncodingVersion
            ))
        ));
        assert!(matches!(
            ArkVtxoId::new(""),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidIdentifier
            ))
        ));
        assert!(matches!(
            ArkExpiryHeight::new(0),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidIdentifier
            ))
        ));
        let mut invalid = descriptor();
        invalid.amount = 0;
        assert!(matches!(
            invalid.validate(),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidIdentifier
            ))
        ));
        let leaf = VtxoTreeNode {
            tx_id: ArkTransactionId::new("tx-1").expect("valid transaction id"),
            left: None,
            right: None,
            is_leaf: true,
        };
        assert!(leaf.validate().is_ok());
        let malformed_leaf = VtxoTreeNode {
            tx_id: ArkTransactionId::new("tx-1").expect("valid transaction id"),
            left: Some(Box::new(leaf.clone())),
            right: None,
            is_leaf: true,
        };
        assert!(matches!(
            malformed_leaf.validate(),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidStateTransition
            ))
        ));
    }

    #[test]
    fn backend_selection_accepts_only_the_safe_disabled_variant() {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());

        let manager = ArkManager::try_with_backend(enclave.clone(), ArkBackend::Unconfigured)
            .expect("unconfigured backend is the safe default");
        assert_eq!(manager.backend(), ArkBackend::Unconfigured);

        assert_unsupported(
            ArkManager::try_with_backend(enclave.clone(), ArkBackend::ProviderOwned),
            UnsupportedOperation::VutxoKeyDerivation,
        );
        assert_unsupported(
            ArkManager::with_backend(enclave, ArkBackend::ProviderOwned),
            UnsupportedOperation::VutxoKeyDerivation,
        );
    }

    #[test]
    fn with_backend_accepts_unconfigured_backend() {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());

        let manager = ArkManager::with_backend(enclave, ArkBackend::Unconfigured)
            .expect("unconfigured backend is the safe default");

        assert_eq!(manager.backend(), ArkBackend::Unconfigured);
    }

    #[test]
    fn all_value_bearing_ark_operations_are_exactly_unsupported_and_stateless() {
        let manager = manager();
        assert_eq!(manager.backend(), ArkBackend::Unconfigured);
        assert_unsupported(
            manager.derive_vutxo_key(&[1; 32], 0),
            UnsupportedOperation::VutxoKeyDerivation,
        );
        assert_unsupported(
            manager.derive_vutxo_public_key(0),
            UnsupportedOperation::VutxoKeyDerivation,
        );
        assert_unsupported(
            manager.sign_vutxo([0; 32], 0),
            UnsupportedOperation::ForfeitSigning,
        );
        assert_unsupported(
            manager.construct_vtxo_tree(vec![descriptor()]),
            UnsupportedOperation::VtxoTreeConstruction,
        );
        assert_eq!(manager.backend(), ArkBackend::Unconfigured);
    }

    #[tokio::test]
    async fn recovery_is_exactly_unsupported() {
        assert_unsupported(
            manager()
                .recovery_scan([1; 32], 20, "https://asp.invalid")
                .await,
            UnsupportedOperation::RecoveryScan,
        );
    }

    fn assert_unsupported<T>(result: ConclaveResult<T>, operation: UnsupportedOperation) {
        match result {
            Err(ConclaveError::ProtocolUnsupported {
                protocol: UnsupportedProtocol::Ark,
                operation: actual_operation,
                reason: UnsupportedReason::NoAuditedImplementation,
            }) => assert_eq!(actual_operation, operation),
            _ => panic!("expected typed Ark unsupported error"),
        }
    }

    #[test]
    fn vtxo_tree_power_of_two() {
        let leaves: Vec<VUtxoDescriptor> = (0..4)
            .map(|i| {
                VUtxoDescriptor::new(
                    ArkVtxoId::new(format!("vutxo-{}", i)).unwrap(),
                    1000 * (i + 1) as u64,
                    ArkDerivationIndex::new(i).unwrap(),
                    format!("addr-{}", i),
                )
                .unwrap()
            })
            .collect();

        let tree = manager().construct_vtxo_tree(leaves).unwrap();
        assert!(!tree.is_leaf);
        assert!(tree.left.is_some());
        assert!(tree.right.is_some());
        assert_eq!(tree.tx_id.as_str().len(), 64); // hex hash
    }

    #[test]
    fn vtxo_tree_single_leaf() {
        let leaf = VUtxoDescriptor::new(
            ArkVtxoId::new("single-vutxo").unwrap(),
            5000,
            ArkDerivationIndex::new(0).unwrap(),
            "single-addr",
        )
        .unwrap();

        let tree = manager().construct_vtxo_tree(vec![leaf]).unwrap();
        assert!(tree.is_leaf);
    }

    #[test]
    fn vtxo_tree_empty_rejected() {
        assert!(manager().construct_vtxo_tree(vec![]).is_err());
    }
}
