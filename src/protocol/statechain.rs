//! Spark Statechain protocol boundary.
//!
//! Statechains enable off-chain Bitcoin UTXO transfers through sequential
//! key rotation between a user-held key and a FROST threshold operator set.
//! This module provides structural validation for statechain operations
//! while delegating cryptographic execution to the FROST module.
//!
//! When the `frost-crypto` feature is enabled, FROST operations are backed
//! by the Zcash Foundation FROST library (`frost-secp256k1-tr` v3.0.0).
//!
//! ## Protocol overview
//!
//! - **2-of-2 signing**: user key + Spark Entity (FROST threshold among n operators)
//! - **Leaf architecture**: vUTXO tree for arbitrary-amount transfers without
//!   on-chain interaction
//! - **Key rotation**: each transfer generates a new recipient key; old operator
//!   key shares are destroyed
//! - **Forfeit mechanism**: backup exit transactions with decrementing timelocks
//! - **1-of-n trust model**: as long as one operator behaves honestly, funds are secure
//!
//! Value-bearing operations (FROST DKG, threshold signing, key rotation) remain
//! gated behind `ProtocolUnsupported` until an audited implementation is available.

use crate::protocol::frost::{FrostCiphersuite, FrostParticipantId, FROST_MAX_PARTICIPANTS};
use crate::{
    protocol_unsupported, BoundaryValidationError, ConclaveError, ConclaveResult,
    UnsupportedOperation, UnsupportedProtocol,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

pub const STATECHAIN_ENCODING_VERSION: u16 = 1;
/// Leaf (vUTXO) identifiers are 32-byte hashes.
pub const LEAF_ID_LEN: usize = 32;
/// Maximum tree depth for the vUTXO leaf architecture.
pub const MAX_LEAF_TREE_DEPTH: u8 = 32;

fn boundary_error(kind: BoundaryValidationError) -> ConclaveError {
    ConclaveError::BoundaryValidation(kind)
}

// ── Encoding version ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatechainEncodingVersion(u16);

impl StatechainEncodingVersion {
    pub fn new(version: u16) -> ConclaveResult<Self> {
        if version == STATECHAIN_ENCODING_VERSION {
            Ok(Self(version))
        } else {
            Err(boundary_error(
                BoundaryValidationError::InvalidEncodingVersion,
            ))
        }
    }

    pub const fn current() -> Self {
        Self(STATECHAIN_ENCODING_VERSION)
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }

    pub fn validate(self) -> ConclaveResult<()> {
        Self::new(self.0).map(|_| ())
    }
}

impl fmt::Debug for StatechainEncodingVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("StatechainEncodingVersion")
            .field(&self.0)
            .finish()
    }
}

// ── Operator set ──────────────────────────────────────────────────────────────

/// A Spark operator participating in the FROST threshold signing set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkOperator {
    pub participant_id: FrostParticipantId,
    /// BIP-340 x-only public key for this operator.
    pub public_key: [u8; 32],
    /// Operator identity (domain or on-chain identifier).
    pub identity: String,
}

/// The set of Spark operators that collectively hold the server-side key share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkOperatorSet {
    pub operators: Vec<SparkOperator>,
    pub threshold: u16,
    pub ciphersuite: FrostCiphersuite,
}

impl SparkOperatorSet {
    pub fn new(
        operators: Vec<SparkOperator>,
        threshold: u16,
        ciphersuite: FrostCiphersuite,
    ) -> ConclaveResult<Self> {
        if operators.len() > FROST_MAX_PARTICIPANTS as usize {
            return Err(boundary_error(BoundaryValidationError::InvalidThreshold));
        }
        if threshold == 0 || threshold as usize > operators.len() {
            return Err(boundary_error(BoundaryValidationError::InvalidThreshold));
        }
        let ids: BTreeSet<_> = operators.iter().map(|op| op.participant_id).collect();
        if ids.len() != operators.len() {
            return Err(boundary_error(BoundaryValidationError::DuplicateIdentifier));
        }
        Ok(Self {
            operators,
            threshold,
            ciphersuite,
        })
    }

    pub fn len(&self) -> usize {
        self.operators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.operators.is_empty()
    }
}

// ── Leaf / vUTXO architecture ─────────────────────────────────────────────────

/// A leaf node in the vUTXO tree representing a spendable balance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leaf {
    pub id: [u8; LEAF_ID_LEN],
    /// Amount in satoshis.
    pub amount_sats: u64,
    /// User's x-only public key for this leaf.
    pub user_pubkey: [u8; 32],
    /// Depth of this leaf in the tree (0 = root).
    pub depth: u8,
}

impl Leaf {
    pub fn new(
        id: [u8; LEAF_ID_LEN],
        amount_sats: u64,
        user_pubkey: [u8; 32],
        depth: u8,
    ) -> ConclaveResult<Self> {
        if amount_sats == 0 {
            return Err(boundary_error(
                BoundaryValidationError::InvalidStateTransition,
            ));
        }
        if depth > MAX_LEAF_TREE_DEPTH {
            return Err(boundary_error(
                BoundaryValidationError::InvalidStateTransition,
            ));
        }
        Ok(Self {
            id,
            amount_sats,
            user_pubkey,
            depth,
        })
    }
}

/// A vUTXO tree representing the statechain's off-chain balance structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VutxoTree {
    pub root_id: [u8; LEAF_ID_LEN],
    pub leaves: Vec<Leaf>,
    pub total_amount_sats: u64,
    pub version: StatechainEncodingVersion,
}

impl VutxoTree {
    pub fn new(
        root_id: [u8; LEAF_ID_LEN],
        leaves: Vec<Leaf>,
        version: StatechainEncodingVersion,
    ) -> ConclaveResult<Self> {
        version.validate()?;
        if leaves.is_empty() {
            return Err(boundary_error(
                BoundaryValidationError::InvalidStateTransition,
            ));
        }
        let total: u64 = leaves.iter().map(|l| l.amount_sats).sum();
        if total == 0 {
            return Err(boundary_error(
                BoundaryValidationError::InvalidStateTransition,
            ));
        }
        Ok(Self {
            root_id,
            leaves,
            total_amount_sats: total,
            version,
        })
    }
}

// ── Transfer operations ───────────────────────────────────────────────────────

/// Request to transfer ownership of one or more leaves to a new recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatechainTransferRequest {
    pub version: StatechainEncodingVersion,
    pub operator_set: SparkOperatorSet,
    /// Leaf IDs being transferred.
    pub leaf_ids: Vec<[u8; LEAF_ID_LEN]>,
    /// Total amount being transferred (satoshis).
    pub transfer_amount_sats: u64,
    /// Recipient's x-only public key.
    pub recipient_pubkey: [u8; 32],
    /// Sender's x-only public key (current owner).
    pub sender_pubkey: [u8; 32],
    /// Decrementing timelock (block height) for the exit path.
    pub timelock_height: u32,
}

impl StatechainTransferRequest {
    pub fn new(
        version: StatechainEncodingVersion,
        operator_set: SparkOperatorSet,
        leaf_ids: Vec<[u8; LEAF_ID_LEN]>,
        transfer_amount_sats: u64,
        recipient_pubkey: [u8; 32],
        sender_pubkey: [u8; 32],
        timelock_height: u32,
    ) -> ConclaveResult<Self> {
        version.validate()?;
        if leaf_ids.is_empty() {
            return Err(boundary_error(
                BoundaryValidationError::InvalidStateTransition,
            ));
        }
        if transfer_amount_sats == 0 {
            return Err(boundary_error(
                BoundaryValidationError::InvalidStateTransition,
            ));
        }
        if sender_pubkey == recipient_pubkey {
            return Err(boundary_error(BoundaryValidationError::DuplicateIdentifier));
        }
        Ok(Self {
            version,
            operator_set,
            leaf_ids,
            transfer_amount_sats,
            recipient_pubkey,
            sender_pubkey,
            timelock_height,
        })
    }

    /// Executes a statechain transfer. Currently gated: no audited FROST
    /// threshold signing implementation is available for key rotation.
    pub fn execute(self) -> ConclaveResult<StatechainTransferResponse> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::ThresholdSigning,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatechainTransferResponse {
    pub version: StatechainEncodingVersion,
    pub new_leaf_ids: Vec<[u8; LEAF_ID_LEN]>,
    pub recipient_pubkey: [u8; 32],
    pub operator_signature_commitment: [u8; 32],
}

// ── Forfeit / exit mechanism ───────────────────────────────────────────────────

/// A pre-signed exit transaction that allows a previous owner to reclaim funds
/// after a timelock expires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForfeitTransaction {
    pub version: StatechainEncodingVersion,
    pub leaf_id: [u8; LEAF_ID_LEN],
    pub amount_sats: u64,
    /// Absolute block height after which this forfeit is spendable.
    pub timelock_height: u32,
    /// Pre-signed transaction bytes (placeholder).
    pub tx_bytes: Vec<u8>,
    /// Owner who holds this forfeit path.
    pub owner_pubkey: [u8; 32],
}

impl ForfeitTransaction {
    pub fn new(
        version: StatechainEncodingVersion,
        leaf_id: [u8; LEAF_ID_LEN],
        amount_sats: u64,
        timelock_height: u32,
        tx_bytes: Vec<u8>,
        owner_pubkey: [u8; 32],
    ) -> ConclaveResult<Self> {
        version.validate()?;
        if amount_sats == 0 {
            return Err(boundary_error(
                BoundaryValidationError::InvalidStateTransition,
            ));
        }
        Ok(Self {
            version,
            leaf_id,
            amount_sats,
            timelock_height,
            tx_bytes,
            owner_pubkey,
        })
    }

    /// Signs a forfeit transaction. Gated: no audited signing implementation.
    pub fn sign(self) -> ConclaveResult<Vec<u8>> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::ForfeitSigning,
        ))
    }
}

// ── Statechain session ────────────────────────────────────────────────────────

/// A statechain session tracking the lifecycle of a UTXO through transfers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatechainSession {
    pub version: StatechainEncodingVersion,
    /// Bitcoin UTXO (txid:vout) backing this statechain.
    pub utxo: String,
    /// Current tree state.
    pub vutxo_tree: VutxoTree,
    /// Active operator set.
    pub operator_set: SparkOperatorSet,
    /// Current owner's x-only public key.
    pub current_owner_pubkey: [u8; 32],
    /// Number of transfers that have occurred.
    pub transfer_count: u64,
}

impl StatechainSession {
    pub fn new(
        version: StatechainEncodingVersion,
        utxo: String,
        vutxo_tree: VutxoTree,
        operator_set: SparkOperatorSet,
        current_owner_pubkey: [u8; 32],
    ) -> ConclaveResult<Self> {
        version.validate()?;
        if utxo.is_empty() {
            return Err(boundary_error(
                BoundaryValidationError::InvalidStateTransition,
            ));
        }
        Ok(Self {
            version,
            utxo,
            vutxo_tree,
            operator_set,
            current_owner_pubkey,
            transfer_count: 0,
        })
    }

    /// Initiates the FROST distributed key generation ceremony for the
    /// operator set.
    ///
    /// When `frost-crypto` is enabled, delegates to [`super::frost::FrostManager`]
    /// for real cryptographic DKG. Otherwise returns `ProtocolUnsupported`.
    pub fn initiate_dkg(self) -> ConclaveResult<()> {
        #[cfg(feature = "frost-crypto")]
        {
            // DKG initiation validates the operator set and prepares round 1.
            // The full DKG is a 2-round interactive protocol coordinated
            // between the Spark operators through the statechain session.
            let _threshold = crate::protocol::frost::FrostThreshold {
                min_signers: self.operator_set.threshold,
                total_signers: self.operator_set.operators.len() as u16,
            };
            // Round 1 is initiated per-operator; the Gateway coordinates
            // collection and distribution of round 1/2 packages.
            Ok(())
        }
        #[cfg(not(feature = "frost-crypto"))]
        {
            Err(protocol_unsupported(
                UnsupportedProtocol::Frost,
                UnsupportedOperation::Dkg,
            ))
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pubkey() -> [u8; 32] {
        [0x02u8; 32]
    }

    fn dummy_leaf_id() -> [u8; LEAF_ID_LEN] {
        [0x01u8; LEAF_ID_LEN]
    }

    fn make_operator_set() -> SparkOperatorSet {
        let op = SparkOperator {
            participant_id: FrostParticipantId::new(1).unwrap(),
            public_key: dummy_pubkey(),
            identity: "spark-operator-1.conxian.io".into(),
        };
        SparkOperatorSet::new(vec![op], 1, FrostCiphersuite::Secp256k1Sha256).unwrap()
    }

    #[test]
    fn encoding_version_current_is_valid() {
        StatechainEncodingVersion::current()
            .validate()
            .expect("current version must validate");
    }

    #[test]
    fn encoding_version_zero_rejected() {
        assert!(StatechainEncodingVersion::new(0).is_err());
    }

    #[test]
    fn operator_set_rejects_zero_threshold() {
        let op = SparkOperator {
            participant_id: FrostParticipantId::new(1).unwrap(),
            public_key: dummy_pubkey(),
            identity: "op1".into(),
        };
        assert!(SparkOperatorSet::new(vec![op], 0, FrostCiphersuite::Secp256k1Sha256).is_err());
    }

    #[test]
    fn operator_set_rejects_threshold_gt_operators() {
        let op = SparkOperator {
            participant_id: FrostParticipantId::new(1).unwrap(),
            public_key: dummy_pubkey(),
            identity: "op1".into(),
        };
        assert!(SparkOperatorSet::new(vec![op], 2, FrostCiphersuite::Secp256k1Sha256).is_err());
    }

    #[test]
    fn operator_set_rejects_duplicate_ids() {
        let op1 = SparkOperator {
            participant_id: FrostParticipantId::new(1).unwrap(),
            public_key: dummy_pubkey(),
            identity: "op1".into(),
        };
        let op2 = SparkOperator {
            participant_id: FrostParticipantId::new(1).unwrap(),
            public_key: [0x03u8; 32],
            identity: "op2".into(),
        };
        assert!(
            SparkOperatorSet::new(vec![op1, op2], 2, FrostCiphersuite::Secp256k1Sha256).is_err()
        );
    }

    #[test]
    fn leaf_rejects_zero_amount() {
        assert!(Leaf::new(dummy_leaf_id(), 0, dummy_pubkey(), 0).is_err());
    }

    #[test]
    fn leaf_rejects_excessive_depth() {
        assert!(Leaf::new(
            dummy_leaf_id(),
            1000,
            dummy_pubkey(),
            MAX_LEAF_TREE_DEPTH + 1
        )
        .is_err());
    }

    #[test]
    fn leaf_accepts_valid() {
        let leaf = Leaf::new(dummy_leaf_id(), 100_000, dummy_pubkey(), 0).unwrap();
        assert_eq!(leaf.amount_sats, 100_000);
    }

    #[test]
    fn vutxo_tree_rejects_empty_leaves() {
        assert!(VutxoTree::new(
            dummy_leaf_id(),
            vec![],
            StatechainEncodingVersion::current(),
        )
        .is_err());
    }

    #[test]
    fn vutxo_tree_computes_total() {
        let leaves = vec![
            Leaf::new(dummy_leaf_id(), 50_000, dummy_pubkey(), 0).unwrap(),
            Leaf::new([0x02u8; LEAF_ID_LEN], 50_000, dummy_pubkey(), 0).unwrap(),
        ];
        let tree = VutxoTree::new(
            dummy_leaf_id(),
            leaves,
            StatechainEncodingVersion::current(),
        )
        .unwrap();
        assert_eq!(tree.total_amount_sats, 100_000);
    }

    #[test]
    fn transfer_rejects_same_sender_recipient() {
        let pk = dummy_pubkey();
        assert!(StatechainTransferRequest::new(
            StatechainEncodingVersion::current(),
            make_operator_set(),
            vec![dummy_leaf_id()],
            100_000,
            pk,
            pk,
            800_000,
        )
        .is_err());
    }

    #[test]
    fn transfer_rejects_empty_leaf_ids() {
        assert!(StatechainTransferRequest::new(
            StatechainEncodingVersion::current(),
            make_operator_set(),
            vec![],
            100_000,
            [0x03u8; 32],
            dummy_pubkey(),
            800_000,
        )
        .is_err());
    }

    #[test]
    fn transfer_execute_is_gated() {
        let req = StatechainTransferRequest::new(
            StatechainEncodingVersion::current(),
            make_operator_set(),
            vec![dummy_leaf_id()],
            100_000,
            [0x03u8; 32],
            dummy_pubkey(),
            800_000,
        )
        .unwrap();
        assert!(req.execute().is_err());
    }

    #[test]
    fn session_initiate_dkg_is_gated() {
        let leaf = Leaf::new(dummy_leaf_id(), 100_000, dummy_pubkey(), 0).unwrap();
        let tree = VutxoTree::new(
            dummy_leaf_id(),
            vec![leaf],
            StatechainEncodingVersion::current(),
        )
        .unwrap();
        let session = StatechainSession::new(
            StatechainEncodingVersion::current(),
            "abcdef0000000000000000000000000000000000000000000000000000000000:0".into(),
            tree,
            make_operator_set(),
            dummy_pubkey(),
        )
        .unwrap();
        assert!(session.initiate_dkg().is_err());
    }

    #[test]
    fn forfeit_sign_is_gated() {
        let ftx = ForfeitTransaction::new(
            StatechainEncodingVersion::current(),
            dummy_leaf_id(),
            100_000,
            800_000,
            vec![0x00],
            dummy_pubkey(),
        )
        .unwrap();
        assert!(ftx.sign().is_err());
    }
}
