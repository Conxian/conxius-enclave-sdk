//! ROAST threshold signing coordinator.
//!
//! ROAST (Robust Asynchronous Schnorr Threshold signatures) extends FROST
//! with malicious-signer robustness. This module models the coordinator
//! boundary: session lifecycle, participant management, commitment
//! collection, signing-package assembly, share collection, and aggregation.
//!
//! Without the `frost-crypto` feature, this module performs versioned
//! structural validation only and returns `ProtocolUnsupported` for every
//! value-bearing operation.

use crate::{
    protocol::frost::{
        FrostCiphersuite, FrostEncodingVersion, FrostKeyPackage, FrostOpaqueEnvelope,
        FrostParticipantId, FrostParticipantSet, FrostSignatureShare,
    },
    BoundaryValidationError, ConclaveError, ConclaveResult,
};
#[cfg(not(feature = "frost-crypto"))]
use crate::{protocol_unsupported, UnsupportedOperation, UnsupportedProtocol};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const ROAST_ENCODING_VERSION: u16 = 1;
pub const ROAST_MAX_SIGNERS: u16 = 255;
pub const ROAST_DEFAULT_MAX_RETRIES: u32 = 3;

fn boundary_error(kind: BoundaryValidationError) -> ConclaveError {
    ConclaveError::BoundaryValidation(kind)
}

// ── ROAST-specific types ──────────────────────────────────────────────

/// ROAST signing round identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RoastRoundId(u32);

impl RoastRoundId {
    pub fn new(id: u32) -> ConclaveResult<Self> {
        if id == 0 {
            Err(boundary_error(BoundaryValidationError::InvalidIdentifier))
        } else {
            Ok(Self(id))
        }
    }

    pub fn validate(self) -> ConclaveResult<()> {
        Self::new(self.0).map(|_| ())
    }
}

/// Commitment from a signer for a ROAST round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoastCommitment {
    pub encoding_version: FrostEncodingVersion,
    pub round_id: RoastRoundId,
    pub signer_id: FrostParticipantId,
    pub commitment: FrostOpaqueEnvelope,
}

impl RoastCommitment {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        self.round_id.validate()?;
        self.signer_id.validate()?;
        self.commitment.validate()?;
        Ok(())
    }
}

/// A signer that failed to produce a valid signature share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoastBlameReason {
    NoCommitment,
    InvalidCommitment,
    NoSignatureShare,
    InvalidSignatureShare,
}

/// Signers excluded from the current or future rounds due to misbehavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoastExclusionList {
    excluded: BTreeSet<FrostParticipantId>,
}

impl RoastExclusionList {
    pub fn new() -> Self {
        Self {
            excluded: BTreeSet::new(),
        }
    }

    pub fn exclude(&mut self, signer: FrostParticipantId) {
        self.excluded.insert(signer);
    }

    pub fn is_excluded(&self, signer: FrostParticipantId) -> bool {
        self.excluded.contains(&signer)
    }

    pub fn len(&self) -> usize {
        self.excluded.len()
    }

    pub fn is_empty(&self) -> bool {
        self.excluded.is_empty()
    }
}

impl Default for RoastExclusionList {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of a ROAST signing round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoastRoundOutcome {
    /// All shares collected and aggregated successfully.
    Aggregated { signature_hex: String },
    /// Round is incomplete — more shares needed.
    Pending { received: usize, required: usize },
    /// Round failed due to misbehaving signers.
    Failed {
        blamed: Vec<(FrostParticipantId, RoastBlameReason)>,
    },
}

// ── ROAST Coordinator ─────────────────────────────────────────────────

/// Coordinates ROAST threshold signing across a set of FROST participants.
///
/// The coordinator manages multiple signing rounds, tracks excluded signers,
/// and orchestrates commitment collection, signing-package assembly, share
/// collection, and signature aggregation.
///
/// Without `frost-crypto`, all value-bearing operations return
/// `ProtocolUnsupported`.
#[derive(Debug)]
pub struct RoastCoordinator {
    ciphersuite: FrostCiphersuite,
    max_retries: u32,
    exclusions: RoastExclusionList,
}

impl RoastCoordinator {
    pub fn new(ciphersuite: FrostCiphersuite) -> Self {
        Self {
            ciphersuite,
            max_retries: ROAST_DEFAULT_MAX_RETRIES,
            exclusions: RoastExclusionList::new(),
        }
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn ciphersuite(&self) -> FrostCiphersuite {
        self.ciphersuite
    }

    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }

    pub fn is_excluded(&self, signer: FrostParticipantId) -> bool {
        self.exclusions.is_excluded(signer)
    }

    pub fn excluded_count(&self) -> usize {
        self.exclusions.len()
    }

    /// Exclude a signer from all future rounds.
    pub fn exclude_signer(&mut self, signer: FrostParticipantId) -> ConclaveResult<()> {
        signer.validate()?;
        self.exclusions.exclude(signer);
        Ok(())
    }

    /// Start a new signing session for a threshold set of participants.
    ///
    /// Returns a [`RoastSigningSession`] that can collect commitments,
    /// assemble a signing package, collect shares, and aggregate.
    pub fn start_session(
        &self,
        key_package: &FrostKeyPackage,
        round_id: RoastRoundId,
    ) -> ConclaveResult<RoastSigningSession> {
        key_package.validate()?;
        round_id.validate()?;

        // Filter out excluded signers
        let active: Vec<FrostParticipantId> = key_package
            .participants
            .as_slice()
            .iter()
            .copied()
            .filter(|p| !self.exclusions.is_excluded(*p))
            .collect();

        if active.len() < key_package.threshold.min_signers as usize {
            return Err(ConclaveError::CryptoError(
                "ROAST: insufficient active signers after exclusions".into(),
            ));
        }

        let active_set = FrostParticipantSet::new(active).map_err(|e| {
            ConclaveError::CryptoError(format!("ROAST: active participant set: {e:?}"))
        })?;

        Ok(RoastSigningSession {
            round_id,
            key_package: key_package.clone(),
            active_participants: active_set,
            commitments: Vec::new(),
            shares: Vec::new(),
            signing_package_digest: None,
            retries: 0,
            round_outcome: None,
        })
    }

    // ── Value-bearing operations (frost-crypto only) ──────────────────

    /// Generate a key package suitable for ROAST coordination.
    #[cfg(feature = "frost-crypto")]
    pub fn generate_key_package(
        &mut self,
        min_signers: u32,
        total_signers: u32,
    ) -> ConclaveResult<FrostKeyPackage> {
        let mut ctx = crate::protocol::frost::FrostSigningContext::new();
        ctx.generate_key_package(min_signers, total_signers)
    }

    #[cfg(not(feature = "frost-crypto"))]
    pub fn generate_key_package(
        &mut self,
        _min_signers: u32,
        _total_signers: u32,
    ) -> ConclaveResult<FrostKeyPackage> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::KeyPackageGeneration,
        ))
    }
}

// ── ROAST Signing Session ─────────────────────────────────────────────

/// An active ROAST signing session.
///
/// Collects commitments from active signers, assembles the signing package,
/// collects signature shares, and aggregates the final Schnorr signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoastSigningSession {
    pub round_id: RoastRoundId,
    pub key_package: FrostKeyPackage,
    pub active_participants: FrostParticipantSet,
    pub commitments: Vec<RoastCommitment>,
    pub shares: Vec<FrostSignatureShare>,
    pub signing_package_digest: Option<[u8; 32]>,
    pub retries: u32,
    pub round_outcome: Option<RoastRoundOutcome>,
}

impl RoastSigningSession {
    /// Submit a commitment from a signer for this round.
    pub fn submit_commitment(&mut self, commitment: RoastCommitment) -> ConclaveResult<()> {
        commitment.validate()?;

        if commitment.round_id != self.round_id {
            return Err(boundary_error(BoundaryValidationError::InvalidObservation));
        }

        if !self.active_participants.contains(commitment.signer_id) {
            return Err(boundary_error(
                BoundaryValidationError::SessionOwnershipViolation,
            ));
        }

        // Reject duplicate signers
        if self
            .commitments
            .iter()
            .any(|c| c.signer_id == commitment.signer_id)
        {
            return Err(boundary_error(BoundaryValidationError::DuplicateSubmission));
        }

        self.commitments.push(commitment);
        Ok(())
    }

    /// Number of commitments collected.
    pub fn commitment_count(&self) -> usize {
        self.commitments.len()
    }

    /// Whether enough commitments have been collected to proceed.
    pub fn has_enough_commitments(&self) -> bool {
        self.commitment_count() >= self.key_package.threshold.min_signers as usize
    }

    /// Submit a signature share for this round.
    pub fn submit_share(&mut self, share: FrostSignatureShare) -> ConclaveResult<()> {
        share.validate()?;

        if !self.active_participants.contains(share.signer_id) {
            return Err(boundary_error(
                BoundaryValidationError::SessionOwnershipViolation,
            ));
        }

        if self.shares.iter().any(|s| s.signer_id == share.signer_id) {
            return Err(boundary_error(BoundaryValidationError::DuplicateSubmission));
        }

        self.shares.push(share);
        Ok(())
    }

    /// Number of signature shares collected.
    pub fn share_count(&self) -> usize {
        self.shares.len()
    }

    /// Whether enough shares have been collected to attempt aggregation.
    pub fn has_enough_shares(&self) -> bool {
        self.share_count() >= self.key_package.threshold.min_signers as usize
    }

    /// Check if all active signers have submitted shares.
    pub fn is_complete(&self) -> bool {
        self.share_count() >= self.active_participants.as_slice().len()
    }

    /// Set the signing package digest for this round.
    pub fn set_signing_package_digest(&mut self, digest: [u8; 32]) -> ConclaveResult<()> {
        if digest == [0; 32] {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        self.signing_package_digest = Some(digest);
        Ok(())
    }

    /// Identify signers who have not submitted valid commitments.
    pub fn identify_blamed(&self) -> Vec<(FrostParticipantId, RoastBlameReason)> {
        let mut blamed = Vec::new();
        let committed: BTreeSet<_> = self.commitments.iter().map(|c| c.signer_id).collect();

        for signer in self.active_participants.as_slice() {
            if !committed.contains(signer) {
                blamed.push((*signer, RoastBlameReason::NoCommitment));
            }
        }

        let shared: BTreeSet<_> = self.shares.iter().map(|s| s.signer_id).collect();
        for signer in committed {
            if !shared.contains(&signer) {
                blamed.push((signer, RoastBlameReason::NoSignatureShare));
            }
        }

        blamed
    }

    // ── Value-bearing operations ──────────────────────────────────────

    /// Assemble the signing package from collected commitments.
    #[cfg(feature = "frost-crypto")]
    pub fn assemble_signing_package(&mut self, message: &[u8]) -> ConclaveResult<()> {
        if !self.has_enough_commitments() {
            return Err(ConclaveError::CryptoError(
                "ROAST: insufficient commitments for signing package".into(),
            ));
        }

        // Compute SHA-256 of (message || commitments) as signing package digest
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(message);
        for c in &self.commitments {
            h.update(c.commitment.digest);
        }
        let digest: [u8; 32] = h.finalize().into();
        self.signing_package_digest = Some(digest);
        Ok(())
    }

    #[cfg(not(feature = "frost-crypto"))]
    pub fn assemble_signing_package(&mut self, _message: &[u8]) -> ConclaveResult<()> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::ThresholdSigning,
        ))
    }

    /// Aggregate collected signature shares into a Schnorr signature.
    #[cfg(feature = "frost-crypto")]
    pub fn aggregate(&mut self) -> ConclaveResult<RoastRoundOutcome> {
        if !self.has_enough_shares() {
            return Ok(RoastRoundOutcome::Pending {
                received: self.share_count(),
                required: self.key_package.threshold.min_signers as usize,
            });
        }

        // Delegate to the FrostSigningContext for raw-crypto aggregation.
        // The context bridges envelope digests ↔ raw ZF FROST bytes.
        let ctx = crate::protocol::frost::FrostSigningContext::new();
        let sig = ctx.aggregate_signatures(
            &self.key_package,
            &self.shares[..self.key_package.threshold.min_signers as usize],
        )?;

        let outcome = RoastRoundOutcome::Aggregated { signature_hex: sig };
        self.round_outcome = Some(outcome.clone());
        Ok(outcome)
    }

    #[cfg(not(feature = "frost-crypto"))]
    pub fn aggregate(&mut self) -> ConclaveResult<RoastRoundOutcome> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::ThresholdAggregation,
        ))
    }

    /// Attempt to finalize the round. If not enough shares, blame missing
    /// signers; if enough, aggregate.
    pub fn finalize_round(&mut self) -> ConclaveResult<RoastRoundOutcome> {
        if self.has_enough_shares() {
            return self.aggregate();
        }

        let blamed = self.identify_blamed();
        let outcome = RoastRoundOutcome::Failed { blamed };
        self.round_outcome = Some(outcome.clone());
        Ok(outcome)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::frost::{
        FrostCiphersuite, FrostEnvelopeKind, FrostKeyPackage, FrostOpaqueEnvelope,
        FrostParticipantId, FrostParticipantSet, FrostThreshold,
    };

    fn make_envelope(kind: FrostEnvelopeKind, digest_byte: u8) -> FrostOpaqueEnvelope {
        FrostOpaqueEnvelope::new(kind, [digest_byte; 32], 64).expect("valid envelope")
    }

    fn make_participant(id: u16) -> FrostParticipantId {
        FrostParticipantId::new(id).expect("valid participant")
    }

    fn make_key_package(n: u16, t: u16) -> FrostKeyPackage {
        let participants: Vec<FrostParticipantId> = (1..=n).map(make_participant).collect();
        FrostKeyPackage {
            encoding_version: FrostEncodingVersion::current(),
            ciphersuite: FrostCiphersuite::Secp256k1Sha256,
            threshold: FrostThreshold::new(t, n).expect("valid threshold"),
            participants: FrostParticipantSet::new(participants).expect("valid set"),
            group_public_key: make_envelope(FrostEnvelopeKind::PublicKeyPackage, 1),
        }
    }

    #[test]
    fn coordinator_rejects_session_when_too_many_excluded() {
        let mut coordinator = RoastCoordinator::new(FrostCiphersuite::Secp256k1Sha256);
        let kp = make_key_package(3, 2);

        // Exclude signers 1 and 2 — only signer 3 remains, below threshold of 2
        coordinator.exclude_signer(make_participant(1)).unwrap();
        coordinator.exclude_signer(make_participant(2)).unwrap();

        assert!(coordinator
            .start_session(&kp, RoastRoundId::new(1).unwrap())
            .is_err());
    }

    #[test]
    fn session_collects_commitments_and_shares() {
        let coordinator = RoastCoordinator::new(FrostCiphersuite::Secp256k1Sha256);
        let kp = make_key_package(3, 2);
        let mut session = coordinator
            .start_session(&kp, RoastRoundId::new(1).unwrap())
            .expect("valid session");

        let c1 = RoastCommitment {
            encoding_version: FrostEncodingVersion::current(),
            round_id: RoastRoundId::new(1).unwrap(),
            signer_id: make_participant(1),
            commitment: make_envelope(FrostEnvelopeKind::Commitment, 2),
        };
        let c2 = RoastCommitment {
            encoding_version: FrostEncodingVersion::current(),
            round_id: RoastRoundId::new(1).unwrap(),
            signer_id: make_participant(2),
            commitment: make_envelope(FrostEnvelopeKind::Commitment, 3),
        };

        session.submit_commitment(c1).expect("commitment 1");
        session.submit_commitment(c2).expect("commitment 2");

        assert_eq!(session.commitment_count(), 2);
        assert!(session.has_enough_commitments());

        // Duplicate commitment rejected
        let c1_dup = RoastCommitment {
            encoding_version: FrostEncodingVersion::current(),
            round_id: RoastRoundId::new(1).unwrap(),
            signer_id: make_participant(1),
            commitment: make_envelope(FrostEnvelopeKind::Commitment, 9),
        };
        assert!(matches!(
            session.submit_commitment(c1_dup),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::DuplicateSubmission
            ))
        ));
    }

    #[test]
    fn round_with_insufficient_shares_returns_failed_with_blame() {
        let coordinator = RoastCoordinator::new(FrostCiphersuite::Secp256k1Sha256);
        let kp = make_key_package(3, 2);
        let mut session = coordinator
            .start_session(&kp, RoastRoundId::new(1).unwrap())
            .expect("valid session");

        // Submit only 1 commitment (need 2 for threshold)
        session
            .submit_commitment(RoastCommitment {
                encoding_version: FrostEncodingVersion::current(),
                round_id: RoastRoundId::new(1).unwrap(),
                signer_id: make_participant(1),
                commitment: make_envelope(FrostEnvelopeKind::Commitment, 2),
            })
            .unwrap();

        // With 0 shares and threshold 2, finalize should blame missing signers
        let outcome = session.finalize_round().expect("finalize returns outcome");
        match outcome {
            RoastRoundOutcome::Failed { blamed } => {
                assert!(!blamed.is_empty());
            }
            _ => panic!("expected Failed outcome"),
        }
    }

    #[test]
    fn session_rejects_wrong_round_commitment() {
        let coordinator = RoastCoordinator::new(FrostCiphersuite::Secp256k1Sha256);
        let kp = make_key_package(3, 2);
        let mut session = coordinator
            .start_session(&kp, RoastRoundId::new(1).unwrap())
            .expect("valid session");

        let wrong_round = RoastCommitment {
            encoding_version: FrostEncodingVersion::current(),
            round_id: RoastRoundId::new(2).unwrap(),
            signer_id: make_participant(1),
            commitment: make_envelope(FrostEnvelopeKind::Commitment, 2),
        };

        assert!(matches!(
            session.submit_commitment(wrong_round),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidObservation
            ))
        ));
    }

    #[test]
    fn session_rejects_non_member_signer() {
        let coordinator = RoastCoordinator::new(FrostCiphersuite::Secp256k1Sha256);
        let kp = make_key_package(3, 2);
        let mut session = coordinator
            .start_session(&kp, RoastRoundId::new(1).unwrap())
            .expect("valid session");

        let outsider = RoastCommitment {
            encoding_version: FrostEncodingVersion::current(),
            round_id: RoastRoundId::new(1).unwrap(),
            signer_id: make_participant(99),
            commitment: make_envelope(FrostEnvelopeKind::Commitment, 2),
        };

        assert!(matches!(
            session.submit_commitment(outsider),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::SessionOwnershipViolation
            ))
        ));
    }

    #[test]
    fn exclusion_list_works() {
        let mut exclusions = RoastExclusionList::new();
        assert!(exclusions.is_empty());

        let signer = make_participant(7);
        exclusions.exclude(signer);
        assert!(exclusions.is_excluded(signer));
        assert_eq!(exclusions.len(), 1);
    }

    #[test]
    #[cfg(not(feature = "frost-crypto"))]
    fn value_bearing_operations_are_unsupported_without_frost_crypto() {
        let mut coordinator = RoastCoordinator::new(FrostCiphersuite::Secp256k1Sha256);
        let kp = make_key_package(3, 2);
        let mut session = coordinator
            .start_session(&kp, RoastRoundId::new(1).unwrap())
            .expect("valid session");

        assert!(matches!(
            coordinator.generate_key_package(2, 3),
            Err(ConclaveError::ProtocolUnsupported { .. })
        ));
        assert!(matches!(
            session.assemble_signing_package(b"message"),
            Err(ConclaveError::ProtocolUnsupported { .. })
        ));
        assert!(matches!(
            session.aggregate(),
            Err(ConclaveError::ProtocolUnsupported { .. })
        ));
    }
}
