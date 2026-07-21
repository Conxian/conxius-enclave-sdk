//! FROST protocol boundary.
//!
//! This module deliberately stops at versioned, secret-safe structural
//! validation. It does not implement RFC 9591 key generation, DKG, nonce
//! handling, signing, verification, or aggregation. Every value-bearing
//! operation therefore remains an exact `ProtocolUnsupported` failure.

use crate::{
    protocol_unsupported, BoundaryValidationError, ConclaveError, ConclaveResult,
    UnsupportedOperation, UnsupportedProtocol,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};

pub const FROST_ENCODING_VERSION: u16 = 1;
pub const FROST_MAX_PARTICIPANTS: u16 = 255;

fn boundary_error(kind: BoundaryValidationError) -> ConclaveError {
    ConclaveError::BoundaryValidation(kind)
}

/// Version of the SDK-owned FROST envelope encoding.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostEncodingVersion(u16);

impl FrostEncodingVersion {
    pub fn new(version: u16) -> ConclaveResult<Self> {
        if version == FROST_ENCODING_VERSION {
            Ok(Self(version))
        } else {
            Err(boundary_error(
                BoundaryValidationError::InvalidEncodingVersion,
            ))
        }
    }

    pub const fn current() -> Self {
        Self(FROST_ENCODING_VERSION)
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }

    pub fn validate(self) -> ConclaveResult<()> {
        Self::new(self.0).map(|_| ())
    }
}

impl fmt::Debug for FrostEncodingVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FrostEncodingVersion")
            .field(&self.0)
            .finish()
    }
}

/// Ciphersuites are named at the boundary; cryptographic execution is not
/// provided by this crate path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrostCiphersuite {
    Secp256k1Sha256,
}

impl FrostCiphersuite {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Secp256k1Sha256 => "FROST-secp256k1-SHA256-v1",
        }
    }
}

/// Non-zero FROST participant identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FrostParticipantId(u16);

impl FrostParticipantId {
    pub fn new(identifier: u16) -> ConclaveResult<Self> {
        if identifier == 0 {
            Err(boundary_error(BoundaryValidationError::InvalidIdentifier))
        } else {
            Ok(Self(identifier))
        }
    }

    pub fn validate(self) -> ConclaveResult<()> {
        Self::new(self.0).map(|_| ())
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Opaque signing-session identifier. The bytes are an identifier only; no
/// nonce or secret material is accepted by this model.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FrostSessionId([u8; 16]);

impl FrostSessionId {
    pub fn new(identifier: [u8; 16]) -> ConclaveResult<Self> {
        if identifier == [0; 16] {
            Err(boundary_error(BoundaryValidationError::InvalidIdentifier))
        } else {
            Ok(Self(identifier))
        }
    }

    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }

    pub fn validate(self) -> ConclaveResult<()> {
        Self::new(self.0).map(|_| ())
    }
}

impl fmt::Debug for FrostSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrostSessionId")
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Validated threshold parameters for a FROST group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostThreshold {
    pub min_signers: u16,
    pub total_signers: u16,
}

impl FrostThreshold {
    pub fn new(min_signers: u16, total_signers: u16) -> ConclaveResult<Self> {
        if min_signers == 0
            || total_signers == 0
            || min_signers > total_signers
            || total_signers > FROST_MAX_PARTICIPANTS
        {
            return Err(boundary_error(BoundaryValidationError::InvalidThreshold));
        }
        Ok(Self {
            min_signers,
            total_signers,
        })
    }

    pub fn validate(self) -> ConclaveResult<()> {
        Self::new(self.min_signers, self.total_signers).map(|_| ())
    }
}

/// A unique, bounded participant set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostParticipantSet {
    participants: Vec<FrostParticipantId>,
}

impl FrostParticipantSet {
    pub fn new(participants: Vec<FrostParticipantId>) -> ConclaveResult<Self> {
        if participants.is_empty() || participants.len() > FROST_MAX_PARTICIPANTS as usize {
            return Err(boundary_error(BoundaryValidationError::InvalidThreshold));
        }

        for participant in &participants {
            participant.validate()?;
        }

        let unique: BTreeSet<_> = participants.iter().copied().collect();
        if unique.len() != participants.len() {
            return Err(boundary_error(BoundaryValidationError::DuplicateIdentifier));
        }

        Ok(Self { participants })
    }

    pub fn contains(&self, participant: FrostParticipantId) -> bool {
        self.participants.contains(&participant)
    }

    pub fn as_slice(&self) -> &[FrostParticipantId] {
        &self.participants
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        Self::new(self.participants.clone()).map(|_| ())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrostEnvelopeKind {
    PublicKeyPackage,
    Commitment,
    EncryptedShare,
    SignatureShare,
    Proof,
}

/// A public, opaque envelope descriptor. The payload itself never crosses or
/// serializes through this model; only a version, kind, digest, and length are
/// retained for structural correlation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostOpaqueEnvelope {
    pub encoding_version: FrostEncodingVersion,
    pub kind: FrostEnvelopeKind,
    pub digest: [u8; 32],
    pub payload_len: u32,
}

impl FrostOpaqueEnvelope {
    pub fn new(
        kind: FrostEnvelopeKind,
        digest: [u8; 32],
        payload_len: u32,
    ) -> ConclaveResult<Self> {
        let envelope = Self {
            encoding_version: FrostEncodingVersion::current(),
            kind,
            digest,
            payload_len,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        if self.digest == [0; 32] || self.payload_len == 0 {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        Ok(())
    }
}

impl fmt::Debug for FrostOpaqueEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrostOpaqueEnvelope")
            .field("encoding_version", &self.encoding_version)
            .field("kind", &self.kind)
            .field("digest", &"<redacted>")
            .field("payload_len", &self.payload_len)
            .finish()
    }
}

/// Public FROST package metadata. The group key is represented only by an
/// opaque envelope and is not a key-generation or signing implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostPublicKeyPackage {
    pub encoding_version: FrostEncodingVersion,
    pub ciphersuite: FrostCiphersuite,
    pub threshold: FrostThreshold,
    pub participants: FrostParticipantSet,
    pub group_public_key: FrostOpaqueEnvelope,
}

impl FrostPublicKeyPackage {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        self.threshold.validate()?;
        self.participants.validate()?;
        if self.participants.as_slice().len() != self.threshold.total_signers as usize {
            return Err(boundary_error(BoundaryValidationError::InvalidThreshold));
        }
        if self.group_public_key.kind != FrostEnvelopeKind::PublicKeyPackage {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        self.group_public_key.validate()
    }
}

/// Compatibility name for the public package boundary. It does not contain a
/// private key share or nonce.
pub type FrostKeyPackage = FrostPublicKeyPackage;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostSignatureShare {
    pub encoding_version: FrostEncodingVersion,
    pub session_id: FrostSessionId,
    pub signer_id: FrostParticipantId,
    pub share: FrostOpaqueEnvelope,
}

impl FrostSignatureShare {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        self.session_id.validate()?;
        self.signer_id.validate()?;
        self.share.validate()?;
        if self.share.kind != FrostEnvelopeKind::SignatureShare {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostDkgRound1Package {
    pub encoding_version: FrostEncodingVersion,
    pub session_id: FrostSessionId,
    pub signer_id: FrostParticipantId,
    pub commitments: Vec<FrostOpaqueEnvelope>,
    pub proof_of_knowledge: FrostOpaqueEnvelope,
}

impl FrostDkgRound1Package {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        self.session_id.validate()?;
        self.signer_id.validate()?;
        if self.commitments.is_empty() {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        for commitment in &self.commitments {
            commitment.validate()?;
            if commitment.kind != FrostEnvelopeKind::Commitment {
                return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
            }
        }
        self.proof_of_knowledge.validate()?;
        if self.proof_of_knowledge.kind != FrostEnvelopeKind::Proof {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostDkgRound2Package {
    pub encoding_version: FrostEncodingVersion,
    pub session_id: FrostSessionId,
    pub signer_id: FrostParticipantId,
    pub encrypted_shares: Vec<FrostEncryptedShare>,
}

impl FrostDkgRound2Package {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        self.session_id.validate()?;
        self.signer_id.validate()?;
        if self.encrypted_shares.is_empty() {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        let mut receivers = BTreeSet::new();
        for share in &self.encrypted_shares {
            share.validate()?;
            if !receivers.insert(share.receiver_id) {
                return Err(boundary_error(BoundaryValidationError::DuplicateIdentifier));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostEncryptedShare {
    pub receiver_id: FrostParticipantId,
    pub encrypted_share: FrostOpaqueEnvelope,
}

impl FrostEncryptedShare {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.receiver_id.validate()?;
        self.encrypted_share.validate()?;
        if self.encrypted_share.kind != FrostEnvelopeKind::EncryptedShare {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        Ok(())
    }
}

/// Structural signing-session ledger. It enforces session ownership and
/// one-submission-per-participant without interpreting a signature share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostSigningSession {
    pub encoding_version: FrostEncodingVersion,
    pub session_id: FrostSessionId,
    pub owner: FrostParticipantId,
    pub threshold: FrostThreshold,
    pub participants: FrostParticipantSet,
    accepted_signers: BTreeSet<FrostParticipantId>,
}

impl FrostSigningSession {
    pub fn new(
        session_id: FrostSessionId,
        owner: FrostParticipantId,
        threshold: FrostThreshold,
        participants: FrostParticipantSet,
    ) -> ConclaveResult<Self> {
        threshold.validate()?;
        participants.validate()?;
        if participants.as_slice().len() != threshold.total_signers as usize
            || !participants.contains(owner)
        {
            return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
        }
        Ok(Self {
            encoding_version: FrostEncodingVersion::current(),
            session_id,
            owner,
            threshold,
            participants,
            accepted_signers: BTreeSet::new(),
        })
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        self.session_id.validate()?;
        self.owner.validate()?;
        self.threshold.validate()?;
        self.participants.validate()?;
        if self.participants.as_slice().len() != self.threshold.total_signers as usize
            || !self.participants.contains(self.owner)
        {
            return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
        }
        for signer in &self.accepted_signers {
            signer.validate()?;
            if !self.participants.contains(*signer) {
                return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
            }
        }
        Ok(())
    }

    pub fn submit_share(
        &mut self,
        caller: FrostParticipantId,
        share: &FrostSignatureShare,
    ) -> ConclaveResult<()> {
        self.validate()?;
        if caller != self.owner {
            return Err(boundary_error(
                BoundaryValidationError::SessionOwnershipViolation,
            ));
        }
        share.validate()?;
        if share.session_id != self.session_id || !self.participants.contains(share.signer_id) {
            return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
        }
        if !self.accepted_signers.insert(share.signer_id) {
            return Err(boundary_error(BoundaryValidationError::DuplicateSubmission));
        }
        Ok(())
    }

    pub fn accepted_signer_count(&self) -> usize {
        self.accepted_signers.len()
    }
}

/// FROST operations are intentionally quarantined until the implementation
/// and evidence gates in `PROTOCOL_IMPLEMENTATION_ROADMAP.md` are complete.
#[derive(Debug, Default, Clone, Copy)]
pub struct FrostManager;

impl FrostManager {
    pub fn generate_key_package(
        _min_signers: u32,
        _total_signers: u32,
        _identifier: &str,
    ) -> ConclaveResult<FrostKeyPackage> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::KeyPackageGeneration,
        ))
    }

    pub fn generate_dkg_round1(
        &self,
        _signer_id: FrostParticipantId,
        _threshold: FrostThreshold,
    ) -> ConclaveResult<FrostDkgRound1Package> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::Dkg,
        ))
    }

    pub fn verify_dkg_round1(&self, _package: &FrostDkgRound1Package) -> ConclaveResult<bool> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::Dkg,
        ))
    }

    pub fn generate_dkg_round2(
        &self,
        _signer_id: FrostParticipantId,
        _other_signer_ids: FrostParticipantSet,
        _round1_package: &FrostDkgRound1Package,
    ) -> ConclaveResult<FrostDkgRound2Package> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::Dkg,
        ))
    }

    pub fn verify_received_share(
        &self,
        _receiver_id: FrostParticipantId,
        _round1_package: &FrostDkgRound1Package,
        _round2_package: &FrostDkgRound2Package,
    ) -> ConclaveResult<bool> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::Dkg,
        ))
    }

    pub fn aggregate_signatures(
        &self,
        _package: &FrostKeyPackage,
        _shares: Vec<FrostSignatureShare>,
        _message: &[u8],
    ) -> ConclaveResult<String> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::ThresholdSigning,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UnsupportedReason;

    fn envelope(kind: FrostEnvelopeKind) -> FrostOpaqueEnvelope {
        FrostOpaqueEnvelope::new(kind, [7; 32], 32).expect("valid opaque envelope")
    }

    fn participants() -> FrostParticipantSet {
        FrostParticipantSet::new(vec![
            FrostParticipantId::new(1).expect("valid participant"),
            FrostParticipantId::new(2).expect("valid participant"),
            FrostParticipantId::new(3).expect("valid participant"),
        ])
        .expect("valid participant set")
    }

    fn threshold() -> FrostThreshold {
        FrostThreshold::new(2, 3).expect("valid threshold")
    }

    fn session_id() -> FrostSessionId {
        FrostSessionId::new([1; 16]).expect("valid session id")
    }

    #[test]
    fn rejects_invalid_thresholds_identifiers_versions_and_duplicates() {
        assert!(matches!(
            FrostThreshold::new(0, 3),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidThreshold
            ))
        ));
        assert!(matches!(
            FrostThreshold::new(3, 2),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidThreshold
            ))
        ));
        assert!(matches!(
            FrostThreshold::new(1, FROST_MAX_PARTICIPANTS + 1),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidThreshold
            ))
        ));
        assert!(matches!(
            FrostParticipantId::new(0),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidIdentifier
            ))
        ));
        assert!(matches!(
            FrostEncodingVersion::new(2),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidEncodingVersion
            ))
        ));
        assert!(matches!(
            FrostParticipantSet::new(vec![
                FrostParticipantId::new(1).expect("valid participant"),
                FrostParticipantId::new(1).expect("valid participant"),
            ]),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::DuplicateIdentifier
            ))
        ));
    }

    #[test]
    fn signing_session_enforces_ownership_and_duplicate_replay() {
        let owner = FrostParticipantId::new(1).expect("valid owner");
        let signer = FrostParticipantId::new(2).expect("valid signer");
        let mut session =
            FrostSigningSession::new(session_id(), owner, threshold(), participants())
                .expect("valid session");
        let share = FrostSignatureShare {
            encoding_version: FrostEncodingVersion::current(),
            session_id: session_id(),
            signer_id: signer,
            share: envelope(FrostEnvelopeKind::SignatureShare),
        };

        assert!(matches!(
            session.submit_share(signer, &share),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::SessionOwnershipViolation
            ))
        ));
        assert_eq!(session.accepted_signer_count(), 0);
        assert!(session.submit_share(owner, &share).is_ok());
        assert_eq!(session.accepted_signer_count(), 1);
        assert!(matches!(
            session.submit_share(owner, &share),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::DuplicateSubmission
            ))
        ));
        assert_eq!(session.accepted_signer_count(), 1);
    }

    #[test]
    fn envelopes_and_errors_do_not_expose_secret_material() {
        let package = FrostSignatureShare {
            encoding_version: FrostEncodingVersion::current(),
            session_id: session_id(),
            signer_id: FrostParticipantId::new(1).expect("valid signer"),
            share: envelope(FrostEnvelopeKind::SignatureShare),
        };
        let json = serde_json::to_string(&package).expect("serializes envelope metadata");
        let debug = format!("{package:?}");
        assert!(!json.contains("private-share-material"));
        assert!(!debug.contains("private-share-material"));
        assert!(!debug.contains("[7, 7, 7"));

        let error =
            ConclaveError::BoundaryValidation(BoundaryValidationError::SessionOwnershipViolation);
        assert!(!error.to_string().contains("private-share-material"));
        let _ = serde_json::to_string(&error).expect("safe error serializes");
    }

    #[test]
    fn all_value_bearing_operations_remain_exactly_unsupported() {
        let manager = FrostManager;
        let participant = FrostParticipantId::new(1).expect("valid participant");
        let set = FrostParticipantSet::new(vec![participant]).expect("valid set");
        let threshold = FrostThreshold::new(1, 1).expect("valid threshold");
        let round1 = FrostDkgRound1Package {
            encoding_version: FrostEncodingVersion::current(),
            session_id: session_id(),
            signer_id: participant,
            commitments: vec![envelope(FrostEnvelopeKind::Commitment)],
            proof_of_knowledge: envelope(FrostEnvelopeKind::Proof),
        };
        let round2 = FrostDkgRound2Package {
            encoding_version: FrostEncodingVersion::current(),
            session_id: session_id(),
            signer_id: participant,
            encrypted_shares: vec![FrostEncryptedShare {
                receiver_id: participant,
                encrypted_share: envelope(FrostEnvelopeKind::EncryptedShare),
            }],
        };
        let package = FrostPublicKeyPackage {
            encoding_version: FrostEncodingVersion::current(),
            ciphersuite: FrostCiphersuite::Secp256k1Sha256,
            threshold,
            participants: set.clone(),
            group_public_key: envelope(FrostEnvelopeKind::PublicKeyPackage),
        };

        assert_unsupported(
            FrostManager::generate_key_package(1, 1, "session"),
            UnsupportedOperation::KeyPackageGeneration,
        );
        assert_unsupported(
            manager.generate_dkg_round1(participant, threshold),
            UnsupportedOperation::Dkg,
        );
        assert_unsupported(
            manager.verify_dkg_round1(&round1),
            UnsupportedOperation::Dkg,
        );
        assert_unsupported(
            manager.generate_dkg_round2(participant, set, &round1),
            UnsupportedOperation::Dkg,
        );
        assert_unsupported(
            manager.verify_received_share(participant, &round1, &round2),
            UnsupportedOperation::Dkg,
        );
        assert_unsupported(
            manager.aggregate_signatures(&package, Vec::new(), b"message"),
            UnsupportedOperation::ThresholdSigning,
        );
    }

    fn assert_unsupported<T>(result: ConclaveResult<T>, operation: UnsupportedOperation) {
        match result {
            Err(ConclaveError::ProtocolUnsupported {
                protocol: UnsupportedProtocol::Frost,
                operation: actual_operation,
                reason: UnsupportedReason::NoAuditedImplementation,
            }) => assert_eq!(actual_operation, operation),
            _ => panic!("expected typed FROST unsupported error"),
        }
    }
}
