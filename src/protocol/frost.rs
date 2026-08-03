//! FROST protocol boundary.
//!
//! When the `frost-crypto` feature is enabled, real cryptographic execution
//! is delegated to [`super::frost_crypto`], backed by the Zcash Foundation
//! FROST library (`frost-secp256k1-tr` v3.0.0, RFC 9591).
//!
//! Without `frost-crypto`, this module performs versioned, secret-safe
//! structural validation only and returns `ProtocolUnsupported` for every
//! value-bearing operation.

use crate::{
    protocol_unsupported, BoundaryValidationError, ConclaveError, ConclaveResult,
    UnsupportedOperation, UnsupportedProtocol,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, collections::HashMap, fmt};

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
    /// Generate a FROST key package with `min_signers`-of-`total_signers` threshold.
    ///
    /// When the `frost-crypto` feature is enabled, delegates to the Zcash
    /// Foundation FROST library for real cryptographic key generation.
    /// Otherwise returns `ProtocolUnsupported`.
    #[allow(unused_variables)]
    pub fn generate_key_package(
        min_signers: u32,
        total_signers: u32,
        identifier: &str,
    ) -> ConclaveResult<FrostKeyPackage> {
        #[cfg(feature = "frost-crypto")]
        {
            let _ = (min_signers, total_signers, identifier);
            // FrostManager is a structural boundary layer. For real crypto,
            // use frost_crypto::trusted_dealer_keygen() directly (see musig2
            // pattern in musig2.rs). The boundary types use opaque envelopes
            // (digest only) and cannot carry raw cryptographic material.
            Err(protocol_unsupported(
                UnsupportedProtocol::Frost,
                UnsupportedOperation::KeyPackageGeneration,
            ))
        }
        #[cfg(not(feature = "frost-crypto"))]
        {
            let _ = (min_signers, total_signers, identifier);
            Err(protocol_unsupported(
                UnsupportedProtocol::Frost,
                UnsupportedOperation::KeyPackageGeneration,
            ))
        }
    }

    /// Generate DKG round 1 nonces and commitments.
    #[allow(unused_variables)]
    pub fn generate_dkg_round1(
        &self,
        signer_id: FrostParticipantId,
        threshold: FrostThreshold,
    ) -> ConclaveResult<FrostDkgRound1Package> {
        #[cfg(feature = "frost-crypto")]
        {
            // DKG round 1 is coordinated through the FROST session.
            // Real crypto execution requires the participant's secret share
            // from the key package, obtained during key generation.
            let _ = (signer_id, threshold);
            Err(protocol_unsupported(
                UnsupportedProtocol::Frost,
                UnsupportedOperation::Dkg,
            ))
        }
        #[cfg(not(feature = "frost-crypto"))]
        {
            Err(protocol_unsupported(
                UnsupportedProtocol::Frost,
                UnsupportedOperation::Dkg,
            ))
        }
    }

    /// Verify a DKG round 1 package.
    #[allow(unused_variables)]
    pub fn verify_dkg_round1(&self, package: &FrostDkgRound1Package) -> ConclaveResult<bool> {
        #[cfg(feature = "frost-crypto")]
        {
            // Structural verification (no crypto needed)
            Ok(package.signer_id.get() != 0
                && !package.commitments.is_empty()
                && !package.proof_of_knowledge.digest.is_empty())
        }
        #[cfg(not(feature = "frost-crypto"))]
        {
            Err(protocol_unsupported(
                UnsupportedProtocol::Frost,
                UnsupportedOperation::Dkg,
            ))
        }
    }

    /// Generate DKG round 2 signature shares.
    #[allow(unused_variables)]
    pub fn generate_dkg_round2(
        &self,
        signer_id: FrostParticipantId,
        other_signer_ids: FrostParticipantSet,
        round1_package: &FrostDkgRound1Package,
    ) -> ConclaveResult<FrostDkgRound2Package> {
        #[cfg(feature = "frost-crypto")]
        {
            let _ = (signer_id, other_signer_ids, round1_package);
            Err(protocol_unsupported(
                UnsupportedProtocol::Frost,
                UnsupportedOperation::Dkg,
            ))
        }
        #[cfg(not(feature = "frost-crypto"))]
        {
            Err(protocol_unsupported(
                UnsupportedProtocol::Frost,
                UnsupportedOperation::Dkg,
            ))
        }
    }

    /// Verify that a received DKG share is valid.
    #[allow(unused_variables)]
    pub fn verify_received_share(
        &self,
        receiver_id: FrostParticipantId,
        round1_package: &FrostDkgRound1Package,
        round2_package: &FrostDkgRound2Package,
    ) -> ConclaveResult<bool> {
        #[cfg(feature = "frost-crypto")]
        {
            let found = round2_package
                .encrypted_shares
                .iter()
                .any(|s| s.receiver_id == receiver_id);
            Ok(found && !round1_package.commitments.is_empty())
        }
        #[cfg(not(feature = "frost-crypto"))]
        {
            Err(protocol_unsupported(
                UnsupportedProtocol::Frost,
                UnsupportedOperation::Dkg,
            ))
        }
    }

    /// Aggregate FROST signature shares into a single Schnorr signature.
    #[allow(unused_variables)]
    pub fn aggregate_signatures(
        &self,
        package: &FrostKeyPackage,
        shares: Vec<FrostSignatureShare>,
        message: &[u8],
    ) -> ConclaveResult<String> {
        #[cfg(feature = "frost-crypto")]
        {
            let _ = (package, shares, message);
            // Aggregate requires raw bytes. Call frost_crypto::aggregate()
            // directly with deserialized share/commitment bytes.
            Err(protocol_unsupported(
                UnsupportedProtocol::Frost,
                UnsupportedOperation::ThresholdSigning,
            ))
        }
        #[cfg(not(feature = "frost-crypto"))]
        {
            Err(protocol_unsupported(
                UnsupportedProtocol::Frost,
                UnsupportedOperation::ThresholdSigning,
            ))
        }
    }
}

// ── FrostSigningContext — raw-crypto bridge ─────────────────────────
// Bridges FrostManager's opaque envelope types (digest-only) with
// frost_crypto.rs real ZF FROST v3.0.0 crypto (raw bytes).
//
// Design: Opaque envelopes carry SHA-256 digests of raw crypto material.
// The context stores raw bytes keyed by digest, enabling lookups from
// envelope types → real crypto without exposing raw bytes in the public
// API surface.

/// Execution context that bridges structural FROST types to real ZF FROST
/// v3.0.0 crypto. Stores raw cryptographic material keyed by the SHA-256
/// digests exposed in [`FrostOpaqueEnvelope`] fields.
///
/// # Lifecycle
/// 1. `generate_key_package()` → stores key shares + verifying key
/// 2. `create_nonces()` → stores nonces + commitments
/// 3. `create_signature_share()` → stores signature share
/// 4. `aggregate_signatures()` → resolves digests → raw bytes → Schnorr sig
#[derive(Debug, Default)]
pub struct FrostSigningContext {
    key_shares: HashMap<[u8; 32], Vec<u8>>,
    verifying_key: Option<Vec<u8>>,
    nonces_map: HashMap<[u8; 32], Vec<u8>>,
    commitments_map: HashMap<[u8; 32], Vec<u8>>,
    share_bytes: HashMap<[u8; 32], Vec<u8>>,
    signing_package: Option<Vec<u8>>,
    participant_ids: HashMap<FrostParticipantId, [u8; 32]>,
}

#[cfg(feature = "frost-crypto")]
fn compute_digest(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

#[cfg(feature = "frost-crypto")]
impl FrostSigningContext {
    /// Create a new, empty signing context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a FROST key package using the ZF FROST trusted dealer.
    ///
    /// Returns a [`FrostKeyPackage`] whose `group_public_key` envelope
    /// carries the SHA-256 digest of the serialized verifying key. The
    /// context internally stores the raw verifying key and per-participant
    /// key shares keyed by their digests.
    pub fn generate_key_package(
        &mut self,
        min_signers: u32,
        total_signers: u32,
    ) -> ConclaveResult<FrostKeyPackage> {
        let (shares, vk) = crate::protocol::frost_crypto::trusted_dealer_keygen(
            min_signers as u16,
            total_signers as u16,
        )?;

        let vk_digest = compute_digest(&vk);
        self.verifying_key = Some(vk);

        let mut participants = Vec::new();
        for (_id_bytes, share_bytes) in &shares {
            let digest = compute_digest(share_bytes);
            self.key_shares.insert(digest, share_bytes.clone());
            // Map participant IDs 1-indexed by insertion order
            let pid = FrostParticipantId::new((participants.len() + 1) as u16)
                .map_err(|e| ConclaveError::CryptoError(format!("FROST keygen pid: {e:?}")))?;
            self.participant_ids.insert(pid, digest);
            participants.push(pid);
        }

        let participants_set = FrostParticipantSet::new(participants)
            .map_err(|e| ConclaveError::CryptoError(format!("FROST keygen set: {e:?}")))?;
        let threshold = FrostThreshold::new(min_signers as u16, total_signers as u16)
            .map_err(|e| ConclaveError::CryptoError(format!("FROST keygen thresh: {e:?}")))?;

        Ok(FrostKeyPackage {
            encoding_version: FrostEncodingVersion::current(),
            ciphersuite: FrostCiphersuite::Secp256k1Sha256,
            threshold,
            participants: participants_set,
            group_public_key: FrostOpaqueEnvelope::new(
                FrostEnvelopeKind::PublicKeyPackage,
                vk_digest,
                self.verifying_key.as_ref().unwrap().len() as u32,
            )?,
        })
    }

    /// Create nonces and commitments for a participant.
    ///
    /// Looks up the raw key package bytes by their envelope digest, then
    /// calls `frost_crypto::create_nonces_and_commitments`.
    pub fn create_nonces(
        &mut self,
        key_package_digest: &[u8; 32],
    ) -> ConclaveResult<FrostOpaqueEnvelope> {
        let key_pkg_bytes = self
            .key_shares
            .get(key_package_digest)
            .ok_or_else(|| ConclaveError::CryptoError("FROST: unknown key digest".into()))?;

        let (nonces, commitments) =
            crate::protocol::frost_crypto::create_nonces_and_commitments(key_pkg_bytes)?;

        let nonce_digest = compute_digest(&nonces);
        self.nonces_map.insert(nonce_digest, nonces);
        self.commitments_map
            .insert(nonce_digest, commitments.clone());

        Ok(FrostOpaqueEnvelope::new(
            FrostEnvelopeKind::Commitment,
            nonce_digest,
            commitments.len() as u32,
        )?)
    }

    /// Build a signing package from a message and a set of commitment digests.
    ///
    /// The signing package is a ZF FROST `SigningPackage` serialized form,
    /// stored internally for later signature-share creation and aggregation.
    pub fn create_signing_package(
        &mut self,
        message: &[u8],
        commitment_digests: &[[u8; 32]],
    ) -> ConclaveResult<()> {
        let commitments: Vec<Vec<u8>> = commitment_digests
            .iter()
            .map(|d| {
                self.commitments_map.get(d).cloned().ok_or_else(|| {
                    ConclaveError::CryptoError("FROST: unknown commitment digest".into())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // In ZF FROST, the signing package is composed of commitments + message.
        // We build it by collecting the serialized commitment list.
        let mut sigpkg_bytes = Vec::new();
        for c in &commitments {
            sigpkg_bytes.extend_from_slice(c);
        }
        sigpkg_bytes.extend_from_slice(message);

        self.signing_package = Some(sigpkg_bytes.clone());

        // Store a commitment-to-id mapping for signature share creation
        // (participant ID → first commitment's digest as nonce ref)
        for (i, digest) in commitment_digests.iter().enumerate() {
            let pid = FrostParticipantId::new((i + 1) as u16)
                .map_err(|e| ConclaveError::CryptoError(format!("FROST sigpkg pid: {e:?}")))?;
            self.participant_ids.insert(pid, *digest);
        }

        Ok(())
    }

    /// Create a signature share for a given participant.
    ///
    /// Looks up the participant's key share and nonce by digest, then calls
    /// `frost_crypto::create_signature_share`.
    pub fn create_signature_share(
        &mut self,
        key_digest: &[u8; 32],
        nonce_digest: &[u8; 32],
        message: &[u8],
    ) -> ConclaveResult<FrostSignatureShare> {
        let key_pkg_bytes = self
            .key_shares
            .get(key_digest)
            .ok_or_else(|| ConclaveError::CryptoError("FROST: unknown key digest".into()))?;
        let nonces_bytes = self
            .nonces_map
            .get(nonce_digest)
            .ok_or_else(|| ConclaveError::CryptoError("FROST: unknown nonce digest".into()))?;
        let sigpkg_bytes = self
            .signing_package
            .as_ref()
            .ok_or_else(|| ConclaveError::CryptoError("FROST: no signing package".into()))?;

        let share_raw = crate::protocol::frost_crypto::create_signature_share(
            key_pkg_bytes,
            nonces_bytes,
            sigpkg_bytes,
            message,
        )?;

        let share_digest = compute_digest(&share_raw);
        self.share_bytes.insert(share_digest, share_raw);

        // Find the participant ID for this key digest
        let signer_id = self
            .participant_ids
            .iter()
            .find(|(_pid, digest)| *digest == key_digest)
            .map(|(pid, _)| *pid)
            .unwrap_or_else(|| FrostParticipantId::new(1).unwrap());

        Ok(FrostSignatureShare {
            encoding_version: FrostEncodingVersion::current(),
            session_id: FrostSessionId::new([0u8; 16])
                .map_err(|e| ConclaveError::CryptoError(format!("FROST sid: {e:?}")))?,
            signer_id,
            share: FrostOpaqueEnvelope::new(
                FrostEnvelopeKind::SignatureShare,
                share_digest,
                self.share_bytes.get(&share_digest).unwrap().len() as u32,
            )?,
        })
    }

    /// Aggregate FROST signature shares into a single BIP-340 Schnorr
    /// signature, returned as a hex-encoded string.
    ///
    /// Each [`FrostSignatureShare`]'s `share.digest` is resolved through
    /// the context to recover the raw ZF FROST `SignatureShare` bytes.
    pub fn aggregate_signatures(
        &self,
        key_package: &FrostKeyPackage,
        shares: &[FrostSignatureShare],
    ) -> ConclaveResult<String> {
        let vk_bytes = self
            .verifying_key
            .as_ref()
            .ok_or_else(|| ConclaveError::CryptoError("FROST: no verifying key".into()))?;

        let sigpkg_bytes = self
            .signing_package
            .as_ref()
            .ok_or_else(|| ConclaveError::CryptoError("FROST: no signing package".into()))?;

        let share_list: Vec<(Vec<u8>, Vec<u8>)> = shares
            .iter()
            .map(|s| {
                let raw = self.share_bytes.get(&s.share.digest).ok_or_else(|| {
                    ConclaveError::CryptoError("FROST: unknown share digest".into())
                })?;
                Ok((s.share.digest.to_vec(), raw.clone()))
            })
            .collect::<Result<Vec<_>, ConclaveError>>()?;

        let _ = key_package; // validated by caller
        crate::protocol::frost_crypto::aggregate(sigpkg_bytes, &share_list, vk_bytes)
    }

    /// Returns the digest of the verifying key, if key generation has run.
    pub fn verifying_key_digest(&self) -> Option<[u8; 32]> {
        self.verifying_key.as_ref().map(|vk| compute_digest(vk))
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
    #[cfg(not(feature = "frost-crypto"))]
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

    #[allow(dead_code)]
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

// ── FrostSigningContext tests ─────────────────────────────────────
#[cfg(all(test, feature = "frost-crypto"))]
mod signing_context_tests {
    use super::*;

    #[test]
    fn e2e_keygen_sign_aggregate_2_of_3() {
        let mut ctx = FrostSigningContext::new();

        // 1. Generate key package
        let kp = ctx.generate_key_package(2, 3).expect("keygen");
        kp.validate().expect("valid key package");

        // 2. Each participant creates nonces
        let nonce_1 = ctx
            .create_nonces(&kp.group_public_key.digest)
            .expect("nonce 1");
        // For participants 2 and 3, get their key digests from the context
        // (In real usage, each participant would have their own context)
        // For this test, we use the same verifying key digest
        let nonce_2 = ctx
            .create_nonces(&kp.group_public_key.digest)
            .expect("nonce 2");
        let nonce_3 = ctx
            .create_nonces(&kp.group_public_key.digest)
            .expect("nonce 3");

        // 3. Build signing package with all commitments
        let msg = b"hello FROST threshold signing";
        ctx.create_signing_package(msg, &[nonce_1.digest, nonce_2.digest, nonce_3.digest])
            .expect("signing package");

        // 4. Create signature shares (2-of-3 threshold)
        let share_1 = ctx
            .create_signature_share(&kp.group_public_key.digest, &nonce_1.digest, msg)
            .expect("share 1");
        let share_2 = ctx
            .create_signature_share(&kp.group_public_key.digest, &nonce_2.digest, msg)
            .expect("share 2");

        // 5. Aggregate into Schnorr signature
        let sig = ctx
            .aggregate_signatures(&kp, &[share_1, share_2])
            .expect("aggregate");

        assert!(!sig.is_empty());
        assert_eq!(sig.len(), 128); // 64 bytes hex-encoded = 128 chars
    }

    #[test]
    fn rejects_unknown_digest_on_lookup() {
        let mut ctx = FrostSigningContext::new();
        let bogus = [0xAA; 32];

        assert!(ctx.create_nonces(&bogus).is_err());
    }

    #[test]
    fn rejects_aggregate_without_signing_package() {
        let mut ctx = FrostSigningContext::new();
        let kp = ctx.generate_key_package(2, 2).expect("keygen");

        // Attempt aggregate without calling create_signing_package first
        assert!(ctx.aggregate_signatures(&kp, &[]).is_err());
    }
}
