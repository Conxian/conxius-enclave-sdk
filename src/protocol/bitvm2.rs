//! BitVM2 protocol boundary.
//!
//! This module models roles, instances, commitments, chain observations,
//! challenge windows, transaction templates, disprove envelopes, backends,
//! and monitoring state. It does not post commitments, construct or sign
//! transactions, verify proofs, resolve challenges, or access a network.

use crate::protocol::ark::{ArkTransactionId, VUtxoDescriptor};
use crate::protocol::bitvm::BitVmManager;
use crate::{
    protocol_unsupported, BoundaryValidationError, ConclaveError, ConclaveResult,
    UnsupportedOperation, UnsupportedProtocol,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, sync::Arc};

pub const BITVM2_ENCODING_VERSION: u16 = 1;

fn boundary_error(kind: BoundaryValidationError) -> ConclaveError {
    ConclaveError::BoundaryValidation(kind)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2EncodingVersion(u16);

impl BitVm2EncodingVersion {
    pub fn new(version: u16) -> ConclaveResult<Self> {
        if version == BITVM2_ENCODING_VERSION {
            Ok(Self(version))
        } else {
            Err(boundary_error(
                BoundaryValidationError::InvalidEncodingVersion,
            ))
        }
    }

    pub const fn current() -> Self {
        Self(BITVM2_ENCODING_VERSION)
    }

    pub fn validate(self) -> ConclaveResult<()> {
        Self::new(self.0).map(|_| ())
    }
}

macro_rules! bytes_id {
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

bytes_id!(BitVm2InstanceId, 16);
bytes_id!(BitVm2CommitmentId, 16);
bytes_id!(BitVm2ObservationId, 16);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BitVm2ChainId(String);

impl BitVm2ChainId {
    pub fn new(value: impl Into<String>) -> ConclaveResult<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 64 || !value.is_ascii() {
            return Err(boundary_error(BoundaryValidationError::InvalidIdentifier));
        }
        Ok(Self(value))
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitVm2Role {
    Operator,
    Challenger,
    Verifier,
    Monitor,
}

/// Challenge-window semantics are inclusive at both boundaries. This is a
/// local structural rule only; it is not a chain observation or timeout proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2ChallengeWindow {
    pub start_block: u64,
    pub end_block: u64,
}

impl BitVm2ChallengeWindow {
    pub fn new(start_block: u64, end_block: u64) -> ConclaveResult<Self> {
        if end_block < start_block {
            return Err(boundary_error(
                BoundaryValidationError::InvalidChallengeWindow,
            ));
        }
        Ok(Self {
            start_block,
            end_block,
        })
    }

    pub const fn contains(self, block_height: u64) -> bool {
        block_height >= self.start_block && block_height <= self.end_block
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitVm2ObservationKind {
    CommitmentPosted,
    ChallengeObserved,
    ResolutionObserved,
    TimeoutObserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalChainObservation {
    pub encoding_version: BitVm2EncodingVersion,
    pub observation_id: BitVm2ObservationId,
    pub instance_id: BitVm2InstanceId,
    pub chain_id: BitVm2ChainId,
    pub kind: BitVm2ObservationKind,
    pub block_height: u64,
    pub event_digest: [u8; 32],
}

impl ExternalChainObservation {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        self.observation_id.validate()?;
        self.instance_id.validate()?;
        self.chain_id.validate()?;
        if self.event_digest == [0; 32] {
            return Err(boundary_error(BoundaryValidationError::InvalidObservation));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationOutcome {
    Recorded,
    AlreadyKnown,
}

/// Durable monitor state is fed only by externally observed chain events.
/// Replaying the same event is idempotent; reusing an observation ID for a
/// different event is rejected as a conflict.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2ObservationLedger {
    observations: HashMap<BitVm2ObservationId, ExternalChainObservation>,
}

impl BitVm2ObservationLedger {
    pub fn observe(
        &mut self,
        observation: ExternalChainObservation,
    ) -> ConclaveResult<ObservationOutcome> {
        observation.validate()?;
        match self.observations.get(&observation.observation_id) {
            Some(existing) if existing == &observation => Ok(ObservationOutcome::AlreadyKnown),
            Some(_) => Err(boundary_error(BoundaryValidationError::ReplayConflict)),
            None => {
                self.observations
                    .insert(observation.observation_id, observation);
                Ok(ObservationOutcome::Recorded)
            }
        }
    }

    pub fn len(&self) -> usize {
        self.observations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitVm2Backend {
    Unconfigured,
    ProviderOwned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2TransactionTemplate {
    pub encoding_version: BitVm2EncodingVersion,
    pub instance_id: BitVm2InstanceId,
    pub template_digest: [u8; 32],
    pub input_count: u16,
    pub output_count: u16,
}

impl BitVm2TransactionTemplate {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        self.instance_id.validate()?;
        if self.template_digest == [0; 32] || self.output_count == 0 {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2DisproveEnvelope {
    pub encoding_version: BitVm2EncodingVersion,
    pub digest: [u8; 32],
    pub payload_len: u32,
}

impl BitVm2DisproveEnvelope {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        if self.digest == [0; 32] || self.payload_len == 0 {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        Ok(())
    }
}

/// Challenge phase in the BitVM2 dispute protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengePhase {
    None,
    Commitment,
    Challenge,
    ResolvedPenalty,
    ResolvedRelease,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2ChallengeStatus {
    pub phase: ChallengePhase,
    pub instance_id: BitVm2InstanceId,
    pub commitment_id: BitVm2CommitmentId,
    pub commitment_txid: Option<ArkTransactionId>,
    pub challenge_txid: Option<ArkTransactionId>,
    pub challenge_block: Option<u64>,
    pub resolution: Option<BitVm2ObservationId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2ForfeitTransaction {
    pub encoding_version: BitVm2EncodingVersion,
    pub instance_id: BitVm2InstanceId,
    pub commitment_id: BitVm2CommitmentId,
    pub vutxo: VUtxoDescriptor,
    pub tree_root: ArkTransactionId,
    pub template: BitVm2TransactionTemplate,
    pub challenge_window: BitVm2ChallengeWindow,
    pub csv_delay: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2Commitment {
    pub encoding_version: BitVm2EncodingVersion,
    pub instance_id: BitVm2InstanceId,
    pub commitment_id: BitVm2CommitmentId,
    pub role: BitVm2Role,
    pub state_root_hash: [u8; 32],
    pub vtxo_count: u32,
    pub merkle_root: [u8; 32],
    pub taproot_internal_key: [u8; 32],
    pub block_height: u64,
    pub challenge_window: BitVm2ChallengeWindow,
}

impl BitVm2Commitment {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        self.instance_id.validate()?;
        self.commitment_id.validate()?;
        self.challenge_window.validate()?;
        if self.state_root_hash == [0; 32]
            || self.merkle_root == [0; 32]
            || self.taproot_internal_key == [0; 32]
            || self.vtxo_count == 0
        {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        Ok(())
    }
}

impl BitVm2ChallengeWindow {
    pub fn validate(self) -> ConclaveResult<()> {
        Self::new(self.start_block, self.end_block).map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2ChallengeResponse {
    pub encoding_version: BitVm2EncodingVersion,
    pub instance_id: BitVm2InstanceId,
    pub commitment_id: BitVm2CommitmentId,
    pub tap_index: u32,
    pub disprove: BitVm2DisproveEnvelope,
    pub expected_output_hash: [u8; 32],
}

impl BitVm2ChallengeResponse {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        self.instance_id.validate()?;
        self.commitment_id.validate()?;
        self.disprove.validate()?;
        if self.expected_output_hash == [0; 32] {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        Ok(())
    }
}

// ── Groth16 Proof Verification (P0) ──────────────────────────────────
//
// BitVM2 uses Groth16 succinct non-interactive zero-knowledge proofs for
// the disprove protocol. The operator constructs a Groth16 proof that a
// committed state transition is invalid; the verifier checks the proof
// against the on-chain verification key.
//
// This module models the proof envelope, verification key, and verifier
// boundary. With the `groth16` feature enabled, the verifier performs the real
// BLS12-381 pairing check; without it, verification fails closed with
// `VerificationUnavailable`.

// Serde helper wrappers for large byte arrays (serde only supports arrays up to [u8; 32]).
struct Bytes48([u8; 48]);
struct Bytes96([u8; 96]);

impl Serialize for Bytes48 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bytes48 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Bytes48;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("48 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                if v.len() != 48 {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut arr = [0u8; 48];
                arr.copy_from_slice(v);
                Ok(Bytes48(arr))
            }
        }
        d.deserialize_bytes(Visitor)
    }
}

impl Serialize for Bytes96 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bytes96 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Bytes96;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("96 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                if v.len() != 96 {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut arr = [0u8; 96];
                arr.copy_from_slice(v);
                Ok(Bytes96(arr))
            }
        }
        d.deserialize_bytes(Visitor)
    }
}

/// Groth16 proof — three group elements (A ∈ G₁，B ∈ G₂, C ∈ G₁).
///
/// Each element is stored as a compressed byte representation:
/// - G₁ elements (A, C): 48 bytes each (compressed BLS12-381)
/// - G₂ element (B): 96 bytes (compressed BLS12-381)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitVm2Groth16Proof {
    pub encoding_version: BitVm2EncodingVersion,
    /// Compressed G₁ point (48 bytes).
    pub a: [u8; 48],
    /// Compressed G₂ point (96 bytes).
    pub b: [u8; 96],
    /// Compressed G₁ point (48 bytes).
    pub c: [u8; 48],
}

impl Serialize for BitVm2Groth16Proof {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = s.serialize_struct("BitVm2Groth16Proof", 4)?;
        state.serialize_field("encoding_version", &self.encoding_version)?;
        state.serialize_field("a", &Bytes48(self.a))?;
        state.serialize_field("b", &Bytes96(self.b))?;
        state.serialize_field("c", &Bytes48(self.c))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for BitVm2Groth16Proof {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = BitVm2Groth16Proof;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("BitVm2Groth16Proof")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error;
                let mut encoding_version = None;
                let mut a = None;
                let mut b = None;
                let mut c = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "encoding_version" => encoding_version = Some(map.next_value()?),
                        "a" => a = Some(map.next_value::<Bytes48>()?.0),
                        "b" => b = Some(map.next_value::<Bytes96>()?.0),
                        "c" => c = Some(map.next_value::<Bytes48>()?.0),
                        _ => {
                            return Err(Error::unknown_field(
                                &key,
                                &["encoding_version", "a", "b", "c"],
                            ))
                        }
                    }
                }
                Ok(BitVm2Groth16Proof {
                    encoding_version: encoding_version
                        .ok_or_else(|| Error::missing_field("encoding_version"))?,
                    a: a.ok_or_else(|| Error::missing_field("a"))?,
                    b: b.ok_or_else(|| Error::missing_field("b"))?,
                    c: c.ok_or_else(|| Error::missing_field("c"))?,
                })
            }
        }
        d.deserialize_struct(
            "BitVm2Groth16Proof",
            &["encoding_version", "a", "b", "c"],
            Visitor,
        )
    }
}

impl BitVm2Groth16Proof {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        if self.a == [0; 48] || self.b == [0; 96] || self.c == [0; 48] {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        Ok(())
    }
}

/// Groth16 verification key (on-chain reference).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitVm2Groth16VerificationKey {
    pub encoding_version: BitVm2EncodingVersion,
    /// Compressed G₁ point — alpha (48 bytes).
    pub alpha_g1: [u8; 48],
    /// Compressed G₂ point — beta (96 bytes).
    pub beta_g2: [u8; 96],
    /// Compressed G₂ point — gamma (96 bytes).
    pub gamma_g2: [u8; 96],
    /// Compressed G₂ point — delta (96 bytes).
    pub delta_g2: [u8; 96],
    /// Compressed G₁ points — gamma_abc (variable length, each 48 bytes).
    pub gamma_abc_g1: Vec<[u8; 48]>,
}

impl Serialize for BitVm2Groth16VerificationKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = s.serialize_struct("BitVm2Groth16VerificationKey", 6)?;
        state.serialize_field("encoding_version", &self.encoding_version)?;
        state.serialize_field("alpha_g1", &Bytes48(self.alpha_g1))?;
        state.serialize_field("beta_g2", &Bytes96(self.beta_g2))?;
        state.serialize_field("gamma_g2", &Bytes96(self.gamma_g2))?;
        state.serialize_field("delta_g2", &Bytes96(self.delta_g2))?;
        let gamma_abc: Vec<Bytes48> = self.gamma_abc_g1.iter().map(|a| Bytes48(*a)).collect();
        state.serialize_field("gamma_abc_g1", &gamma_abc)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for BitVm2Groth16VerificationKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = BitVm2Groth16VerificationKey;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("BitVm2Groth16VerificationKey")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error;
                let mut encoding_version = None;
                let mut alpha_g1 = None;
                let mut beta_g2 = None;
                let mut gamma_g2 = None;
                let mut delta_g2 = None;
                let mut gamma_abc_g1: Option<Vec<[u8; 48]>> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "encoding_version" => encoding_version = Some(map.next_value()?),
                        "alpha_g1" => alpha_g1 = Some(map.next_value::<Bytes48>()?.0),
                        "beta_g2" => beta_g2 = Some(map.next_value::<Bytes96>()?.0),
                        "gamma_g2" => gamma_g2 = Some(map.next_value::<Bytes96>()?.0),
                        "delta_g2" => delta_g2 = Some(map.next_value::<Bytes96>()?.0),
                        "gamma_abc_g1" => {
                            gamma_abc_g1 = Some(
                                map.next_value::<Vec<Bytes48>>()?
                                    .into_iter()
                                    .map(|b| b.0)
                                    .collect(),
                            )
                        }
                        _ => {
                            return Err(Error::unknown_field(
                                &key,
                                &[
                                    "encoding_version",
                                    "alpha_g1",
                                    "beta_g2",
                                    "gamma_g2",
                                    "delta_g2",
                                    "gamma_abc_g1",
                                ],
                            ))
                        }
                    }
                }
                Ok(BitVm2Groth16VerificationKey {
                    encoding_version: encoding_version
                        .ok_or_else(|| Error::missing_field("encoding_version"))?,
                    alpha_g1: alpha_g1.ok_or_else(|| Error::missing_field("alpha_g1"))?,
                    beta_g2: beta_g2.ok_or_else(|| Error::missing_field("beta_g2"))?,
                    gamma_g2: gamma_g2.ok_or_else(|| Error::missing_field("gamma_g2"))?,
                    delta_g2: delta_g2.ok_or_else(|| Error::missing_field("delta_g2"))?,
                    gamma_abc_g1: gamma_abc_g1.unwrap_or_default(),
                })
            }
        }
        d.deserialize_struct(
            "BitVm2Groth16VerificationKey",
            &[
                "encoding_version",
                "alpha_g1",
                "beta_g2",
                "gamma_g2",
                "delta_g2",
                "gamma_abc_g1",
            ],
            Visitor,
        )
    }
}

impl BitVm2Groth16VerificationKey {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.encoding_version.validate()?;
        if self.alpha_g1 == [0; 48]
            || self.beta_g2 == [0; 96]
            || self.gamma_g2 == [0; 96]
            || self.delta_g2 == [0; 96]
        {
            return Err(boundary_error(BoundaryValidationError::InvalidEnvelope));
        }
        Ok(())
    }
}

/// Groth16 public inputs to the BitVM2 disprove statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2Groth16PublicInputs {
    pub instance_id: BitVm2InstanceId,
    pub commitment_id: BitVm2CommitmentId,
    pub state_root_hash: [u8; 32],
    pub challenge_digest: [u8; 32],
}

impl BitVm2Groth16PublicInputs {
    pub fn validate(&self) -> ConclaveResult<()> {
        self.instance_id.validate()?;
        self.commitment_id.validate()?;
        if self.state_root_hash == [0; 32] || self.challenge_digest == [0; 32] {
            return Err(boundary_error(BoundaryValidationError::InvalidObservation));
        }
        Ok(())
    }
}

/// Outcome of Groth16 proof verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Groth16VerificationOutcome {
    Valid,
    Invalid,
    VerificationUnavailable,
}

/// Groth16 verifier boundary.
///
/// With the `groth16` feature enabled, this verifier performs the real
/// BLS12-381 pairing check for the Groth16 verification equation. Without the
/// feature, verification fails closed and returns
/// [`Groth16VerificationOutcome::VerificationUnavailable`].
#[derive(Debug, Clone, Default)]
pub struct BitVm2Groth16Verifier {
    _private: (),
}

impl BitVm2Groth16Verifier {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Verify a Groth16 proof against a verification key and public inputs.
    ///
    /// The Groth16 verification equation is:
    ///
    /// ```text
    /// e(A, B) == e(alpha, beta) · e(acc, gamma) · e(C, delta)
    /// ```
    ///
    /// where `acc = IC_0 + Σ_i IC_{i+1} · public_input_i`. Without the
    /// `groth16` feature this returns
    /// [`Groth16VerificationOutcome::VerificationUnavailable`] rather than
    /// approving a proof.
    pub fn verify(
        &self,
        proof: &BitVm2Groth16Proof,
        vk: &BitVm2Groth16VerificationKey,
        inputs: &BitVm2Groth16PublicInputs,
    ) -> ConclaveResult<Groth16VerificationOutcome> {
        // Validate public inputs and encoding versions.
        inputs.validate()?;
        proof.encoding_version.validate()?;
        vk.encoding_version.validate()?;

        // Reject all-zero point representations (G1 = 48 bytes, G2 = 96 bytes).
        if proof.a == [0u8; 48] || proof.b == [0u8; 96] || proof.c == [0u8; 48] {
            return Ok(Groth16VerificationOutcome::Invalid);
        }
        if vk.alpha_g1 == [0u8; 48]
            || vk.beta_g2 == [0u8; 96]
            || vk.gamma_g2 == [0u8; 96]
            || vk.delta_g2 == [0u8; 96]
        {
            return Ok(Groth16VerificationOutcome::Invalid);
        }
        if vk.gamma_abc_g1.is_empty() {
            return Ok(Groth16VerificationOutcome::Invalid);
        }
        for p in &vk.gamma_abc_g1 {
            if *p == [0u8; 48] {
                return Ok(Groth16VerificationOutcome::Invalid);
            }
        }

        #[cfg(feature = "groth16")]
        {
            self.verify_pairing(proof, vk, inputs)
        }

        #[cfg(not(feature = "groth16"))]
        {
            let _ = (proof, vk, inputs);
            Ok(Groth16VerificationOutcome::VerificationUnavailable)
        }
    }

    /// Perform the real BLS12-381 Groth16 pairing verification.
    #[cfg(feature = "groth16")]
    fn verify_pairing(
        &self,
        proof: &BitVm2Groth16Proof,
        vk: &BitVm2Groth16VerificationKey,
        inputs: &BitVm2Groth16PublicInputs,
    ) -> ConclaveResult<Groth16VerificationOutcome> {
        use bls12_381::{pairing, G1Affine, G1Projective, G2Affine};

        // Decompress every point. `from_compressed` validates that the point is
        // on-curve and in the correct prime-order subgroup; any failure is an
        // invalid proof (fail closed).
        let a = match G1Affine::from_compressed(&proof.a).into_option() {
            Some(p) => p,
            None => return Ok(Groth16VerificationOutcome::Invalid),
        };
        let b = match G2Affine::from_compressed(&proof.b).into_option() {
            Some(p) => p,
            None => return Ok(Groth16VerificationOutcome::Invalid),
        };
        let c = match G1Affine::from_compressed(&proof.c).into_option() {
            Some(p) => p,
            None => return Ok(Groth16VerificationOutcome::Invalid),
        };
        let alpha = match G1Affine::from_compressed(&vk.alpha_g1).into_option() {
            Some(p) => p,
            None => return Ok(Groth16VerificationOutcome::Invalid),
        };
        let beta = match G2Affine::from_compressed(&vk.beta_g2).into_option() {
            Some(p) => p,
            None => return Ok(Groth16VerificationOutcome::Invalid),
        };
        let gamma = match G2Affine::from_compressed(&vk.gamma_g2).into_option() {
            Some(p) => p,
            None => return Ok(Groth16VerificationOutcome::Invalid),
        };
        let delta = match G2Affine::from_compressed(&vk.delta_g2).into_option() {
            Some(p) => p,
            None => return Ok(Groth16VerificationOutcome::Invalid),
        };

        // Reject the point at infinity: it is degenerate for Groth16 proofs and
        // verification keys.
        if bool::from(a.is_identity())
            || bool::from(b.is_identity())
            || bool::from(c.is_identity())
            || bool::from(alpha.is_identity())
            || bool::from(beta.is_identity())
            || bool::from(gamma.is_identity())
            || bool::from(delta.is_identity())
        {
            return Ok(Groth16VerificationOutcome::Invalid);
        }

        // The verification key must carry one IC term per public input plus the
        // constant IC_0 term.
        let public_scalars = derive_public_scalars(inputs);
        if vk.gamma_abc_g1.len() != public_scalars.len() + 1 {
            return Ok(Groth16VerificationOutcome::Invalid);
        }

        // Decompress the IC terms.
        let mut ic_points = Vec::with_capacity(vk.gamma_abc_g1.len());
        for ic_bytes in &vk.gamma_abc_g1 {
            match G1Affine::from_compressed(ic_bytes).into_option() {
                Some(p) => {
                    if bool::from(p.is_identity()) {
                        return Ok(Groth16VerificationOutcome::Invalid);
                    }
                    ic_points.push(p);
                }
                None => return Ok(Groth16VerificationOutcome::Invalid),
            }
        }

        // acc = IC_0 + Σ_i IC_{i+1} · public_input_i
        let mut acc = G1Projective::from(ic_points[0]);
        for (ic, scalar) in ic_points.iter().skip(1).zip(public_scalars.iter()) {
            acc += *ic * *scalar;
        }
        let acc = G1Affine::from(acc);

        // e(A, B) == e(alpha, beta) · e(acc, gamma) · e(C, delta)
        let lhs = pairing(&a, &b);
        let rhs = pairing(&alpha, &beta) + pairing(&acc, &gamma) + pairing(&c, &delta);

        if lhs == rhs {
            Ok(Groth16VerificationOutcome::Valid)
        } else {
            Ok(Groth16VerificationOutcome::Invalid)
        }
    }
}

/// Derive the Groth16 public input scalars from the BitVM2 public inputs.
///
/// Each field is folded into the BLS12-381 scalar field (`Fr`) via
/// `Scalar::from_bytes_wide`, which reduces a 64-byte little-endian buffer and
/// always succeeds. The four public inputs map one-to-one to four `Fr`
/// elements in this fixed order:
///
/// 1. `instance_id` (16 bytes)
/// 2. `commitment_id` (16 bytes)
/// 3. `state_root_hash` (32 bytes)
/// 4. `challenge_digest` (32 bytes)
///
/// The exact arity must match the deployed BitVM2 verification key; the
/// verifier fails closed on any mismatch.
#[cfg(feature = "groth16")]
fn derive_public_scalars(inputs: &BitVm2Groth16PublicInputs) -> Vec<bls12_381::Scalar> {
    use bls12_381::Scalar;

    let fields: [&[u8]; 4] = [
        &inputs.instance_id.bytes(),
        &inputs.commitment_id.bytes(),
        &inputs.state_root_hash,
        &inputs.challenge_digest,
    ];

    let mut scalars = Vec::with_capacity(fields.len());
    for field in fields {
        let mut buf = [0u8; 64];
        buf[..field.len()].copy_from_slice(field);
        scalars.push(Scalar::from_bytes_wide(&buf));
    }
    scalars
}

// ── Monitor and Orchestrator ─────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm2Monitor {
    ledger: BitVm2ObservationLedger,
}

impl BitVm2Monitor {
    pub fn observe(
        &mut self,
        observation: ExternalChainObservation,
    ) -> ConclaveResult<ObservationOutcome> {
        self.ledger.observe(observation)
    }

    pub fn observation_count(&self) -> usize {
        self.ledger.len()
    }
}

/// BitVM2 orchestrator. Unsupported value-bearing methods intentionally do not
/// touch `active_challenges`; only `observe_chain_event` can change monitor
/// state, and it requires an externally supplied observation.
pub struct BitVm2Orchestrator {
    #[allow(dead_code)]
    ark_manager: Arc<crate::protocol::ark::ArkManager>,
    #[allow(dead_code)]
    bitvm_manager: Arc<BitVmManager>,
    #[allow(dead_code)]
    backend: BitVm2Backend,
    #[allow(dead_code)]
    active_challenges: HashMap<String, BitVm2ChallengeStatus>,
    monitor: BitVm2Monitor,
}

impl BitVm2Orchestrator {
    pub fn new(
        ark_manager: Arc<crate::protocol::ark::ArkManager>,
        bitvm_manager: Arc<BitVmManager>,
    ) -> Self {
        Self {
            ark_manager,
            bitvm_manager,
            backend: BitVm2Backend::Unconfigured,
            active_challenges: HashMap::new(),
            monitor: BitVm2Monitor::default(),
        }
    }

    pub fn backend(&self) -> BitVm2Backend {
        self.backend
    }

    pub fn observe_chain_event(
        &mut self,
        observation: ExternalChainObservation,
    ) -> ConclaveResult<ObservationOutcome> {
        self.monitor.observe(observation)
    }

    pub fn observed_event_count(&self) -> usize {
        self.monitor.observation_count()
    }

    pub fn create_forfeit_with_commitment(
        &self,
        _vutxo: VUtxoDescriptor,
        _vtxo_tree: crate::protocol::ark::VtxoTreeNode,
        _state_root_hash: [u8; 32],
        _taproot_internal_key: [u8; 32],
    ) -> ConclaveResult<BitVm2ForfeitTransaction> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::ForfeitConstruction,
        ))
    }

    pub fn post_commitment(&mut self, _commitment: BitVm2Commitment) -> ConclaveResult<String> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::CommitmentPosting,
        ))
    }

    pub fn challenge_commitment(
        &mut self,
        _commitment_id: &str,
        _response: BitVm2ChallengeResponse,
    ) -> ConclaveResult<()> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::ChallengeSubmission,
        ))
    }

    pub fn resolve_challenge(
        &mut self,
        _commitment_id: &str,
        _operator_punished: bool,
        _block_height: u64,
    ) -> ConclaveResult<()> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::ChallengeResolution,
        ))
    }

    pub fn get_challenge_status(
        &self,
        _commitment_id: &str,
    ) -> ConclaveResult<BitVm2ChallengeStatus> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::ChallengeStatus,
        ))
    }

    pub fn is_within_challenge_window(
        &self,
        _commitment_id: &str,
        _current_block: u64,
    ) -> ConclaveResult<bool> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::ChallengeWindow,
        ))
    }

    pub fn sign_forfeit(
        &self,
        _forfeit_tx: &BitVm2ForfeitTransaction,
        _derivation_path: &str,
    ) -> ConclaveResult<String> {
        Err(protocol_unsupported(
            UnsupportedProtocol::BitVm2,
            UnsupportedOperation::ForfeitSigning,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        enclave::cloud::CloudEnclave,
        protocol::ark::{ArkManager, ArkVtxoId},
        UnsupportedReason,
    };

    fn orchestrator() -> BitVm2Orchestrator {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let ark = Arc::new(ArkManager::new(enclave.clone()));
        let bitvm = Arc::new(BitVmManager::new(enclave));
        BitVm2Orchestrator::new(ark, bitvm)
    }

    fn observation(digest: u8) -> ExternalChainObservation {
        ExternalChainObservation {
            encoding_version: BitVm2EncodingVersion::current(),
            observation_id: BitVm2ObservationId::new([1; 16]).expect("valid observation id"),
            instance_id: BitVm2InstanceId::new([2; 16]).expect("valid instance id"),
            chain_id: BitVm2ChainId::new("bitcoin").expect("valid chain id"),
            kind: BitVm2ObservationKind::CommitmentPosted,
            block_height: 100,
            event_digest: [digest; 32],
        }
    }

    #[test]
    fn validates_challenge_window_boundaries_and_identifiers() {
        assert!(BitVm2ChallengeWindow::new(10, 20)
            .expect("valid window")
            .contains(10));
        assert!(BitVm2ChallengeWindow::new(10, 20)
            .expect("valid window")
            .contains(20));
        assert!(!BitVm2ChallengeWindow::new(10, 20)
            .expect("valid window")
            .contains(9));
        assert!(!BitVm2ChallengeWindow::new(10, 20)
            .expect("valid window")
            .contains(21));
        assert!(matches!(
            BitVm2ChallengeWindow::new(21, 20),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidChallengeWindow
            ))
        ));
        assert!(matches!(
            BitVm2EncodingVersion::new(2),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidEncodingVersion
            ))
        ));
    }

    #[test]
    fn duplicate_chain_observations_are_idempotent_and_conflicts_fail_closed() {
        let mut monitor = BitVm2Monitor::default();
        assert_eq!(
            monitor
                .observe(observation(3))
                .expect("records observation"),
            ObservationOutcome::Recorded
        );
        assert_eq!(
            monitor
                .observe(observation(3))
                .expect("duplicate is idempotent"),
            ObservationOutcome::AlreadyKnown
        );
        assert!(matches!(
            monitor.observe(observation(4)),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::ReplayConflict
            ))
        ));
        assert_eq!(monitor.observation_count(), 1);
    }

    #[test]
    fn unsupported_operations_do_not_mutate_or_synthesize_state() {
        let mut manager = orchestrator();
        let before = manager.observed_event_count();
        let vutxo = VUtxoDescriptor::new(
            ArkVtxoId::new("vtxo-1").expect("valid vtxo id"),
            100,
            crate::protocol::ark::ArkDerivationIndex::new(0),
            "bc1q-example",
        )
        .expect("valid vtxo");
        let tree = crate::protocol::ark::VtxoTreeNode {
            tx_id: ArkTransactionId::new("root").expect("valid tx id"),
            left: None,
            right: None,
            is_leaf: true,
        };
        let commitment = BitVm2Commitment {
            encoding_version: BitVm2EncodingVersion::current(),
            instance_id: BitVm2InstanceId::new([2; 16]).expect("valid instance id"),
            commitment_id: BitVm2CommitmentId::new([3; 16]).expect("valid commitment id"),
            role: BitVm2Role::Operator,
            state_root_hash: [4; 32],
            vtxo_count: 1,
            merkle_root: [5; 32],
            taproot_internal_key: [6; 32],
            block_height: 100,
            challenge_window: BitVm2ChallengeWindow::new(100, 110).expect("valid window"),
        };
        let response = BitVm2ChallengeResponse {
            encoding_version: BitVm2EncodingVersion::current(),
            instance_id: commitment.instance_id,
            commitment_id: commitment.commitment_id,
            tap_index: 0,
            disprove: BitVm2DisproveEnvelope {
                encoding_version: BitVm2EncodingVersion::current(),
                digest: [7; 32],
                payload_len: 64,
            },
            expected_output_hash: [8; 32],
        };

        assert_unsupported(
            manager.create_forfeit_with_commitment(vutxo.clone(), tree, [4; 32], [6; 32]),
            UnsupportedOperation::ForfeitConstruction,
        );
        assert_unsupported(
            manager.post_commitment(commitment),
            UnsupportedOperation::CommitmentPosting,
        );
        assert_unsupported(
            manager.challenge_commitment("commitment", response),
            UnsupportedOperation::ChallengeSubmission,
        );
        assert_unsupported(
            manager.resolve_challenge("commitment", true, 110),
            UnsupportedOperation::ChallengeResolution,
        );
        assert_unsupported(
            manager.get_challenge_status("commitment"),
            UnsupportedOperation::ChallengeStatus,
        );
        assert_unsupported(
            manager.is_within_challenge_window("commitment", 110),
            UnsupportedOperation::ChallengeWindow,
        );
        assert_eq!(manager.observed_event_count(), before);
        assert_eq!(manager.backend(), BitVm2Backend::Unconfigured);
    }

    #[test]
    fn observed_events_are_the_only_modeled_state_transition() {
        let mut manager = orchestrator();
        assert_eq!(
            manager
                .observe_chain_event(observation(3))
                .expect("records external event"),
            ObservationOutcome::Recorded
        );
        assert_eq!(manager.observed_event_count(), 1);
    }

    fn assert_unsupported<T>(result: ConclaveResult<T>, operation: UnsupportedOperation) {
        match result {
            Err(ConclaveError::ProtocolUnsupported {
                protocol: UnsupportedProtocol::BitVm2,
                operation: actual_operation,
                reason: UnsupportedReason::NoAuditedImplementation,
            }) => assert_eq!(actual_operation, operation),
            _ => panic!("expected typed BitVM2 unsupported error"),
        }
    }

    // ── Groth16 tests ────────────────────────────────────────────────

    #[test]
    fn groth16_proof_rejects_zero_bytes() {
        let proof = BitVm2Groth16Proof {
            encoding_version: BitVm2EncodingVersion::current(),
            a: [0; 48],
            b: [1; 96],
            c: [2; 48],
        };
        assert!(matches!(
            proof.validate(),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidEnvelope
            ))
        ));
    }

    #[test]
    fn groth16_proof_accepts_valid_elements() {
        let proof = BitVm2Groth16Proof {
            encoding_version: BitVm2EncodingVersion::current(),
            a: [1; 48],
            b: [2; 96],
            c: [3; 48],
        };
        assert!(proof.validate().is_ok());
    }

    #[test]
    fn groth16_vk_rejects_zero_key_elements() {
        let vk = BitVm2Groth16VerificationKey {
            encoding_version: BitVm2EncodingVersion::current(),
            alpha_g1: [0; 48],
            beta_g2: [2; 96],
            gamma_g2: [3; 96],
            delta_g2: [4; 96],
            gamma_abc_g1: vec![],
        };
        assert!(matches!(
            vk.validate(),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidEnvelope
            ))
        ));
    }

    #[test]
    fn groth16_vk_accepts_valid_keys() {
        let vk = BitVm2Groth16VerificationKey {
            encoding_version: BitVm2EncodingVersion::current(),
            alpha_g1: [1; 48],
            beta_g2: [2; 96],
            gamma_g2: [3; 96],
            delta_g2: [4; 96],
            gamma_abc_g1: vec![[5; 48], [6; 48]],
        };
        assert!(vk.validate().is_ok());
    }

    #[test]
    fn groth16_verifier_rejects_arbitrary_bytes_fail_closed() {
        let verifier = BitVm2Groth16Verifier::new();

        // Arbitrary bytes with the compression flag set are not valid curve
        // points, so they must never be accepted as a valid proof (fail closed).
        let mut a = [1u8; 48];
        a[0] |= 0x80;
        let mut b = [2u8; 96];
        b[0] |= 0x80;
        let mut c = [3u8; 48];
        c[0] |= 0x80;
        let mut alpha = [1u8; 48];
        alpha[0] |= 0x80;

        let proof = BitVm2Groth16Proof {
            encoding_version: BitVm2EncodingVersion::current(),
            a,
            b,
            c,
        };
        let vk = BitVm2Groth16VerificationKey {
            encoding_version: BitVm2EncodingVersion::current(),
            alpha_g1: alpha,
            beta_g2: [2; 96],
            gamma_g2: [3; 96],
            delta_g2: [4; 96],
            gamma_abc_g1: vec![[5; 48], [6; 48], [7; 48], [8; 48], [9; 48]],
        };
        let inputs = BitVm2Groth16PublicInputs {
            instance_id: BitVm2InstanceId::new([1; 16]).expect("valid instance"),
            commitment_id: BitVm2CommitmentId::new([2; 16]).expect("valid commitment"),
            state_root_hash: [3; 32],
            challenge_digest: [4; 32],
        };

        let outcome = verifier
            .verify(&proof, &vk, &inputs)
            .expect("verification completed");
        // Never approve arbitrary bytes as a valid Groth16 proof.
        assert_ne!(outcome, Groth16VerificationOutcome::Valid);

        // All-zero points are rejected outright.
        let zero_proof = BitVm2Groth16Proof {
            encoding_version: BitVm2EncodingVersion::current(),
            a: [0; 48],
            b: [0; 96],
            c: [0; 48],
        };
        let outcome_zero = verifier
            .verify(&zero_proof, &vk, &inputs)
            .expect("verification completed");
        assert_eq!(outcome_zero, Groth16VerificationOutcome::Invalid);
    }

    #[cfg(feature = "groth16")]
    #[test]
    fn groth16_verifier_verifies_genuine_proof() {
        use bls12_381::{G1Affine, G2Affine, Scalar};

        let verifier = BitVm2Groth16Verifier::new();

        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();

        let inputs = BitVm2Groth16PublicInputs {
            instance_id: BitVm2InstanceId::new([1; 16]).expect("valid instance"),
            commitment_id: BitVm2CommitmentId::new([2; 16]).expect("valid commitment"),
            state_root_hash: [3; 32],
            challenge_digest: [4; 32],
        };

        // Derive the same public scalars the verifier derives.
        let scalars = derive_public_scalars(&inputs);
        let sum_s = {
            let mut s = Scalar::zero();
            for x in &scalars {
                s += *x;
            }
            s
        };

        // Build the IC terms so that acc = -g1:
        //   acc = IC_0 + g1*(s0 + s1 + s2 + s3) = -g1
        // => IC_0 = -(1 + sum_s) * g1
        let ic0 = G1Affine::from(g1 * (-Scalar::one() - sum_s));

        let vk = BitVm2Groth16VerificationKey {
            encoding_version: BitVm2EncodingVersion::current(),
            alpha_g1: g1.to_compressed(),
            beta_g2: g2.to_compressed(),
            gamma_g2: g2.to_compressed(),
            delta_g2: g2.to_compressed(),
            gamma_abc_g1: vec![
                ic0.to_compressed(),
                g1.to_compressed(),
                g1.to_compressed(),
                g1.to_compressed(),
                g1.to_compressed(),
            ],
        };

        let proof = BitVm2Groth16Proof {
            encoding_version: BitVm2EncodingVersion::current(),
            a: g1.to_compressed(),
            b: g2.to_compressed(),
            c: g1.to_compressed(),
        };

        let outcome = verifier
            .verify(&proof, &vk, &inputs)
            .expect("verification completed");
        assert_eq!(outcome, Groth16VerificationOutcome::Valid);
    }

    #[cfg(feature = "groth16")]
    #[test]
    fn groth16_verifier_rejects_arity_mismatch() {
        use bls12_381::{G1Affine, G2Affine};

        let verifier = BitVm2Groth16Verifier::new();
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();

        let proof = BitVm2Groth16Proof {
            encoding_version: BitVm2EncodingVersion::current(),
            a: g1.to_compressed(),
            b: g2.to_compressed(),
            c: g1.to_compressed(),
        };
        // Only one IC term (constant) — arity does not match four public inputs.
        let vk = BitVm2Groth16VerificationKey {
            encoding_version: BitVm2EncodingVersion::current(),
            alpha_g1: g1.to_compressed(),
            beta_g2: g2.to_compressed(),
            gamma_g2: g2.to_compressed(),
            delta_g2: g2.to_compressed(),
            gamma_abc_g1: vec![g1.to_compressed()],
        };
        let inputs = BitVm2Groth16PublicInputs {
            instance_id: BitVm2InstanceId::new([1; 16]).expect("valid instance"),
            commitment_id: BitVm2CommitmentId::new([2; 16]).expect("valid commitment"),
            state_root_hash: [3; 32],
            challenge_digest: [4; 32],
        };

        let outcome = verifier
            .verify(&proof, &vk, &inputs)
            .expect("verification completed");
        assert_eq!(outcome, Groth16VerificationOutcome::Invalid);
    }

    #[test]
    fn groth16_public_inputs_rejects_zero_digests() {
        let inputs = BitVm2Groth16PublicInputs {
            instance_id: BitVm2InstanceId::new([1; 16]).expect("valid instance"),
            commitment_id: BitVm2CommitmentId::new([2; 16]).expect("valid commitment"),
            state_root_hash: [0; 32],
            challenge_digest: [4; 32],
        };
        assert!(matches!(
            inputs.validate(),
            Err(ConclaveError::BoundaryValidation(
                BoundaryValidationError::InvalidObservation
            ))
        ));
    }
}
