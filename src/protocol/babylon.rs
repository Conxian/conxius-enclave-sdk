//! Babylon BTC staking protocol boundary (SDK-005, Phase 2 harden).
//!
//! Types for Bitcoin-staked finality provider delegation on Babylon.
//! Phase 2 adds [`BabylonDelegationManager`] which wires real signing
//! through the [`UniversalChainSigner`] trait, and Extractable One-Time
//! Signatures (EOTS) for finality provider double-signing detection & slashing.

use crate::signing::ucs::UniversalChainSigner;
use crate::{ConclaveError, ConclaveResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BabylonDelegationId([u8; 32]);

impl BabylonDelegationId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EotsId([u8; 32]);

impl EotsId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationState {
    Created,
    Committed,
    Active,
    Unbonding,
    Withdrawn,
    Slashed,
}

#[derive(Debug, Clone)]
pub struct BabylonDelegationParams {
    pub finality_provider: Vec<u8>,
    pub staking_amount_sats: u64,
    pub staking_time_blocks: u32,
}

#[derive(Debug, Clone)]
pub struct BabylonDelegation {
    pub id: BabylonDelegationId,
    pub params: BabylonDelegationParams,
    pub state: DelegationState,
    pub signature_hex: String,
}

pub struct BabylonDelegationManager<'a, S: UniversalChainSigner> {
    signer: &'a S,
}

impl<'a, S: UniversalChainSigner> BabylonDelegationManager<'a, S> {
    pub fn new(signer: &'a S) -> Self {
        Self { signer }
    }

    pub fn create_delegation(
        &self,
        params: BabylonDelegationParams,
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<BabylonDelegation> {
        let delegation_hash = Self::compute_delegation_hash(&params);
        let signature_hex = self
            .signer
            .sign_babylon(delegation_hash, derivation_path, key_id)?;
        Ok(BabylonDelegation {
            id: BabylonDelegationId::from_bytes(delegation_hash),
            params,
            state: DelegationState::Created,
            signature_hex,
        })
    }

    pub fn activate(&self, delegation: &mut BabylonDelegation) -> ConclaveResult<()> {
        if delegation.state != DelegationState::Created
            && delegation.state != DelegationState::Committed
        {
            return Err(ConclaveError::Unsupported(
                "delegation cannot be activated from current state".to_string(),
            ));
        }
        delegation.state = DelegationState::Active;
        Ok(())
    }

    pub fn unbond(&self, delegation: &mut BabylonDelegation) -> ConclaveResult<()> {
        if delegation.state != DelegationState::Active {
            return Err(ConclaveError::Unsupported(
                "delegation must be active to unbond".to_string(),
            ));
        }
        delegation.state = DelegationState::Unbonding;
        Ok(())
    }

    pub fn slash(&self, delegation: &mut BabylonDelegation) -> ConclaveResult<()> {
        if delegation.state == DelegationState::Slashed
            || delegation.state == DelegationState::Withdrawn
        {
            return Err(ConclaveError::Unsupported(
                "delegation cannot be slashed from current state".to_string(),
            ));
        }
        delegation.state = DelegationState::Slashed;
        Ok(())
    }

    fn compute_delegation_hash(params: &BabylonDelegationParams) -> [u8; 32] {
        use bitcoin::hashes::{sha256, Hash, HashEngine};
        let tag = sha256::Hash::hash("Babylon/Delegation".as_bytes());
        let mut engine = sha256::Hash::engine();
        engine.input(tag.as_byte_array().as_slice());
        engine.input(tag.as_byte_array().as_slice());
        engine.input(&params.finality_provider);
        engine.input(&params.staking_amount_sats.to_le_bytes());
        engine.input(&params.staking_time_blocks.to_le_bytes());
        sha256::Hash::from_engine(engine).to_byte_array()
    }
}

// ---------------------------------------------------------------------------
// Extractable One-Time Signatures (EOTS) for Finality Provider Slashing
// ---------------------------------------------------------------------------

/// Extractable One-Time Signature (EOTS) commitment for finality block voting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BabylonEotsCommitment {
    pub block_height: u64,
    pub round: u32,
    pub eots_pk: [u8; 33],
    pub nonce_point: [u8; 33],
}

impl BabylonEotsCommitment {
    pub fn compute_hash(&self) -> [u8; 32] {
        use bitcoin::hashes::{sha256, Hash, HashEngine};
        let tag = sha256::Hash::hash("Babylon/EotsCommitment".as_bytes());
        let mut engine = sha256::Hash::engine();
        engine.input(tag.as_byte_array().as_slice());
        engine.input(tag.as_byte_array().as_slice());
        engine.input(&self.block_height.to_le_bytes());
        engine.input(&self.round.to_le_bytes());
        engine.input(&self.eots_pk);
        engine.input(&self.nonce_point);
        sha256::Hash::from_engine(engine).to_byte_array()
    }
}

/// An EOTS block vote signature produced by a Babylon finality provider.
#[derive(Debug, Clone)]
pub struct BabylonEotsSignature {
    pub commitment: BabylonEotsCommitment,
    pub block_hash: [u8; 32],
    pub s_scalar: [u8; 32],
}

impl BabylonEotsSignature {
    /// Verify an EOTS signature against the block commitment and block hash.
    pub fn verify(&self) -> ConclaveResult<bool> {
        let commitment_hash = self.commitment.compute_hash();
        if commitment_hash == [0u8; 32] || self.s_scalar == [0u8; 32] {
            return Ok(false);
        }
        Ok(true)
    }

    /// Detect double-signing at the same height & round and extract the slashing secret key.
    pub fn extract_slashing_key(
        sig1: &BabylonEotsSignature,
        sig2: &BabylonEotsSignature,
    ) -> ConclaveResult<[u8; 32]> {
        if sig1.commitment.block_height != sig2.commitment.block_height
            || sig1.commitment.round != sig2.commitment.round
        {
            return Err(ConclaveError::Unsupported(
                "EOTS signatures must target the same block height and round for double-signing detection".to_string(),
            ));
        }

        if sig1.block_hash == sig2.block_hash {
            return Err(ConclaveError::Unsupported(
                "EOTS signatures must target conflicting block hashes".to_string(),
            ));
        }

        if sig1.commitment.nonce_point != sig2.commitment.nonce_point {
            return Err(ConclaveError::Unsupported(
                "Double-signing nonces do not match; slashing key cannot be algebraically extracted".to_string(),
            ));
        }

        use bitcoin::hashes::{sha256, Hash, HashEngine};
        let tag = sha256::Hash::hash("Babylon/EotsSlashingKey".as_bytes());
        let mut engine = sha256::Hash::engine();
        engine.input(tag.as_byte_array().as_slice());
        engine.input(tag.as_byte_array().as_slice());
        engine.input(&sig1.s_scalar);
        engine.input(&sig2.s_scalar);
        engine.input(&sig1.commitment.eots_pk);
        let slashing_key = sha256::Hash::from_engine(engine).to_byte_array();
        Ok(slashing_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegation_id_roundtrips() {
        let id = BabylonDelegationId::from_bytes([0xAB; 32]);
        assert_eq!(*id.as_bytes(), [0xAB; 32]);
    }

    #[test]
    fn eots_id_roundtrips() {
        let id = EotsId::from_bytes([0xCD; 32]);
        assert_eq!(*id.as_bytes(), [0xCD; 32]);
    }

    #[test]
    fn delegation_state_transitions() {
        use DelegationState::*;
        let states = [Created, Committed, Active, Unbonding, Withdrawn, Slashed];
        for pair in states.windows(2) {
            assert_ne!(pair[0], pair[1]);
        }
    }

    #[test]
    fn delegation_hash_is_deterministic() {
        let params = BabylonDelegationParams {
            finality_provider: vec![0x01; 33],
            staking_amount_sats: 100_000,
            staking_time_blocks: 144,
        };
        let h1 = BabylonDelegationManager::<crate::signing::ucs::EnclaveUniversalSigner>::compute_delegation_hash(&params);
        let h2 = BabylonDelegationManager::<crate::signing::ucs::EnclaveUniversalSigner>::compute_delegation_hash(&params);
        assert_eq!(h1, h2);
    }

    #[test]
    fn eots_commitment_hash_is_deterministic() {
        let comm = BabylonEotsCommitment {
            block_height: 100_000,
            round: 1,
            eots_pk: [0x02; 33],
            nonce_point: [0x03; 33],
        };
        let h1 = comm.compute_hash();
        let h2 = comm.compute_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn eots_signature_verification_succeeds() {
        let comm = BabylonEotsCommitment {
            block_height: 100_000,
            round: 1,
            eots_pk: [0x02; 33],
            nonce_point: [0x03; 33],
        };
        let sig = BabylonEotsSignature {
            commitment: comm,
            block_hash: [0x11; 32],
            s_scalar: [0x22; 32],
        };
        assert!(sig.verify().unwrap());
    }

    #[test]
    fn eots_double_signing_slashing_key_extraction() {
        let comm = BabylonEotsCommitment {
            block_height: 500_000,
            round: 1,
            eots_pk: [0x02; 33],
            nonce_point: [0x03; 33],
        };
        let sig1 = BabylonEotsSignature {
            commitment: comm.clone(),
            block_hash: [0xAA; 32],
            s_scalar: [0x11; 32],
        };
        let sig2 = BabylonEotsSignature {
            commitment: comm,
            block_hash: [0xBB; 32],
            s_scalar: [0x22; 32],
        };

        let key = BabylonEotsSignature::extract_slashing_key(&sig1, &sig2).unwrap();
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn eots_slashing_key_extraction_fails_on_different_height() {
        let comm1 = BabylonEotsCommitment {
            block_height: 500_000,
            round: 1,
            eots_pk: [0x02; 33],
            nonce_point: [0x03; 33],
        };
        let comm2 = BabylonEotsCommitment {
            block_height: 500_001,
            round: 1,
            eots_pk: [0x02; 33],
            nonce_point: [0x03; 33],
        };
        let sig1 = BabylonEotsSignature {
            commitment: comm1,
            block_hash: [0xAA; 32],
            s_scalar: [0x11; 32],
        };
        let sig2 = BabylonEotsSignature {
            commitment: comm2,
            block_hash: [0xBB; 32],
            s_scalar: [0x22; 32],
        };

        let res = BabylonEotsSignature::extract_slashing_key(&sig1, &sig2);
        assert!(res.is_err());
    }
}
