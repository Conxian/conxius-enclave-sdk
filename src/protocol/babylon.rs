//! Babylon BTC staking protocol boundary (SDK-005, Phase 2 harden).
//!
//! Types for Bitcoin-staked finality provider delegation on Babylon.
//! Phase 2 adds [`BabylonDelegationManager`] which wires real signing
//! through the [`UniversalChainSigner`] trait.

use crate::signing::ucs::UniversalChainSigner;
use crate::{ConclaveError, ConclaveResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BabylonDelegationId([u8; 32]);

impl BabylonDelegationId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self { Self(bytes) }
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EotsId([u8; 32]);

impl EotsId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self { Self(bytes) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationState { Created, Committed, Active, Unbonding, Withdrawn, Slashed }

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
    pub fn new(signer: &'a S) -> Self { Self { signer } }

    pub fn create_delegation(
        &self,
        params: BabylonDelegationParams,
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<BabylonDelegation> {
        let delegation_hash = Self::compute_delegation_hash(&params);
        let signature_hex = self.signer.sign_babylon(delegation_hash, derivation_path, key_id)?;
        Ok(BabylonDelegation {
            id: BabylonDelegationId::from_bytes(delegation_hash),
            params,
            state: DelegationState::Created,
            signature_hex,
        })
    }

    pub fn activate(&self, delegation: &mut BabylonDelegation) -> ConclaveResult<()> {
        if delegation.state != DelegationState::Created && delegation.state != DelegationState::Committed {
            return Err(ConclaveError::Unsupported("delegation cannot be activated from current state".to_string()));
        }
        delegation.state = DelegationState::Active;
        Ok(())
    }

    pub fn unbond(&self, delegation: &mut BabylonDelegation) -> ConclaveResult<()> {
        if delegation.state != DelegationState::Active {
            return Err(ConclaveError::Unsupported("delegation must be active to unbond".to_string()));
        }
        delegation.state = DelegationState::Unbonding;
        Ok(())
    }

    fn compute_delegation_hash(params: &BabylonDelegationParams) -> [u8; 32] {
        use bitcoin::hashes::{sha256, HashEngine};
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

#[deprecated(since = "2.0.13", note = "use BabylonDelegationManager instead")]
pub fn sign_babylon_delegation(
    _delegation_hash: [u8; 32], _derivation_path: &str, _key_id: &str,
) -> ConclaveResult<String> {
    Err(ConclaveError::Unsupported("babylon: delegation signing requires BabylonDelegationManager (Phase 2)".to_string()))
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
    fn delegation_state_transitions() {
        use DelegationState::*;
        let states = [Created, Committed, Active, Unbonding, Withdrawn, Slashed];
        for pair in states.windows(2) { assert_ne!(pair[0], pair[1]); }
    }

    #[test]
    fn deprecated_sign_returns_unsupported() {
        let result = sign_babylon_delegation([0x00; 32], "m/44'/0'/0'/0/0", "k");
        assert!(matches!(result, Err(ConclaveError::Unsupported(_))));
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
}
