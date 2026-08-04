//! Babylon BTC staking protocol boundary (SDK-005).
//!
//! This module provides typed identifiers and fail-closed quarantine for
//! Babylon BTC delegation signing. Value-bearing operations return exact
//! [`ConclaveError::ProtocolUnsupported`] until Phase 1 integration is
//! complete.
//!
//! ## Pinned references
//! - Babylon docs: <https://docs.babylonchain.io>
//! - BTC staking spec: <https://github.com/babylonlabs-io/babylon>

use crate::ConclaveError;

/// Babylon delegation identifier (BIP-341 style output key commitment).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BabylonDelegationId([u8; 32]);

impl BabylonDelegationId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// EOTS (Extractable One-Time Signature) identifier for slashing protection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EotsId([u8; 32]);

impl EotsId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Babylon staking lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationState {
    /// Delegation created but not yet committed on Bitcoin.
    Created,
    /// BTC commitment transaction confirmed.
    Committed,
    /// Active staking period (EOTS is live).
    Active,
    /// Unbonding period started.
    Unbonding,
    /// Delegation withdrawn.
    Withdrawn,
    /// Slashing event occurred.
    Slashed,
}

/// Babylon delegation parameters.
#[derive(Debug, Clone)]
pub struct BabylonDelegationParams {
    /// Babylon finality provider public key.
    pub finality_provider: Vec<u8>,
    /// Staking amount in satoshis.
    pub staking_amount_sats: u64,
    /// Staking time in Bitcoin blocks.
    pub staking_time_blocks: u32,
}

/// Placeholder: value-bearing Babylon operations remain fail-closed until
/// SDK-005 integration.
pub fn sign_babylon_delegation(
    _params: &BabylonDelegationParams,
    _derivation_path: &str,
    _key_id: &str,
) -> Result<String, ConclaveError> {
    Err(ConclaveError::Unsupported(
        "Babylon BTC delegation signing is not yet implemented (SDK-005)".to_string(),
    ))
}
