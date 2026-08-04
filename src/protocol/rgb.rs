//! RGB protocol state transition boundary (SDK-006).
//!
//! This module provides typed identifiers and fail-closed quarantine for
//! RGB state transition signing. Value-bearing operations return exact
//! [`ConclaveError::ProtocolUnsupported`] until Phase 1 integration is
//! complete.
//!
//! ## Pinned references
//! - RGB spec: <https://rgb.tech>
//! - RGB Core: <https://github.com/RGB-WG/rgb-core>

use crate::ConclaveError;

/// RGB contract identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RgbContractId([u8; 32]);

impl RgbContractId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// RGB state transition identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RgbTransitionId([u8; 32]);

impl RgbTransitionId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// RGB seal definition — anchors a state transition to a Bitcoin UTXO.
#[derive(Debug, Clone)]
pub struct RgbSeal {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// RGB asset schema identifier (e.g., RGB20, RGB21, RGB25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RgbSchema {
    /// Fungible token (RGB20).
    Rgb20,
    /// Non-fungible token (RGB21).
    Rgb21,
    /// Collectible token (RGB25).
    Rgb25,
    /// Custom schema.
    Custom(String),
}

/// Placeholder: value-bearing RGB operations remain fail-closed until
/// SDK-006 integration.
pub fn sign_rgb_transition(
    _contract_id: &RgbContractId,
    _schema: &RgbSchema,
    _seal: &RgbSeal,
    _derivation_path: &str,
    _key_id: &str,
) -> Result<String, ConclaveError> {
    Err(ConclaveError::Unsupported(
        "RGB state transition signing is not yet implemented (SDK-006)".to_string(),
    ))
}
