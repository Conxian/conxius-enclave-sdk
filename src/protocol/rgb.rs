//! RGB asset protocol boundary (SDK-006, Phase 2 harden).
//!
//! Types for RGB contract state transitions anchored to Bitcoin UTXOs.
//! Phase 2 adds [`RgbTransitionBuilder`] for constructing and signing
//! RGB state transitions through the UCS.

use crate::signing::ucs::UniversalChainSigner;
use crate::ConclaveResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RgbContractId([u8; 32]);

impl RgbContractId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RgbTransitionId([u8; 32]);

impl RgbTransitionId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Anchors an RGB state transition to a Bitcoin UTXO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RgbSeal {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// RGB schema version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RgbSchema {
    Rgb20,
    Rgb21,
    Rgb25,
    Custom(String),
}

/// A fully-formed RGB state transition with Bitcoin anchoring.
#[derive(Debug, Clone)]
pub struct RgbTransition {
    pub contract_id: RgbContractId,
    pub transition_id: RgbTransitionId,
    pub schema: RgbSchema,
    pub seal: RgbSeal,
    pub signature_hex: String,
}

// ---------------------------------------------------------------------------
// Transition builder (Phase 2)
// ---------------------------------------------------------------------------

/// Constructs and signs RGB state transitions through the UCS.
pub struct RgbTransitionBuilder<'a, S: UniversalChainSigner> {
    signer: &'a S,
}

impl<'a, S: UniversalChainSigner> RgbTransitionBuilder<'a, S> {
    pub fn new(signer: &'a S) -> Self {
        Self { signer }
    }

    /// Build and sign an RGB state transition.
    pub fn build_transition(
        &self,
        contract_id: RgbContractId,
        schema: RgbSchema,
        seal: RgbSeal,
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<RgbTransition> {
        let transition_hash = Self::compute_transition_hash(&contract_id, &schema, &seal);
        let signature_hex =
            self.signer
                .sign_bitcoin_taproot(transition_hash, derivation_path, key_id, None)?;
        Ok(RgbTransition {
            contract_id,
            transition_id: RgbTransitionId::from_bytes(transition_hash),
            schema,
            seal,
            signature_hex,
        })
    }

    fn compute_transition_hash(
        contract_id: &RgbContractId,
        schema: &RgbSchema,
        seal: &RgbSeal,
    ) -> [u8; 32] {
        use bitcoin::hashes::{sha256, HashEngine};
        let schema_tag = match schema {
            RgbSchema::Rgb20 => b"RGB20",
            RgbSchema::Rgb21 => b"RGB21",
            RgbSchema::Rgb25 => b"RGB25",
            RgbSchema::Custom(s) => s.as_bytes(),
        };
        let tag = sha256::Hash::hash("RGB/Transition".as_bytes());
        let mut engine = sha256::Hash::engine();
        engine.input(tag.as_byte_array().as_slice());
        engine.input(tag.as_byte_array().as_slice());
        engine.input(contract_id.as_bytes());
        engine.input(schema_tag);
        engine.input(&seal.txid);
        engine.input(&seal.vout.to_le_bytes());
        sha256::Hash::from_engine(engine).to_byte_array()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_id_roundtrips() {
        let id = RgbContractId::from_bytes([0xCD; 32]);
        assert_eq!(*id.as_bytes(), [0xCD; 32]);
    }

    #[test]
    fn seal_construction() {
        let seal = RgbSeal {
            txid: [0xAB; 32],
            vout: 3,
        };
        assert_eq!(seal.vout, 3);
    }

    #[test]
    fn transition_hash_is_deterministic() {
        let cid = RgbContractId::from_bytes([0x01; 32]);
        let seal = RgbSeal {
            txid: [0x02; 32],
            vout: 0,
        };
        let h1 = RgbTransitionBuilder::<crate::signing::ucs::EnclaveUniversalSigner>::compute_transition_hash(&cid, &RgbSchema::Rgb20, &seal);
        let h2 = RgbTransitionBuilder::<crate::signing::ucs::EnclaveUniversalSigner>::compute_transition_hash(&cid, &RgbSchema::Rgb20, &seal);
        assert_eq!(h1, h2);
    }
}
