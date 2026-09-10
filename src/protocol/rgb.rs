//! RGB asset protocol boundary (SDK-006, Phase 2 harden).
//!
//! Types for RGB contract state transitions anchored to Bitcoin UTXOs.
//! Phase 2 adds [`RgbTransitionBuilder`] for constructing and signing
//! RGB state transitions through the UCS, plus blinded single-use seals
//! (`RgbBlindedSeal`) and batch asset allocation transitions (`RgbBatchTransition`).

use crate::signing::ucs::UniversalChainSigner;
use crate::{ConclaveError, ConclaveResult};

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

/// Anchors an RGB state transition to an explicit Bitcoin UTXO seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RgbSeal {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// A blinded single-use seal hiding UTXO location via SHA-256 tag and blinding factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RgbBlindedSeal([u8; 32]);

impl RgbBlindedSeal {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compute a blinded single-use seal hash from a Bitcoin UTXO and blinding factor.
    pub fn blind(txid: &[u8; 32], vout: u32, blinding_factor: u64) -> Self {
        use bitcoin::hashes::{sha256, Hash, HashEngine};
        let tag = sha256::Hash::hash("RGB/BlindedSeal".as_bytes());
        let mut engine = sha256::Hash::engine();
        engine.input(tag.as_byte_array().as_slice());
        engine.input(tag.as_byte_array().as_slice());
        engine.input(txid);
        engine.input(&vout.to_le_bytes());
        engine.input(&blinding_factor.to_le_bytes());
        Self(sha256::Hash::from_engine(engine).to_byte_array())
    }

    /// Verify that an unblinded UTXO and blinding factor produce this blinded seal.
    pub fn verify(&self, txid: &[u8; 32], vout: u32, blinding_factor: u64) -> bool {
        let expected = Self::blind(txid, vout, blinding_factor);
        self.0 == expected.0
    }
}

/// RGB asset allocation assignment to a blinded seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RgbAssetAllocation {
    pub asset_id: [u8; 32],
    pub amount: u64,
    pub blinded_seal: RgbBlindedSeal,
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

/// A batch RGB state transition transferring asset allocations to blinded seals.
#[derive(Debug, Clone)]
pub struct RgbBatchTransition {
    pub contract_id: RgbContractId,
    pub transition_id: RgbTransitionId,
    pub inputs: Vec<RgbSeal>,
    pub allocations: Vec<RgbAssetAllocation>,
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

    /// Build and sign a single RGB state transition.
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

    /// Build and sign a batch RGB asset transfer transition to blinded seals.
    pub fn build_batch_transition(
        &self,
        contract_id: RgbContractId,
        inputs: Vec<RgbSeal>,
        allocations: Vec<RgbAssetAllocation>,
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<RgbBatchTransition> {
        if inputs.is_empty() || allocations.is_empty() {
            return Err(ConclaveError::Unsupported(
                "Batch RGB transition requires non-empty inputs and allocations".to_string(),
            ));
        }

        let transition_hash = Self::compute_batch_hash(&contract_id, &inputs, &allocations);
        let signature_hex =
            self.signer
                .sign_bitcoin_taproot(transition_hash, derivation_path, key_id, None)?;

        Ok(RgbBatchTransition {
            contract_id,
            transition_id: RgbTransitionId::from_bytes(transition_hash),
            inputs,
            allocations,
            signature_hex,
        })
    }

    fn compute_transition_hash(
        contract_id: &RgbContractId,
        schema: &RgbSchema,
        seal: &RgbSeal,
    ) -> [u8; 32] {
        use bitcoin::hashes::{sha256, Hash, HashEngine};
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

    fn compute_batch_hash(
        contract_id: &RgbContractId,
        inputs: &[RgbSeal],
        allocations: &[RgbAssetAllocation],
    ) -> [u8; 32] {
        use bitcoin::hashes::{sha256, Hash, HashEngine};
        let tag = sha256::Hash::hash("RGB/BatchTransition".as_bytes());
        let mut engine = sha256::Hash::engine();
        engine.input(tag.as_byte_array().as_slice());
        engine.input(tag.as_byte_array().as_slice());
        engine.input(contract_id.as_bytes());
        for input in inputs {
            engine.input(&input.txid);
            engine.input(&input.vout.to_le_bytes());
        }
        for alloc in allocations {
            engine.input(&alloc.asset_id);
            engine.input(&alloc.amount.to_le_bytes());
            engine.input(alloc.blinded_seal.as_bytes());
        }
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
    fn blinded_seal_derivation_and_verification() {
        let txid = [0x12; 32];
        let vout = 2;
        let blinding = 999888777;

        let blinded = RgbBlindedSeal::blind(&txid, vout, blinding);
        assert_ne!(*blinded.as_bytes(), [0u8; 32]);

        assert!(blinded.verify(&txid, vout, blinding));
        assert!(!blinded.verify(&txid, vout, blinding + 1));
        assert!(!blinded.verify(&[0x99; 32], vout, blinding));
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

    #[test]
    fn batch_transition_hash_is_deterministic() {
        let cid = RgbContractId::from_bytes([0x01; 32]);
        let inputs = vec![RgbSeal {
            txid: [0x02; 32],
            vout: 1,
        }];
        let blinded = RgbBlindedSeal::blind(&[0x03; 32], 0, 12345);
        let allocations = vec![RgbAssetAllocation {
            asset_id: [0xAA; 32],
            amount: 500,
            blinded_seal: blinded,
        }];

        let h1 = RgbTransitionBuilder::<crate::signing::ucs::EnclaveUniversalSigner>::compute_batch_hash(&cid, &inputs, &allocations);
        let h2 = RgbTransitionBuilder::<crate::signing::ucs::EnclaveUniversalSigner>::compute_batch_hash(&cid, &inputs, &allocations);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }
}
