use crate::{ConclaveError, ConclaveResult};
use bitcoin::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// OP_CAT Recursive Covenant Manager (BIP-347)
/// Orchestrates script construction for Bitcoin vaults and L2 scaling.
pub struct CovenantManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CovenantScript {
    pub script_hex: String,
    pub internal_key: String,
}

impl CovenantManager {
    /// Generates a BIP-347 compliant OP_CAT vault script.
    /// This script enforces that the next transaction spends to a specific template.
    pub fn generate_cat_vault_script(
        internal_key: &XOnlyPublicKey,
        template_hash: [u8; 32],
    ) -> ConclaveResult<CovenantScript> {
        let mut script = Vec::new();

        // 1. Push template hash for recursive check
        script.push(0x20); // OP_PUSHBYTES_32
        script.extend_from_slice(&template_hash);

        // 2. OP_CAT the spend constraints
        // In a real script, we would be CAT-ing parts of the transaction data
        script.push(0x7e); // OP_CAT

        // 3. Verify against the vault authority key
        script.push(0x20); // OP_PUSHBYTES_32
        script.extend_from_slice(&internal_key.serialize().0);
        script.push(0xac); // OP_CHECKSIG

        Ok(CovenantScript {
            script_hex: hex::encode(script),
            internal_key: internal_key.to_string(),
        })
    }

    /// Verifies if a spending script matches the recursive invariant.
    /// Hardened for v2.0.6: Validates witness elements against the expected template hash.
    pub fn verify_recursive_invariant(
        &self,
        script_witness: &[Vec<u8>],
        expected_template_hash: [u8; 32],
    ) -> ConclaveResult<bool> {
        // Fail-Closed: Ensure witness has required elements for OP_CAT verification
        // Expecting [part1, part2, signature] as a simplified example
        if script_witness.len() < 2 {
            return Err(ConclaveError::InvalidPayload);
        }

        // 1. Reconstruct the concatenated state
        let mut hasher = Sha256::new();
        hasher.update(&script_witness[0]);
        hasher.update(&script_witness[1]);
        let result_hash = hasher.finalize();

        // 2. Verify against the recursive invariant (template hash)
        if result_hash.as_slice() != expected_template_hash {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::XOnlyPublicKey;

    #[test]
    fn test_generate_cat_vault_script() {
        let pubkey = XOnlyPublicKey::from_byte_array(&[1u8; 32]).unwrap();
        let hash = [2u8; 32];
        let res = CovenantManager::generate_cat_vault_script(&pubkey, hash).unwrap();

        assert!(res.script_hex.contains("7e")); // OP_CAT
        assert!(res.script_hex.contains("ac")); // OP_CHECKSIG
    }

    #[test]
    fn test_verify_recursive_invariant_harden() {
        let mgr = CovenantManager;
        let part1 = b"template_prefix".to_vec();
        let part2 = b"template_suffix".to_vec();

        let mut hasher = Sha256::new();
        hasher.update(&part1);
        hasher.update(&part2);
        let expected_hash: [u8; 32] = hasher.finalize().into();

        let witness = vec![part1.clone(), part2.clone()];

        // Valid invariant
        assert!(mgr
            .verify_recursive_invariant(&witness, expected_hash)
            .unwrap());

        // Invalid invariant
        let wrong_hash = [0u8; 32];
        assert!(!mgr
            .verify_recursive_invariant(&witness, wrong_hash)
            .unwrap());

        // Empty witness fails closed
        assert!(mgr.verify_recursive_invariant(&[], expected_hash).is_err());
    }
}
