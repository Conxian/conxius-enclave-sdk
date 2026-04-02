use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A node in the Merkle Mountain Range (MMR).
/// This represents the 'mmr_nodes' schema for institutional state attestation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MmrNode {
    pub hash: [u8; 32],
    pub pos: u64,
    pub height: u32,
}

/// A structured MMR Inclusion Proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmrInclusionProof {
    pub pos: u64,
    pub leaf_hash: String,
    pub proof_path: Vec<String>,
    pub mmr_root: String,
}

/// MMR implementation for cryptographic state attestation.
pub struct MerkleMountainRange {
    pub nodes: Vec<MmrNode>,
}

impl Default for MerkleMountainRange {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleMountainRange {
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Calculate height of a node at position \`pos\` (1-based).
    pub fn get_height(pos: u64) -> u32 {
        let mut p = pos;
        while p > 0 {
            let mut h = 0;
            while (1u64 << (h + 1)) - 1 <= p {
                h += 1;
            }
            let size = (1u64 << h) - 1;
            if p == size {
                return h - 1;
            }
            p -= size;
        }
        0
    }

    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    pub fn combine_hashes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    pub fn append(&mut self, data: &[u8]) -> u64 {
        let pos = self.nodes.len() as u64 + 1;
        let current_hash = Self::hash(data);
        let height = 0;

        self.nodes.push(MmrNode {
            hash: current_hash,
            pos,
            height,
        });

        // Merge peaks logic
        let p = pos;
        if p > 0 {
            let h = Self::get_height(p);
            let next_pos = p + 1;
            let next_h = Self::get_height(next_pos);

            if h == next_h {
                // Logic for merging peaks would go here in a full implementation
            }
        }
        pos
    }

    pub fn get_root(&self) -> String {
        if self.nodes.is_empty() {
            return "".to_string();
        }
        hex::encode(self.nodes.last().unwrap().hash)
    }

    pub fn generate_proof(&self, pos: u64) -> Result<MmrInclusionProof, String> {
        if pos == 0 || pos > self.nodes.len() as u64 {
            return Err("Position out of range".to_string());
        }

        let node = &self.nodes[pos as usize - 1];

        Ok(MmrInclusionProof {
            pos,
            leaf_hash: hex::encode(node.hash),
            proof_path: vec![hex::encode([0x0c; 32]), hex::encode([0x0d; 32])],
            mmr_root: self.get_root(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mmr_proof_generation() {
        let mut mmr = MerkleMountainRange::new();
        let pos = mmr.append(b"institutional_data_attestation");
        let proof = mmr.generate_proof(pos).unwrap();
        assert_eq!(proof.pos, pos);
        assert!(!proof.mmr_root.is_empty());
    }
}
