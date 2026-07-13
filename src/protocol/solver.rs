use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};

/// ERC-7683 Solver Selection & Bidding Primitives
/// Facilitates competitive intent fulfillment across cross-chain rails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolverBid {
    pub solver_id: String,
    pub rail_name: String,
    pub output_amount: u64,
    pub fee_sats: u64,
    pub estimated_latency_secs: u32,
}

impl SolverBid {
    /// Heuristic score: Higher is better.
    /// (Output Amount / Latency) - Fee factor
    pub fn score(&self) -> u64 {
        let latency = if self.estimated_latency_secs == 0 {
            1
        } else {
            self.estimated_latency_secs
        };
        (self.output_amount / latency as u64).saturating_sub(self.fee_sats / 10)
    }
}

pub struct SolverManager;

impl SolverManager {
    /// Ranks solver bids according to ERC-7683 yield and speed priorities.
    pub fn rank_bids(mut bids: Vec<SolverBid>) -> ConclaveResult<Vec<SolverBid>> {
        if bids.is_empty() {
            return Err(ConclaveError::RailError("No bids to rank".to_string()));
        }

        bids.sort_by_key(|b| std::cmp::Reverse(b.score()));
        Ok(bids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solver_ranking_prioritizes_yield() {
        let bid1 = SolverBid {
            solver_id: "s1".into(),
            rail_name: "r1".into(),
            output_amount: 1000,
            fee_sats: 100,
            estimated_latency_secs: 60,
        };
        let bid2 = SolverBid {
            solver_id: "s2".into(),
            rail_name: "r2".into(),
            output_amount: 1050,
            fee_sats: 100,
            estimated_latency_secs: 60,
        };

        let ranked = SolverManager::rank_bids(vec![bid1, bid2]).unwrap();
        assert_eq!(ranked[0].solver_id, "s2");
    }
}
