use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Discreet Log Contracts (DLC) support for non-custodial financial agreements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlcContract {
    pub contract_id: String,
    pub oracle_announcement: String,
    pub local_collateral: u64,
    pub remote_collateral: u64,
    pub state: DlcState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DlcState {
    Offered,
    Accepted,
    Signed,
    Broadcast,
    Closed,
}

pub struct DlcManager {
    // Placeholder for BDK-DLC or specialized Schnorr logic
}

impl Default for DlcManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DlcManager {
    pub fn new() -> Self {
        Self {}
    }

    /// Generates a deterministic DLC contract identifier from parameters.
    pub fn generate_contract_id(&self, oracle_announcement: &str, local_collateral: u64) -> String {
        let mut hasher = Sha256::new();
        hasher.update(oracle_announcement.as_bytes());
        hasher.update(local_collateral.to_be_bytes());
        hex::encode(hasher.finalize())
    }

    /// Transitions a contract to a new state if the move is valid.
    pub fn transition_state(&self, contract: &mut DlcContract, new_state: DlcState) -> Result<(), String> {
        match (&contract.state, &new_state) {
            (DlcState::Offered, DlcState::Accepted) => contract.state = new_state,
            (DlcState::Accepted, DlcState::Signed) => contract.state = new_state,
            (DlcState::Signed, DlcState::Broadcast) => contract.state = new_state,
            (DlcState::Broadcast, DlcState::Closed) => contract.state = new_state,
            _ => return Err(format!("Invalid state transition from {:?} to {:?}", contract.state, new_state)),
        }
        Ok(())
    }
}
