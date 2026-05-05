use crate::ConclaveResult;
use crate::enclave::EnclaveManager;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Discreet Log Contracts (DLC) support for non-custodial financial agreements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlcContract {
    pub contract_id: String,
    pub oracle_announcement: String,
    pub local_collateral: u64,
    pub remote_collateral: u64,
    pub state: DlcState,
    pub local_pubkey: Option<String>,
    pub remote_pubkey: Option<String>,
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
    enclave: Option<Arc<dyn EnclaveManager>>,
}

impl Default for DlcManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DlcManager {
    pub fn new() -> Self {
        Self { enclave: None }
    }

    pub fn with_enclave(enclave: Arc<dyn EnclaveManager>) -> Self {
        Self {
            enclave: Some(enclave),
        }
    }

    /// Generates a deterministic DLC contract identifier from parameters.
    pub fn generate_contract_id(&self, oracle_announcement: &str, local_collateral: u64) -> String {
        let mut hasher = Sha256::new();
        hasher.update(oracle_announcement.as_bytes());
        hasher.update(local_collateral.to_be_bytes());
        hex::encode(hasher.finalize())
    }

    /// Transitions a contract to a new state if the move is valid.
    pub fn transition_state(
        &self,
        contract: &mut DlcContract,
        new_state: DlcState,
    ) -> Result<(), String> {
        match (&contract.state, &new_state) {
            (DlcState::Offered, DlcState::Accepted) => contract.state = new_state,
            (DlcState::Accepted, DlcState::Signed) => contract.state = new_state,
            (DlcState::Signed, DlcState::Broadcast) => contract.state = new_state,
            (DlcState::Broadcast, DlcState::Closed) => contract.state = new_state,
            _ => {
                return Err(format!(
                    "Invalid state transition from {:?} to {:?}",
                    contract.state, new_state
                ));
            }
        }
        Ok(())
    }

    /// Prepares a DLC offer with hardware-backed public key.
    pub fn offer_contract(
        &self,
        oracle_announcement: &str,
        local_collateral: u64,
        remote_collateral: u64,
    ) -> ConclaveResult<DlcContract> {
        let local_pubkey = if let Some(enclave) = &self.enclave {
            Some(enclave.get_public_key("m/44'/5757'/0'/0/dlc")?)
        } else {
            None
        };

        let contract_id = self.generate_contract_id(oracle_announcement, local_collateral);

        Ok(DlcContract {
            contract_id,
            oracle_announcement: oracle_announcement.to_string(),
            local_collateral,
            remote_collateral,
            state: DlcState::Offered,
            local_pubkey,
            remote_pubkey: None,
        })
    }

    /// Accepts a DLC offer, adding the remote public key.
    pub fn accept_contract(
        &self,
        mut contract: DlcContract,
        remote_pubkey: String,
    ) -> Result<DlcContract, String> {
        if contract.state != DlcState::Offered {
            return Err("Contract must be in Offered state to be accepted".to_string());
        }

        contract.remote_pubkey = Some(remote_pubkey);
        contract.state = DlcState::Accepted;
        Ok(contract)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::cloud::CloudEnclave;

    #[test]
    fn test_dlc_contract_id_generation() {
        let mgr = DlcManager::new();
        let id1 = mgr.generate_contract_id("oracle_announcement_1", 1000);
        let id2 = mgr.generate_contract_id("oracle_announcement_1", 1000);
        let id3 = mgr.generate_contract_id("oracle_announcement_2", 1000);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_dlc_lifecycle() -> crate::ConclaveResult<()> {
        let enclave = Arc::new(CloudEnclave::new("https://vault.conxian.io".to_string())?);
        let mgr = DlcManager::with_enclave(enclave);

        let mut contract = mgr.offer_contract("announcement_v1", 5000, 5000)?;
        assert_eq!(contract.state, DlcState::Offered);
        assert!(contract.local_pubkey.is_some());

        contract = mgr
            .accept_contract(contract, "remote_pubkey_hex".to_string())
            .map_err(crate::ConclaveError::EnclaveFailure)?;
        assert_eq!(contract.state, DlcState::Accepted);
        assert_eq!(
            contract.remote_pubkey,
            Some("remote_pubkey_hex".to_string())
        );

        mgr.transition_state(&mut contract, DlcState::Signed)
            .map_err(crate::ConclaveError::EnclaveFailure)?;
        assert_eq!(contract.state, DlcState::Signed);

        Ok(())
    }
}
