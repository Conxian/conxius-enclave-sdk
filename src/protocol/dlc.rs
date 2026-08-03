use crate::enclave::EnclaveManager;
use crate::{ConclaveError, ConclaveResult};
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
    ) -> ConclaveResult<()> {
        match (&contract.state, &new_state) {
            (DlcState::Offered, DlcState::Accepted) => contract.state = new_state,
            (DlcState::Accepted, DlcState::Signed) => contract.state = new_state,
            (DlcState::Signed, DlcState::Broadcast) => contract.state = new_state,
            (DlcState::Broadcast, DlcState::Closed) => contract.state = new_state,
            _ => {
                return Err(ConclaveError::EnclaveFailure(format!(
                    "Invalid state transition from {:?} to {:?}",
                    contract.state, new_state
                )));
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
    ) -> ConclaveResult<DlcContract> {
        if contract.state != DlcState::Offered {
            return Err(ConclaveError::EnclaveFailure(
                "Contract must be in Offered state to be accepted".to_string(),
            ));
        }

        contract.remote_pubkey = Some(remote_pubkey);
        contract.state = DlcState::Accepted;
        Ok(contract)
    }

    /// Verify an oracle attestation (BIP-340 Schnorr signature).
    ///
    /// Oracles sign attestations over event outcomes. The message is the
    /// tagged hash `SHA-256("DLC/oracle" || event_id || outcome)`.
    pub fn verify_oracle_attestation(
        &self,
        oracle_pubkey: &[u8; 32],
        event_id: &str,
        outcome: u64,
        attestation_sig: &[u8; 64],
    ) -> ConclaveResult<bool> {
        // BIP-340 tagged hash: SHA-256("DLC/oracle" || event_id || outcome)
        let tag = {
            let mut h = Sha256::new();
            h.update(b"DLC/oracle");
            h.finalize()
        };
        let mut hasher = Sha256::new();
        hasher.update(tag);
        hasher.update(tag);
        hasher.update(event_id.as_bytes());
        hasher.update(&outcome.to_be_bytes());
        let msg_hash: [u8; 32] = hasher.finalize().into();

        let sig = secp256k1::schnorr::Signature::from_byte_array(*attestation_sig);
        let pk = secp256k1::XOnlyPublicKey::from_byte_array(*oracle_pubkey)
            .map_err(|e| ConclaveError::CryptoError(format!("DLC oracle key: {e:?}")))?;

        Ok(secp256k1::schnorr::verify(&sig, &msg_hash, &pk).is_ok())
    }

    /// Build a Contract Execution Transaction (CET) template.
    ///
    /// Constructs the CET output descriptors for a given oracle outcome.
    /// Returns the serialized transaction template bytes (placeholder
    /// format — real PSBT construction requires a bitcoin library).
    pub fn build_cet_template(
        &self,
        contract: &DlcContract,
        oracle_outcome: u64,
        total_collateral: u64,
    ) -> ConclaveResult<Vec<u8>> {
        if contract.state != DlcState::Signed {
            return Err(ConclaveError::EnclaveFailure(
                "CET can only be built for Signed contracts".into(),
            ));
        }

        // CET payout formula: local gets (outcome * total / max_outcome)
        // Add max/2 before division for nearest-integer rounding.
        let local_payout = ((oracle_outcome as u128)
            .saturating_mul(total_collateral as u128)
            .saturating_add(u64::MAX as u128 / 2))
            .saturating_div(u64::MAX as u128) as u64;
        let remote_payout = total_collateral.saturating_sub(local_payout);

        // Serialize CET template: [local_payout: u64][remote_payout: u64][contract_id_hash: 32]
        let mut tpl = Vec::with_capacity(72);
        tpl.extend_from_slice(&local_payout.to_be_bytes());
        tpl.extend_from_slice(&remote_payout.to_be_bytes());

        let mut hasher = Sha256::new();
        hasher.update(contract.contract_id.as_bytes());
        tpl.extend_from_slice(&hasher.finalize());

        Ok(tpl)
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
        let enclave = Arc::new(CloudEnclave::new(
            "https://vault.conxian-labs.com".to_string(),
        )?);
        let mgr = DlcManager::with_enclave(enclave);

        let mut contract = mgr.offer_contract("announcement_v1", 5000, 5000)?;
        assert_eq!(contract.state, DlcState::Offered);
        assert!(contract.local_pubkey.is_some());

        contract = mgr.accept_contract(contract, "remote_pubkey_hex".to_string())?;
        assert_eq!(contract.state, DlcState::Accepted);
        assert_eq!(
            contract.remote_pubkey,
            Some("remote_pubkey_hex".to_string())
        );

        mgr.transition_state(&mut contract, DlcState::Signed)?;
        assert_eq!(contract.state, DlcState::Signed);

        Ok(())
    }

    #[test]
    fn oracle_attestation_invalid_sig_rejected() {
        let mgr = DlcManager::new();
        let result = mgr.verify_oracle_attestation(
            &[2u8; 32], // oracle pubkey
            "btc/usd-2026-08-03",
            45000,
            &[0u8; 64], // all-zero signature (invalid)
        );
        // Should not panic, returns false or error for empty sig
        match result {
            Ok(valid) => assert!(!valid),
            Err(_) => {} // parse failure also acceptable
        }
    }

    #[test]
    fn cet_template_rejects_non_signed_contract() {
        let mgr = DlcManager::new();
        let contract = DlcContract {
            contract_id: "test-dlc-1".into(),
            oracle_announcement: "announcement".into(),
            local_collateral: 5000,
            remote_collateral: 5000,
            state: DlcState::Accepted, // not Signed
            local_pubkey: None,
            remote_pubkey: None,
        };
        assert!(mgr.build_cet_template(&contract, 50, 10000).is_err());
    }

    #[test]
    fn cet_template_payout_is_proportional() {
        let mgr = DlcManager::new();
        let contract = DlcContract {
            contract_id: "test-dlc-2".into(),
            oracle_announcement: "announcement".into(),
            local_collateral: 5000,
            remote_collateral: 5000,
            state: DlcState::Signed,
            local_pubkey: None,
            remote_pubkey: None,
        };
        // 50% outcome → 50% payout
        let cet_50 = mgr
            .build_cet_template(&contract, u64::MAX / 2, 10000)
            .unwrap();
        // First 8 bytes = local payout
        let local_payout = u64::from_be_bytes(cet_50[..8].try_into().unwrap());
        assert_eq!(local_payout, 5000);

        // 100% outcome → 100% payout
        let cet_100 = mgr.build_cet_template(&contract, u64::MAX, 10000).unwrap();
        let local_full = u64::from_be_bytes(cet_100[..8].try_into().unwrap());
        assert_eq!(local_full, 10000);
    }
}
