use crate::enclave::EnclaveManager;
use crate::protocol::stacks::StacksManager;
use crate::ConclaveResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualStackIntent {
    pub amount_sbtc: u64,
    pub amount_stx: u64,
    pub lock_period: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StacksPostCondition {
    pub asset_name: String,
    pub amount: u64,
    pub condition_code: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasFeeIntent {
    pub tx_payload: Vec<u8>,
    pub estimated_fee_sbtc: u64,
}

pub struct YieldEngine<'a> {
    enclave: &'a dyn EnclaveManager,
}

impl<'a> YieldEngine<'a> {
    pub fn new(enclave: &'a dyn EnclaveManager) -> Self {
        Self { enclave }
    }

    /// Abstract sBTC 'Dual Stacking' into a 1-click SDK method.
    pub fn dual_stack(
        &self,
        intent: DualStackIntent,
    ) -> ConclaveResult<(String, Vec<StacksPostCondition>)> {
        let post_conditions = vec![
            StacksPostCondition {
                asset_name: "sBTC".to_string(),
                amount: intent.amount_sbtc,
                condition_code: 0x01,
            },
            StacksPostCondition {
                asset_name: "STX".to_string(),
                amount: intent.amount_stx,
                condition_code: 0x01,
            },
        ];

        let payload = format!(
            "(dual-stack {} {} {})",
            intent.amount_sbtc, intent.amount_stx, intent.lock_period
        );

        let stacks_mgr = StacksManager::new(self.enclave);
        let tx_intent = stacks_mgr
            .prepare_transaction(payload.as_bytes())
            .map_err(|_e| crate::ConclaveError::InvalidPayload)?;
        let signature = stacks_mgr.sign_prepared_transaction(tx_intent, "default-key")?;

        Ok((signature, post_conditions))
    }

    /// sBTC as Gas: Abstracts the need for users to hold native tokens for fees.
    pub fn prepare_gas_sponsored_tx(&self, intent: GasFeeIntent) -> ConclaveResult<String> {
        let mut payload = intent.tx_payload.clone();
        payload.extend_from_slice(&intent.estimated_fee_sbtc.to_le_bytes());

        let stacks_mgr = StacksManager::new(self.enclave);
        let tx_intent = stacks_mgr
            .prepare_transaction(&payload)
            .map_err(|_e| crate::ConclaveError::InvalidPayload)?;
        let signature = stacks_mgr.sign_prepared_transaction(tx_intent, "default-key")?;

        Ok(signature)
    }
}
