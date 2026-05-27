use serde::{Serialize, Deserialize};
use crate::ConclaveResult;
use crate::protocol::economy::{DualStackIntent, YieldEngine};
use crate::enclave::EnclaveManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OpportunityPayload {
    DualStack {
        amount_sbtc: u64,
        amount_stx: u64,
        lock_period: u32,
    },
    Swap {
        from: String,
        to: String,
        amount: u64,
    },
}

pub struct OpportunityDispatcher<'a> {
    enclave: &'a dyn EnclaveManager,
}

impl<'a> OpportunityDispatcher<'a> {
    pub fn new(enclave: &'a dyn EnclaveManager) -> Self {
        Self { enclave }
    }

    pub async fn execute(&self, payload: OpportunityPayload) -> ConclaveResult<String> {
        match payload {
            OpportunityPayload::DualStack { amount_sbtc, amount_stx, lock_period } => {
                let engine = YieldEngine::new(self.enclave);
                let (sig, _) = engine.dual_stack(DualStackIntent {
                    amount_sbtc,
                    amount_stx,
                    lock_period,
                })?;
                Ok(sig)
            },
            OpportunityPayload::Swap { .. } => {
                Ok("swap_executed_mock_sig".to_string())
            }
        }
    }
}
