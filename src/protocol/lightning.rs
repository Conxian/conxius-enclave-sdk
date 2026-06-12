use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LightningPaymentStatus {
    Created,
    Pending,
    Succeeded,
    Failed,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LightningFailureType {
    /// Permanent failure (e.g. invalid invoice, no route found after max attempts)
    Permanent,
    /// Transient failure (e.g. temporary routing issue, node offline)
    Transient,
    /// Indeterminate state (e.g. Handoff Limbo, payment in flight with no finality)
    Indeterminate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningPaymentIntent {
    pub payment_hash: String,
    pub invoice: String,
    pub amount_msat: u64,
    pub status: LightningPaymentStatus,
    pub failure_type: Option<LightningFailureType>,
    pub retry_count: u32,
    pub created_at: u64,
    pub last_updated_at: u64,
}

impl LightningPaymentIntent {
    pub fn new(payment_hash: String, invoice: String, amount_msat: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            payment_hash,
            invoice,
            amount_msat,
            status: LightningPaymentStatus::Created,
            failure_type: None,
            retry_count: 0,
            created_at: now,
            last_updated_at: now,
        }
    }

    pub fn transition_to(&mut self, next_status: LightningPaymentStatus) -> ConclaveResult<()> {
        let valid = match (self.status, next_status) {
            (LightningPaymentStatus::Created, LightningPaymentStatus::Pending) => true,
            (LightningPaymentStatus::Pending, LightningPaymentStatus::Succeeded) => true,
            (LightningPaymentStatus::Pending, LightningPaymentStatus::Failed) => true,
            (LightningPaymentStatus::Pending, LightningPaymentStatus::Indeterminate) => true,
            (LightningPaymentStatus::Indeterminate, LightningPaymentStatus::Succeeded) => true,
            (LightningPaymentStatus::Indeterminate, LightningPaymentStatus::Failed) => true,
            (LightningPaymentStatus::Failed, LightningPaymentStatus::Pending) => true, // Retry path
            _ => false,
        };

        if !valid {
            return Err(ConclaveError::InvalidPayload);
        }

        self.status = next_status;
        self.last_updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if next_status != LightningPaymentStatus::Failed {
            self.failure_type = None;
        }

        Ok(())
    }

    pub fn mark_failed(&mut self, failure_type: LightningFailureType) -> ConclaveResult<()> {
        self.transition_to(LightningPaymentStatus::Failed)?;
        self.failure_type = Some(failure_type);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_lifecycle() {
        let mut intent =
            LightningPaymentIntent::new("hash123".to_string(), "lnbc1...".to_string(), 1000000);

        assert_eq!(intent.status, LightningPaymentStatus::Created);

        intent
            .transition_to(LightningPaymentStatus::Pending)
            .unwrap();
        assert_eq!(intent.status, LightningPaymentStatus::Pending);

        intent
            .transition_to(LightningPaymentStatus::Succeeded)
            .unwrap();
        assert_eq!(intent.status, LightningPaymentStatus::Succeeded);
    }

    #[test]
    fn test_failure_taxonomy() {
        let mut intent =
            LightningPaymentIntent::new("hash456".to_string(), "lnbc2...".to_string(), 500000);

        intent
            .transition_to(LightningPaymentStatus::Pending)
            .unwrap();
        intent.mark_failed(LightningFailureType::Transient).unwrap();

        assert_eq!(intent.status, LightningPaymentStatus::Failed);
        assert_eq!(intent.failure_type, Some(LightningFailureType::Transient));

        // Retry
        intent
            .transition_to(LightningPaymentStatus::Pending)
            .unwrap();
        assert_eq!(intent.status, LightningPaymentStatus::Pending);
        assert!(intent.failure_type.is_none());
    }

    #[test]
    fn test_invalid_transition() {
        let mut intent =
            LightningPaymentIntent::new("hash789".to_string(), "lnbc3...".to_string(), 1000);

        let result = intent.transition_to(LightningPaymentStatus::Succeeded);
        assert!(result.is_err());
    }
}
