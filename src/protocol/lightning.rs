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
pub enum LightningEvent {
    PaymentInitiated,
    PaymentInFlight,
    PaymentSettled {
        preimage: String,
    },
    PaymentFailed {
        failure: LightningFailureType,
        reason: String,
    },
    PaymentHandoffLimbo,
    PaymentRetried,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningPaymentIntent {
    pub payment_hash: String,
    pub invoice: String,
    pub amount_msat: u64,
    pub status: LightningPaymentStatus,
    pub failure_type: Option<LightningFailureType>,
    pub failure_reason: Option<String>,
    pub preimage: Option<String>,
    pub retry_count: u32,
    pub created_at: u64,
    pub last_updated_at: u64,
    pub event_log: Vec<(u64, LightningEvent)>,
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
            failure_reason: None,
            preimage: None,
            retry_count: 0,
            created_at: now,
            last_updated_at: now,
            event_log: Vec::new(),
        }
    }

    pub fn apply_event(&mut self, event: LightningEvent) -> ConclaveResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let next_status = match &event {
            LightningEvent::PaymentInitiated => LightningPaymentStatus::Pending,
            LightningEvent::PaymentInFlight => LightningPaymentStatus::Pending,
            LightningEvent::PaymentSettled { .. } => LightningPaymentStatus::Succeeded,
            LightningEvent::PaymentFailed { .. } => LightningPaymentStatus::Failed,
            LightningEvent::PaymentHandoffLimbo => LightningPaymentStatus::Indeterminate,
            LightningEvent::PaymentRetried => {
                self.retry_count += 1;
                LightningPaymentStatus::Pending
            }
        };

        self.validate_transition(next_status)?;

        // Update fields based on event
        match event.clone() {
            LightningEvent::PaymentSettled { preimage } => {
                self.preimage = Some(preimage);
                self.failure_type = None;
                self.failure_reason = None;
            }
            LightningEvent::PaymentFailed { failure, reason } => {
                self.failure_type = Some(failure);
                self.failure_reason = Some(reason);
            }
            LightningEvent::PaymentRetried => {
                self.failure_type = None;
                self.failure_reason = None;
            }
            _ => {}
        }

        self.status = next_status;
        self.last_updated_at = now;
        self.event_log.push((now, event));

        Ok(())
    }

    fn validate_transition(&self, next_status: LightningPaymentStatus) -> ConclaveResult<()> {
        let valid = match (self.status, next_status) {
            (LightningPaymentStatus::Created, LightningPaymentStatus::Pending) => true,
            (LightningPaymentStatus::Pending, LightningPaymentStatus::Pending) => true, // Updates
            (LightningPaymentStatus::Pending, LightningPaymentStatus::Succeeded) => true,
            (LightningPaymentStatus::Pending, LightningPaymentStatus::Failed) => true,
            (LightningPaymentStatus::Pending, LightningPaymentStatus::Indeterminate) => true,
            (LightningPaymentStatus::Indeterminate, LightningPaymentStatus::Succeeded) => true,
            (LightningPaymentStatus::Indeterminate, LightningPaymentStatus::Failed) => true,
            (LightningPaymentStatus::Failed, LightningPaymentStatus::Pending) => true, // Retry
            _ => false,
        };

        if !valid {
            return Err(ConclaveError::InvalidPayload);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_lifecycle_events() {
        let mut intent =
            LightningPaymentIntent::new("hash123".to_string(), "lnbc1...".to_string(), 1000000);

        assert_eq!(intent.status, LightningPaymentStatus::Created);

        intent
            .apply_event(LightningEvent::PaymentInitiated)
            .unwrap();
        assert_eq!(intent.status, LightningPaymentStatus::Pending);

        intent
            .apply_event(LightningEvent::PaymentSettled {
                preimage: "secret".to_string(),
            })
            .unwrap();
        assert_eq!(intent.status, LightningPaymentStatus::Succeeded);
        assert_eq!(intent.preimage, Some("secret".to_string()));
    }

    #[test]
    fn test_failure_and_retry() {
        let mut intent =
            LightningPaymentIntent::new("hash456".to_string(), "lnbc2...".to_string(), 500000);

        intent
            .apply_event(LightningEvent::PaymentInitiated)
            .unwrap();
        intent
            .apply_event(LightningEvent::PaymentFailed {
                failure: LightningFailureType::Transient,
                reason: "no route".to_string(),
            })
            .unwrap();

        assert_eq!(intent.status, LightningPaymentStatus::Failed);
        assert_eq!(intent.failure_type, Some(LightningFailureType::Transient));

        intent.apply_event(LightningEvent::PaymentRetried).unwrap();
        assert_eq!(intent.status, LightningPaymentStatus::Pending);
        assert_eq!(intent.retry_count, 1);
        assert!(intent.failure_type.is_none());
    }
}
