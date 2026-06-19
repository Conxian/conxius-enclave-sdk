use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LIGHTNING_RETRIES: u32 = 5;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LightningPaymentStatus {
    Created,
    Pending,
    Succeeded,
    Failed,
    Indeterminate,
    Expired,
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
    PaymentExpired,
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
    pub expires_at: Option<u64>,
    pub event_log: Vec<(u64, LightningEvent)>,
}

impl LightningPaymentIntent {
    pub fn new(payment_hash: String, invoice: String, amount_msat: u64, expiry_secs: Option<u64>) -> Self {
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
            expires_at: expiry_secs.map(|s| now + s),
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
                if !self.can_retry() {
                    return Err(ConclaveError::InvalidPayload);
                }
                self.retry_count += 1;
                LightningPaymentStatus::Pending
            }
            LightningEvent::PaymentExpired => LightningPaymentStatus::Expired,
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

    pub fn can_retry(&self) -> bool {
        if self.status != LightningPaymentStatus::Failed {
            return false;
        }

        if self.retry_count >= MAX_LIGHTNING_RETRIES {
            return false;
        }

        match self.failure_type {
            Some(LightningFailureType::Permanent) => false,
            Some(LightningFailureType::Transient) => true,
            Some(LightningFailureType::Indeterminate) => false, // Fails closed
            None => false,
        }
    }

    pub fn is_final(&self) -> bool {
        matches!(
            self.status,
            LightningPaymentStatus::Succeeded | LightningPaymentStatus::Expired
        ) || (self.status == LightningPaymentStatus::Failed && !self.can_retry())
    }

    fn validate_transition(&self, next_status: LightningPaymentStatus) -> ConclaveResult<()> {
        let valid = match (self.status, next_status) {
            (LightningPaymentStatus::Created, LightningPaymentStatus::Pending) => true,
            (LightningPaymentStatus::Pending, LightningPaymentStatus::Pending) => true,
            (LightningPaymentStatus::Pending, LightningPaymentStatus::Succeeded) => true,
            (LightningPaymentStatus::Pending, LightningPaymentStatus::Failed) => true,
            (LightningPaymentStatus::Pending, LightningPaymentStatus::Indeterminate) => true,
            (LightningPaymentStatus::Pending, LightningPaymentStatus::Expired) => true,
            (LightningPaymentStatus::Indeterminate, LightningPaymentStatus::Succeeded) => true,
            (LightningPaymentStatus::Indeterminate, LightningPaymentStatus::Failed) => true,
            (LightningPaymentStatus::Failed, LightningPaymentStatus::Pending) => true,
            (LightningPaymentStatus::Failed, LightningPaymentStatus::Expired) => true,
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
            LightningPaymentIntent::new("hash123".to_string(), "lnbc1...".to_string(), 1000000, None);

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
        assert!(intent.is_final());
    }

    #[test]
    fn test_failure_and_retry() {
        let mut intent =
            LightningPaymentIntent::new("hash456".to_string(), "lnbc2...".to_string(), 500000, None);

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
        assert!(intent.can_retry());

        intent.apply_event(LightningEvent::PaymentRetried).unwrap();
        assert_eq!(intent.status, LightningPaymentStatus::Pending);
        assert_eq!(intent.retry_count, 1);
        assert!(intent.failure_type.is_none());
    }

    #[test]
    fn test_permanent_failure_blocks_retry() {
        let mut intent =
            LightningPaymentIntent::new("hash789".to_string(), "lnbc3...".to_string(), 200000, None);

        intent
            .apply_event(LightningEvent::PaymentInitiated)
            .unwrap();
        intent
            .apply_event(LightningEvent::PaymentFailed {
                failure: LightningFailureType::Permanent,
                reason: "invalid invoice".to_string(),
            })
            .unwrap();

        assert!(!intent.can_retry());
        assert!(intent.apply_event(LightningEvent::PaymentRetried).is_err());
        assert!(intent.is_final());
    }

    #[test]
    fn test_max_retries() {
        let mut intent =
            LightningPaymentIntent::new("hash_max".to_string(), "lnbc4...".to_string(), 100000, None);

        for _ in 0..MAX_LIGHTNING_RETRIES {
            intent.apply_event(LightningEvent::PaymentInitiated).unwrap();
            intent.apply_event(LightningEvent::PaymentFailed {
                failure: LightningFailureType::Transient,
                reason: "temp error".to_string(),
            }).unwrap();
            intent.apply_event(LightningEvent::PaymentRetried).unwrap();
        }

        // Now at Failed state after last retry attempt would move to Pending, but let's say it fails again
        intent.apply_event(LightningEvent::PaymentFailed {
            failure: LightningFailureType::Transient,
            reason: "temp error".to_string(),
        }).unwrap();

        assert!(!intent.can_retry());
        assert_eq!(intent.retry_count, MAX_LIGHTNING_RETRIES);
    }
}
