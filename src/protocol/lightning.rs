use crate::{ConclaveError, ConclaveResult};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
fn current_unix_seconds() -> u64 {
    (js_sys::Date::now() / 1_000.0).max(0.0) as u64
}

#[cfg(not(target_arch = "wasm32"))]
fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

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
    pub fn new(
        payment_hash: String,
        invoice: String,
        amount_msat: u64,
        expiry_secs: Option<u64>,
    ) -> Self {
        let now = current_unix_seconds();

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

    /// Parse and validate BOLT11 invoice parameters against the intent fields.
    pub fn parse_and_validate_invoice(&self) -> ConclaveResult<Bolt11Invoice> {
        let parsed =
            Bolt11Invoice::from_str(&self.invoice).map_err(|_| ConclaveError::InvalidPayload)?;

        let invoice_hash = hex::encode(parsed.payment_hash());
        if !invoice_hash.eq_ignore_ascii_case(&self.payment_hash) {
            return Err(ConclaveError::InvalidPayload);
        }

        if parsed.would_expire(std::time::Duration::from_secs(current_unix_seconds())) {
            return Err(ConclaveError::InvalidPayload);
        }

        if let Some(inv_msat) = parsed.amount_milli_satoshis() {
            if inv_msat != self.amount_msat {
                return Err(ConclaveError::InvalidPayload);
            }
        }

        Ok(parsed)
    }

    /// Verify preimage settlement and update intent state to Succeeded.
    pub fn verify_settlement_preimage(&mut self, preimage_hex: &str) -> ConclaveResult<()> {
        let preimage_bytes =
            hex::decode(preimage_hex).map_err(|_| ConclaveError::InvalidPayload)?;

        if preimage_bytes.len() != 32 {
            return Err(ConclaveError::InvalidPayload);
        }

        use sha2::{Digest, Sha256};
        let computed_hash = Sha256::digest(preimage_bytes);
        let computed_hash_hex = hex::encode(computed_hash);

        if !computed_hash_hex.eq_ignore_ascii_case(&self.payment_hash) {
            return Err(ConclaveError::InvalidPayload);
        }

        self.apply_event(LightningEvent::PaymentSettled {
            preimage: preimage_hex.to_string(),
        })
    }

    pub fn apply_event(&mut self, event: LightningEvent) -> ConclaveResult<()> {
        let now = current_unix_seconds();

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
            (LightningPaymentStatus::Failed, LightningPaymentStatus::Pending) => true, // Retry
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
        let mut intent = LightningPaymentIntent::new(
            "hash123".to_string(),
            "lnbc1...".to_string(),
            1000000,
            None,
        );

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
        let mut intent = LightningPaymentIntent::new(
            "hash456".to_string(),
            "lnbc2...".to_string(),
            500000,
            None,
        );

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
        let mut intent = LightningPaymentIntent::new(
            "hash789".to_string(),
            "lnbc3...".to_string(),
            200000,
            None,
        );

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
        let mut intent = LightningPaymentIntent::new(
            "hash_max".to_string(),
            "lnbc4...".to_string(),
            100000,
            None,
        );

        for _ in 0..MAX_LIGHTNING_RETRIES {
            intent
                .apply_event(LightningEvent::PaymentInitiated)
                .unwrap();
            intent
                .apply_event(LightningEvent::PaymentFailed {
                    failure: LightningFailureType::Transient,
                    reason: "temp error".to_string(),
                })
                .unwrap();
            intent.apply_event(LightningEvent::PaymentRetried).unwrap();
        }

        // Now at Failed state after last retry attempt would move to Pending, but let's say it fails again
        intent
            .apply_event(LightningEvent::PaymentFailed {
                failure: LightningFailureType::Transient,
                reason: "temp error".to_string(),
            })
            .unwrap();

        assert!(!intent.can_retry());
        assert_eq!(intent.retry_count, MAX_LIGHTNING_RETRIES);
    }

    #[test]
    fn test_preimage_settlement_verification() {
        // Preimage 32 bytes of 0x01
        let preimage_bytes = [1u8; 32];
        let preimage_hex = hex::encode(preimage_bytes);
        use sha2::{Digest, Sha256};
        let expected_hash = hex::encode(Sha256::digest(preimage_bytes));

        let mut intent =
            LightningPaymentIntent::new(expected_hash, "lnbc...".to_string(), 50000, None);

        intent
            .apply_event(LightningEvent::PaymentInitiated)
            .unwrap();
        assert_eq!(intent.status, LightningPaymentStatus::Pending);

        // Wrong preimage
        let wrong_preimage = hex::encode([2u8; 32]);
        assert!(intent.verify_settlement_preimage(&wrong_preimage).is_err());

        // Right preimage
        assert!(intent.verify_settlement_preimage(&preimage_hex).is_ok());
        assert_eq!(intent.status, LightningPaymentStatus::Succeeded);
        assert_eq!(intent.preimage, Some(preimage_hex));
    }
}
