//! Lightning channel state machine (structural, fail-closed).
//!
//! Models the channel lifecycle (funding, HTLC add/settle/fail, cooperative
//! and unilateral close) as a type-safe metadata machine. It deliberately holds
//! no secret material: commitment/revocation signing is delegated to
//! `LightningSigner::sign_commitment_tx` through the UCS, and preimage
//! settlement verifies the SHA-256 payment hash before transitioning.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Channel lifecycle phase.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LightningChannelPhase {
    Created,
    PendingOpen,
    Open,
    Closing,
    Dispute,
    Closed,
}

/// Direction of an in-flight HTLC relative to the local node.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LightningHtlcDirection {
    /// We are forwarding/sending the payment.
    Offered,
    /// The counterparty is sending us the payment.
    Received,
}

/// Lifecycle state of a single HTLC.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LightningHtlcState {
    Pending,
    Settled,
    Failed,
}

/// An in-flight HTLC (metadata only — no secret material).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LightningHtlc {
    pub id: u64,
    pub amount_msat: u64,
    pub direction: LightningHtlcDirection,
    pub payment_hash: [u8; 32],
    pub state: LightningHtlcState,
    pub cltv_expiry: u32,
}

/// Channel events recorded for audit/observability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LightningChannelEvent {
    FundingProposed { funding_msat: u64 },
    ChannelOpened,
    HtlcAdded { htlc_id: u64 },
    HtlcSettled { htlc_id: u64 },
    HtlcFailed { htlc_id: u64 },
    CooperativeCloseInitiated,
    ForceCloseInitiated,
    ChannelClosed { closing_txid: String },
}

/// Fail-closed channel state-machine error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LightningChannelError {
    #[error("channel state transition is invalid")]
    InvalidTransition,
    #[error("channel is not open")]
    NotOpen,
    #[error("HTLC is not pending")]
    HtlcNotPending,
    #[error("HTLC not found")]
    HtlcNotFound,
    #[error("insufficient balance")]
    InsufficientBalance,
    #[error("amount must be greater than zero")]
    InvalidAmount,
    #[error("duplicate HTLC id")]
    DuplicateHtlc,
    #[error("preimage does not match the payment hash")]
    InvalidPreimage,
    #[error("unresolved HTLCs prevent cooperative close")]
    UnresolvedHtlcs,
}

/// A Lightning channel. Balances exclude in-flight HTLC amounts; the invariant
/// `local_balance + remote_balance + sum(pending HTLC amounts) == capacity`
/// holds across every valid transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningChannel {
    pub channel_id: String,
    pub counterparty: String,
    pub local_balance_msat: u64,
    pub remote_balance_msat: u64,
    pub phase: LightningChannelPhase,
    pub commitment_number: u64,
    htlc_counter: u64,
    pub htlc_list: Vec<LightningHtlc>,
    pub event_log: Vec<LightningChannelEvent>,
}

impl LightningChannel {
    pub fn new(channel_id: impl Into<String>, counterparty: impl Into<String>) -> Self {
        Self {
            channel_id: channel_id.into(),
            counterparty: counterparty.into(),
            local_balance_msat: 0,
            remote_balance_msat: 0,
            phase: LightningChannelPhase::Created,
            commitment_number: 0,
            htlc_counter: 0,
            htlc_list: Vec::new(),
            event_log: Vec::new(),
        }
    }

    /// Total channel capacity (the conserved balance invariant).
    pub fn capacity_msat(&self) -> u64 {
        let pending: u64 = self
            .htlc_list
            .iter()
            .filter(|htlc| htlc.state == LightningHtlcState::Pending)
            .map(|htlc| htlc.amount_msat)
            .sum();
        self.local_balance_msat
            .saturating_add(self.remote_balance_msat)
            .saturating_add(pending)
    }

    pub fn is_open(&self) -> bool {
        self.phase == LightningChannelPhase::Open
    }

    pub fn pending_htlc_count(&self) -> usize {
        self.htlc_list
            .iter()
            .filter(|htlc| htlc.state == LightningHtlcState::Pending)
            .count()
    }

    /// Propose channel funding: `Created` -> `PendingOpen`. Either party may
    /// contribute; at least one non-zero side is required.
    pub fn propose_funding(
        &mut self,
        local_funding_msat: u64,
        remote_funding_msat: u64,
    ) -> Result<(), LightningChannelError> {
        if local_funding_msat == 0 && remote_funding_msat == 0 {
            return Err(LightningChannelError::InvalidAmount);
        }
        self.transition_to(LightningChannelPhase::PendingOpen)?;
        self.local_balance_msat = local_funding_msat;
        self.remote_balance_msat = remote_funding_msat;
        self.record(LightningChannelEvent::FundingProposed {
            funding_msat: local_funding_msat.saturating_add(remote_funding_msat),
        });
        Ok(())
    }

    /// Confirm funding broadcast/confirmation: `PendingOpen` -> `Open`.
    pub fn confirm_open(&mut self) -> Result<(), LightningChannelError> {
        self.transition_to(LightningChannelPhase::Open)?;
        self.record(LightningChannelEvent::ChannelOpened);
        Ok(())
    }

    /// Offer an outgoing HTLC. Reserves `amount_msat` from the local balance.
    pub fn add_offered_htlc(
        &mut self,
        amount_msat: u64,
        payment_hash: [u8; 32],
        cltv_expiry: u32,
    ) -> Result<u64, LightningChannelError> {
        self.require_open()?;
        if amount_msat == 0 {
            return Err(LightningChannelError::InvalidAmount);
        }
        if self.local_balance_msat < amount_msat {
            return Err(LightningChannelError::InsufficientBalance);
        }
        let id = self.alloc_htlc_id()?;
        self.local_balance_msat -= amount_msat;
        self.htlc_list.push(LightningHtlc {
            id,
            amount_msat,
            direction: LightningHtlcDirection::Offered,
            payment_hash,
            state: LightningHtlcState::Pending,
            cltv_expiry,
        });
        self.commitment_number = self.commitment_number.saturating_add(1);
        self.record(LightningChannelEvent::HtlcAdded { htlc_id: id });
        Ok(id)
    }

    /// Accept an incoming HTLC. Reserves `amount_msat` from the remote balance.
    pub fn receive_htlc(
        &mut self,
        amount_msat: u64,
        payment_hash: [u8; 32],
        cltv_expiry: u32,
    ) -> Result<u64, LightningChannelError> {
        self.require_open()?;
        if amount_msat == 0 {
            return Err(LightningChannelError::InvalidAmount);
        }
        if self.remote_balance_msat < amount_msat {
            return Err(LightningChannelError::InsufficientBalance);
        }
        let id = self.alloc_htlc_id()?;
        self.remote_balance_msat -= amount_msat;
        self.htlc_list.push(LightningHtlc {
            id,
            amount_msat,
            direction: LightningHtlcDirection::Received,
            payment_hash,
            state: LightningHtlcState::Pending,
            cltv_expiry,
        });
        self.commitment_number = self.commitment_number.saturating_add(1);
        self.record(LightningChannelEvent::HtlcAdded { htlc_id: id });
        Ok(id)
    }

    /// Settle a pending HTLC with a valid SHA-256 preimage.
    pub fn settle_htlc(
        &mut self,
        htlc_id: u64,
        preimage: &[u8; 32],
    ) -> Result<(), LightningChannelError> {
        self.require_open()?;
        let payment_hash: [u8; 32] = Sha256::digest(preimage).into();
        let index = self.htlc_index(htlc_id)?;
        if self.htlc_list[index].state != LightningHtlcState::Pending {
            return Err(LightningChannelError::HtlcNotPending);
        }
        if self.htlc_list[index].payment_hash != payment_hash {
            return Err(LightningChannelError::InvalidPreimage);
        }
        let amount = self.htlc_list[index].amount_msat;
        match self.htlc_list[index].direction {
            LightningHtlcDirection::Offered => {
                // We paid the counterparty; the reserved amount leaves the channel.
                self.remote_balance_msat = self.remote_balance_msat.saturating_add(amount);
            }
            LightningHtlcDirection::Received => {
                // The counterparty paid us.
                self.local_balance_msat = self.local_balance_msat.saturating_add(amount);
            }
        }
        self.htlc_list[index].state = LightningHtlcState::Settled;
        self.commitment_number = self.commitment_number.saturating_add(1);
        self.record(LightningChannelEvent::HtlcSettled { htlc_id });
        Ok(())
    }

    /// Fail a pending HTLC, refunding the reserved amount to the originator.
    pub fn fail_htlc(&mut self, htlc_id: u64) -> Result<(), LightningChannelError> {
        self.require_open()?;
        let index = self.htlc_index(htlc_id)?;
        if self.htlc_list[index].state != LightningHtlcState::Pending {
            return Err(LightningChannelError::HtlcNotPending);
        }
        let amount = self.htlc_list[index].amount_msat;
        match self.htlc_list[index].direction {
            LightningHtlcDirection::Offered => {
                self.local_balance_msat = self.local_balance_msat.saturating_add(amount);
            }
            LightningHtlcDirection::Received => {
                self.remote_balance_msat = self.remote_balance_msat.saturating_add(amount);
            }
        }
        self.htlc_list[index].state = LightningHtlcState::Failed;
        self.commitment_number = self.commitment_number.saturating_add(1);
        self.record(LightningChannelEvent::HtlcFailed { htlc_id });
        Ok(())
    }

    /// Initiate a cooperative close. Requires a fully-resolved HTLC set.
    pub fn initiate_cooperative_close(&mut self) -> Result<(), LightningChannelError> {
        self.require_open()?;
        if self.pending_htlc_count() != 0 {
            return Err(LightningChannelError::UnresolvedHtlcs);
        }
        self.transition_to(LightningChannelPhase::Closing)?;
        self.record(LightningChannelEvent::CooperativeCloseInitiated);
        Ok(())
    }

    /// Initiate a unilateral (force) close.
    pub fn force_close(&mut self) -> Result<(), LightningChannelError> {
        if !matches!(self.phase, LightningChannelPhase::Open | LightningChannelPhase::Closing) {
            return Err(LightningChannelError::InvalidTransition);
        }
        self.transition_to(LightningChannelPhase::Dispute)?;
        self.record(LightningChannelEvent::ForceCloseInitiated);
        Ok(())
    }

    /// Terminal close: `Closing` or `Dispute` -> `Closed`.
    pub fn complete_close(&mut self, closing_txid: impl Into<String>) -> Result<(), LightningChannelError> {
        if !matches!(self.phase, LightningChannelPhase::Closing | LightningChannelPhase::Dispute) {
            return Err(LightningChannelError::InvalidTransition);
        }
        self.transition_to(LightningChannelPhase::Closed)?;
        self.record(LightningChannelEvent::ChannelClosed {
            closing_txid: closing_txid.into(),
        });
        Ok(())
    }

    fn require_open(&self) -> Result<(), LightningChannelError> {
        if !self.is_open() {
            return Err(LightningChannelError::NotOpen);
        }
        Ok(())
    }

    fn alloc_htlc_id(&mut self) -> Result<u64, LightningChannelError> {
        self.htlc_counter = self.htlc_counter.saturating_add(1);
        let id = self.htlc_counter;
        if self.htlc_list.iter().any(|htlc| htlc.id == id) {
            return Err(LightningChannelError::DuplicateHtlc);
        }
        Ok(id)
    }

    fn htlc_index(&self, htlc_id: u64) -> Result<usize, LightningChannelError> {
        self.htlc_list
            .iter()
            .position(|htlc| htlc.id == htlc_id)
            .ok_or(LightningChannelError::HtlcNotFound)
    }

    fn transition_to(&mut self, next: LightningChannelPhase) -> Result<(), LightningChannelError> {
        let valid = matches!(
            (self.phase, next),
            (LightningChannelPhase::Created, LightningChannelPhase::PendingOpen)
                | (LightningChannelPhase::PendingOpen, LightningChannelPhase::Open)
                | (LightningChannelPhase::Open, LightningChannelPhase::Closing)
                | (LightningChannelPhase::Open, LightningChannelPhase::Dispute)
                | (LightningChannelPhase::Closing, LightningChannelPhase::Dispute)
                | (LightningChannelPhase::Closing, LightningChannelPhase::Closed)
                | (LightningChannelPhase::Dispute, LightningChannelPhase::Closed)
        );
        if !valid {
            return Err(LightningChannelError::InvalidTransition);
        }
        self.phase = next;
        Ok(())
    }

    fn record(&mut self, event: LightningChannelEvent) {
        self.event_log.push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_channel(local_msat: u64, remote_msat: u64) -> LightningChannel {
        let mut channel = LightningChannel::new("chan-1", "counterparty");
        channel.propose_funding(local_msat, remote_msat).unwrap();
        channel.confirm_open().unwrap();
        channel
    }

    fn preimage(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn payment_hash_of(preimage: [u8; 32]) -> [u8; 32] {
        Sha256::digest(preimage).into()
    }

    #[test]
    fn channel_lifecycle_progresses_through_phases() {
        let mut channel = LightningChannel::new("chan-1", "peer");
        assert_eq!(channel.phase, LightningChannelPhase::Created);
        assert_eq!(channel.capacity_msat(), 0);

        channel.propose_funding(1_000_000, 0).unwrap();
        assert_eq!(channel.phase, LightningChannelPhase::PendingOpen);
        assert_eq!(channel.local_balance_msat, 1_000_000);
        assert_eq!(channel.capacity_msat(), 1_000_000);

        channel.confirm_open().unwrap();
        assert!(channel.is_open());
    }

    #[test]
    fn offered_htlc_settle_and_fail_preserve_capacity_invariant() {
        let mut channel = open_channel(1_000_000, 0);
        let hash = payment_hash_of(preimage(7));

        let id = channel.add_offered_htlc(100_000, hash, 500).unwrap();
        assert_eq!(channel.local_balance_msat, 900_000);
        assert_eq!(channel.capacity_msat(), 1_000_000);

        channel.settle_htlc(id, &preimage(7)).unwrap();
        assert_eq!(channel.remote_balance_msat, 100_000);
        assert_eq!(channel.local_balance_msat, 900_000);
        assert_eq!(channel.capacity_msat(), 1_000_000);
        assert_eq!(channel.pending_htlc_count(), 0);
    }

    #[test]
    fn received_htlc_settle_and_fail_preserve_capacity_invariant() {
        let mut channel = open_channel(1_000_000, 1_000_000);
        assert_eq!(channel.capacity_msat(), 2_000_000);

        // A received HTLC that settles pays us.
        let id = channel
            .receive_htlc(300_000, payment_hash_of(preimage(1)), 500)
            .unwrap();
        assert_eq!(channel.remote_balance_msat, 700_000);
        channel.settle_htlc(id, &preimage(1)).unwrap();
        assert_eq!(channel.local_balance_msat, 1_300_000);
        assert_eq!(channel.capacity_msat(), 2_000_000);

        // A received HTLC that fails refunds the counterparty.
        let id = channel
            .receive_htlc(200_000, payment_hash_of(preimage(2)), 500)
            .unwrap();
        assert_eq!(channel.remote_balance_msat, 500_000);
        channel.fail_htlc(id).unwrap();
        assert_eq!(channel.remote_balance_msat, 700_000);
        assert_eq!(channel.capacity_msat(), 2_000_000);
    }

    #[test]
    fn channel_fails_closed_on_invalid_operations() {
        let mut channel = LightningChannel::new("chan-1", "peer");

        // Cannot add HTLC before the channel is open.
        assert_eq!(
            channel.add_offered_htlc(1_000, [0; 32], 500),
            Err(LightningChannelError::NotOpen)
        );

        channel.propose_funding(1_000_000, 0).unwrap();
        channel.confirm_open().unwrap();

        // Zero amount rejected.
        assert_eq!(
            channel.add_offered_htlc(0, [0; 32], 500),
            Err(LightningChannelError::InvalidAmount)
        );

        // Over-spend rejected.
        assert_eq!(
            channel.add_offered_htlc(2_000_000, [0; 32], 500),
            Err(LightningChannelError::InsufficientBalance)
        );

        // Invalid transition: cannot confirm_open again.
        assert_eq!(
            channel.confirm_open(),
            Err(LightningChannelError::InvalidTransition)
        );
    }

    #[test]
    fn settle_requires_correct_preimage() {
        let mut channel = open_channel(1_000_000, 0);
        let id = channel.add_offered_htlc(100_000, payment_hash_of(preimage(7)), 500).unwrap();

        assert_eq!(
            channel.settle_htlc(id, &preimage(8)),
            Err(LightningChannelError::InvalidPreimage)
        );
        // HTLC remains pending and balance unchanged.
        assert_eq!(channel.pending_htlc_count(), 1);
        assert_eq!(channel.local_balance_msat, 900_000);

        channel.settle_htlc(id, &preimage(7)).unwrap();
        assert_eq!(channel.pending_htlc_count(), 0);
    }

    #[test]
    fn cooperative_close_requires_resolved_htlcs() {
        let mut channel = open_channel(1_000_000, 0);
        let id = channel.add_offered_htlc(100_000, payment_hash_of(preimage(7)), 500).unwrap();

        // Unresolved HTLC blocks cooperative close.
        assert_eq!(
            channel.initiate_cooperative_close(),
            Err(LightningChannelError::UnresolvedHtlcs)
        );

        channel.settle_htlc(id, &preimage(7)).unwrap();
        channel.initiate_cooperative_close().unwrap();
        assert_eq!(channel.phase, LightningChannelPhase::Closing);
        channel.complete_close("txid-1").unwrap();
        assert_eq!(channel.phase, LightningChannelPhase::Closed);
    }

    #[test]
    fn force_close_can_occur_with_pending_htlcs() {
        let mut channel = open_channel(1_000_000, 0);
        channel.add_offered_htlc(100_000, payment_hash_of(preimage(7)), 500).unwrap();
        channel.force_close().unwrap();
        assert_eq!(channel.phase, LightningChannelPhase::Dispute);
        channel.complete_close("txid-1").unwrap();
        assert_eq!(channel.phase, LightningChannelPhase::Closed);
    }
}
