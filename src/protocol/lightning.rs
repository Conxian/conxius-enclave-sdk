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

    /// Compute a fail-closed multi-hop route for this payment from
    /// `source_node` to the invoice payee. Route selection is deterministic and
    /// fails closed (no route, capacity/fee/CLTV/hop violation) rather than
    /// returning a partial or unverifiable path.
    pub fn compute_route(
        &self,
        source_node: &str,
        graph: &LightningNetworkGraph,
        constraints: &LightningRouteConstraints,
    ) -> Result<LightningRoute, LightningRouteError> {
        let invoice = self
            .parse_and_validate_invoice()
            .map_err(|_| LightningRouteError::InvalidInvoice)?;
        let payee = invoice
            .payee_pub_key()
            .ok_or(LightningRouteError::InvalidInvoice)?;
        let target_node = hex::encode(payee.serialize());
        LightningRouter::find_route(
            graph,
            source_node,
            &target_node,
            self.amount_msat,
            constraints,
        )
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

// ── Route-finding ────────────────────────────────────────────────────────
//
// Deterministic, fail-closed route selection over a channel graph. This is a
// self-contained route-finder (Dijkstra over directed channel edges) rather
// than a full LDK node; it enforces amount/capacity, fee, CLTV, and hop budget
// constraints and never returns a partial or unverifiable path.

/// A directed Lightning channel edge in the route-finding graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LightningChannelEdge {
    pub source: String,
    pub target: String,
    pub short_channel_id: u64,
    pub capacity_msat: u64,
    pub htlc_minimum_msat: u64,
    pub htlc_maximum_msat: Option<u64>,
    pub base_fee_msat: u64,
    pub proportional_fee_ppm: u64,
    pub cltv_expiry_delta: u32,
    pub enabled: bool,
}

/// A snapshot of the Lightning network channel graph for route selection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LightningNetworkGraph {
    edges: Vec<LightningChannelEdge>,
}

impl LightningNetworkGraph {
    pub fn new() -> Self {
        Self { edges: Vec::new() }
    }

    pub fn add_edge(&mut self, edge: LightningChannelEdge) -> &mut Self {
        self.edges.push(edge);
        self
    }

    pub fn edges(&self) -> &[LightningChannelEdge] {
        &self.edges
    }

    pub fn len(&self) -> usize {
        self.edges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    fn enabled_edges_from<'a>(
        &'a self,
        node: &'a str,
    ) -> impl Iterator<Item = &'a LightningChannelEdge> + 'a {
        self.edges
            .iter()
            .filter(move |edge| edge.enabled && edge.source == node)
    }
}

/// A single hop in a computed route.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LightningRouteHop {
    pub node_id: String,
    pub short_channel_id: u64,
    pub fee_msat: u64,
    pub cltv_expiry_delta: u32,
}

/// A computed multi-hop route.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LightningRoute {
    pub hops: Vec<LightningRouteHop>,
    pub total_fee_msat: u64,
    pub total_cltv_delta: u32,
}

impl LightningRoute {
    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    pub fn len(&self) -> usize {
        self.hops.len()
    }
}

/// Route-selection budget constraints. `None` means unbounded.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LightningRouteConstraints {
    pub max_fee_msat: Option<u64>,
    pub max_cltv_delta: Option<u32>,
    pub max_hops: Option<usize>,
}

/// Fail-closed route-finding error. Budget/capacity/CLTV violations fold into
/// `NoRoute`: the router either finds a feasible route or reports none, and
/// never returns a partial or unverifiable path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LightningRouteError {
    #[error("no feasible route found")]
    NoRoute,
    #[error("route-finding graph is empty")]
    GraphEmpty,
    #[error("payment amount must be greater than zero")]
    AmountBelowMinimum,
    #[error("invoice is invalid or missing a payee node")]
    InvalidInvoice,
}

fn edge_fee_msat(edge: &LightningChannelEdge, amount_msat: u64) -> u64 {
    let proportional = (edge.proportional_fee_ppm as u128 * amount_msat as u128) / 1_000_000;
    edge.base_fee_msat.saturating_add(proportional as u64)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueueEntry {
    node: String,
    fee_msat: u64,
    cltv_delta: u32,
    hops: usize,
}

impl Ord for QueueEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse to make a min-heap keyed on (fee, cltv, hops).
        other
            .fee_msat
            .cmp(&self.fee_msat)
            .then_with(|| other.cltv_delta.cmp(&self.cltv_delta))
            .then_with(|| other.hops.cmp(&self.hops))
            .then_with(|| other.node.cmp(&self.node))
    }
}

impl PartialOrd for QueueEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Deterministic, fail-closed route finder over a channel graph.
pub struct LightningRouter;

impl LightningRouter {
    /// Find the minimum-fee route from `source` to `target` for `amount_msat`,
    /// honoring the given budget constraints. Returns `Err` (fail closed) when
    /// no feasible route exists.
    pub fn find_route(
        graph: &LightningNetworkGraph,
        source: &str,
        target: &str,
        amount_msat: u64,
        constraints: &LightningRouteConstraints,
    ) -> Result<LightningRoute, LightningRouteError> {
        if graph.is_empty() {
            return Err(LightningRouteError::GraphEmpty);
        }
        if amount_msat == 0 {
            return Err(LightningRouteError::AmountBelowMinimum);
        }
        if source == target {
            return Err(LightningRouteError::NoRoute);
        }

        use std::collections::{BinaryHeap, HashMap};

        let mut best: HashMap<String, (u64, u32, usize)> = HashMap::new();
        let mut previous: HashMap<String, (String, LightningChannelEdge)> = HashMap::new();
        let mut heap = BinaryHeap::new();

        best.insert(source.to_string(), (0, 0, 0));
        heap.push(QueueEntry {
            node: source.to_string(),
            fee_msat: 0,
            cltv_delta: 0,
            hops: 0,
        });

        while let Some(entry) = heap.pop() {
            // Skip stale entries (lazy deletion).
            if let Some((fee, cltv, hops)) = best.get(&entry.node) {
                if entry.fee_msat > *fee || entry.cltv_delta > *cltv || entry.hops > *hops {
                    continue;
                }
            }

            if entry.node == target {
                break;
            }

            for edge in graph.enabled_edges_from(&entry.node) {
                // Capacity / HTLC-value feasibility.
                if edge.capacity_msat < amount_msat {
                    continue;
                }
                if amount_msat < edge.htlc_minimum_msat {
                    continue;
                }
                if edge.htlc_maximum_msat.is_some_and(|max| amount_msat > max) {
                    continue;
                }

                let fee = edge_fee_msat(edge, amount_msat);
                let new_fee = entry.fee_msat.saturating_add(fee);
                let new_cltv = entry.cltv_delta.saturating_add(edge.cltv_expiry_delta);
                let new_hops = entry.hops + 1;

                if constraints.max_fee_msat.is_some_and(|max| new_fee > max) {
                    continue;
                }
                if constraints.max_cltv_delta.is_some_and(|max| new_cltv > max) {
                    continue;
                }
                if constraints.max_hops.is_some_and(|max| new_hops > max) {
                    continue;
                }

                let better = match best.get(&edge.target) {
                    None => true,
                    Some((fee, cltv, hops)) => (new_fee, new_cltv, new_hops) < (*fee, *cltv, *hops),
                };
                if better {
                    best.insert(edge.target.clone(), (new_fee, new_cltv, new_hops));
                    previous.insert(edge.target.clone(), (entry.node.clone(), edge.clone()));
                    heap.push(QueueEntry {
                        node: edge.target.clone(),
                        fee_msat: new_fee,
                        cltv_delta: new_cltv,
                        hops: new_hops,
                    });
                }
            }
        }

        let (total_fee_msat, total_cltv_delta, _) = best
            .get(target)
            .copied()
            .ok_or(LightningRouteError::NoRoute)?;

        // Reconstruct the path from `target` back to `source`.
        let mut hops: Vec<LightningRouteHop> = Vec::new();
        let mut node = target.to_string();
        while node != source {
            let (prev_node, edge) = previous.get(&node).ok_or(LightningRouteError::NoRoute)?;
            hops.push(LightningRouteHop {
                node_id: edge.target.clone(),
                short_channel_id: edge.short_channel_id,
                fee_msat: edge_fee_msat(edge, amount_msat),
                cltv_expiry_delta: edge.cltv_expiry_delta,
            });
            node = prev_node.clone();
        }
        hops.reverse();

        Ok(LightningRoute {
            hops,
            total_fee_msat,
            total_cltv_delta,
        })
    }
}

/// BOLT12 offer representation for recurring/reusable payments.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bolt12Offer {
    pub raw_offer: String,
    pub offer_id: String,
    pub description: Option<String>,
    pub issuer: Option<String>,
    pub amount_msat: Option<u64>,
}

impl Bolt12Offer {
    /// Parse and validate a BOLT12 offer string (starting with ).
    pub fn parse_and_validate(raw_offer: &str) -> ConclaveResult<Self> {
        let trimmed = raw_offer.trim();
        if !trimmed.to_lowercase().starts_with("lno1") || trimmed.len() < 10 {
            return Err(ConclaveError::InvalidPayload);
        }

        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(trimmed.as_bytes());
        let offer_id = hex::encode(hash);

        Ok(Self {
            raw_offer: trimmed.to_string(),
            offer_id,
            description: None,
            issuer: None,
            amount_msat: None,
        })
    }
}

/// BIP-353 Human-readable DNS Payment Address (user@domain.tld).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bip353PaymentAddress {
    pub user: String,
    pub domain: String,
    pub raw_address: String,
}

impl Bip353PaymentAddress {
    /// Parse and validate a BIP-353 payment address.
    pub fn parse_and_validate(raw_address: &str) -> ConclaveResult<Self> {
        let trimmed = raw_address.trim();
        let parts: Vec<&str> = trimmed.split('@').collect();
        if parts.len() != 2 {
            return Err(ConclaveError::InvalidPayload);
        }

        let user = parts[0].trim();
        let domain = parts[1].trim();

        if user.is_empty() || domain.is_empty() || !domain.contains('.') {
            return Err(ConclaveError::InvalidPayload);
        }

        if !user
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '_' || c == '-')
        {
            return Err(ConclaveError::InvalidPayload);
        }

        Ok(Self {
            user: user.to_string(),
            domain: domain.to_lowercase(),
            raw_address: format!("{}@{}", user, domain.to_lowercase()),
        })
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

    fn channel(
        source: &str,
        target: &str,
        short_channel_id: u64,
        base_fee_msat: u64,
    ) -> LightningChannelEdge {
        LightningChannelEdge {
            source: source.to_string(),
            target: target.to_string(),
            short_channel_id,
            capacity_msat: 1_000_000,
            htlc_minimum_msat: 1,
            htlc_maximum_msat: None,
            base_fee_msat,
            proportional_fee_ppm: 0,
            cltv_expiry_delta: 10,
            enabled: true,
        }
    }

    #[test]
    fn route_finder_selects_minimum_fee_path() {
        let mut graph = LightningNetworkGraph::new();
        graph.add_edge(channel("A", "B", 1, 1));
        graph.add_edge(channel("B", "D", 2, 1));
        graph.add_edge(channel("A", "C", 3, 100));
        graph.add_edge(channel("C", "D", 4, 100));

        let route = LightningRouter::find_route(
            &graph,
            "A",
            "D",
            50_000,
            &LightningRouteConstraints::default(),
        )
        .unwrap();
        assert_eq!(route.total_fee_msat, 2);
        assert_eq!(route.total_cltv_delta, 20);
        assert_eq!(route.len(), 2);
        assert_eq!(route.hops[0].node_id, "B");
        assert_eq!(route.hops[0].short_channel_id, 1);
        assert_eq!(route.hops[1].node_id, "D");
    }

    #[test]
    fn route_finder_fails_closed_without_feasible_path() {
        let mut graph = LightningNetworkGraph::new();
        graph.add_edge(channel("A", "B", 1, 1));
        // No edge out of B → no route to D.
        assert_eq!(
            LightningRouter::find_route(
                &graph,
                "A",
                "D",
                1_000,
                &LightningRouteConstraints::default()
            ),
            Err(LightningRouteError::NoRoute)
        );

        // Source == target is not a valid route.
        assert_eq!(
            LightningRouter::find_route(
                &graph,
                "A",
                "A",
                1_000,
                &LightningRouteConstraints::default()
            ),
            Err(LightningRouteError::NoRoute)
        );

        // Amount exceeds capacity on the only edge.
        let mut small = LightningNetworkGraph::new();
        let mut low_capacity = channel("A", "B", 1, 1);
        low_capacity.capacity_msat = 100;
        small.add_edge(low_capacity);
        assert_eq!(
            LightningRouter::find_route(
                &small,
                "A",
                "B",
                1_000,
                &LightningRouteConstraints::default()
            ),
            Err(LightningRouteError::NoRoute)
        );
    }

    #[test]
    fn route_finder_enforces_budgets_and_disabled_edges() {
        let mut graph = LightningNetworkGraph::new();
        graph.add_edge(channel("A", "B", 1, 5));
        graph.add_edge(channel("B", "D", 2, 5));

        // Fee budget too low (total 10 > 9).
        let fee_budget = LightningRouteConstraints {
            max_fee_msat: Some(9),
            ..LightningRouteConstraints::default()
        };
        assert_eq!(
            LightningRouter::find_route(&graph, "A", "D", 1_000, &fee_budget),
            Err(LightningRouteError::NoRoute)
        );

        // CLTV budget too low (total 20 > 19).
        let cltv_budget = LightningRouteConstraints {
            max_cltv_delta: Some(19),
            ..LightningRouteConstraints::default()
        };
        assert_eq!(
            LightningRouter::find_route(&graph, "A", "D", 1_000, &cltv_budget),
            Err(LightningRouteError::NoRoute)
        );

        // Hop budget too low (2 hops > 1).
        let hop_budget = LightningRouteConstraints {
            max_hops: Some(1),
            ..LightningRouteConstraints::default()
        };
        assert_eq!(
            LightningRouter::find_route(&graph, "A", "D", 1_000, &hop_budget),
            Err(LightningRouteError::NoRoute)
        );

        // Disabled edge is not traversed.
        let mut disabled = LightningNetworkGraph::new();
        let mut blocked = channel("A", "B", 1, 1);
        blocked.enabled = false;
        disabled.add_edge(blocked);
        disabled.add_edge(channel("B", "D", 2, 1));
        assert_eq!(
            LightningRouter::find_route(
                &disabled,
                "A",
                "D",
                1_000,
                &LightningRouteConstraints::default()
            ),
            Err(LightningRouteError::NoRoute)
        );
    }

    #[test]
    fn bolt12_offer_parsing_and_validation() {
        let valid_offer = "lno1qgsqvgnwgcg35z6ee2v3yd2f3pvs2v3yd2f3pvs2v3yd2f3pvs2v3yd2f3pvs";
        let offer = Bolt12Offer::parse_and_validate(valid_offer).unwrap();
        assert_eq!(offer.raw_offer, valid_offer);
        assert_eq!(offer.offer_id.len(), 64);

        assert!(Bolt12Offer::parse_and_validate("lnbc110n1p3...").is_err());
        assert!(Bolt12Offer::parse_and_validate("lno1short").is_err());
        assert!(Bolt12Offer::parse_and_validate("").is_err());
    }

    #[test]
    fn bip353_address_parsing_and_validation() {
        let valid_addr = "alice@pay.example.com";
        let parsed = Bip353PaymentAddress::parse_and_validate(valid_addr).unwrap();
        assert_eq!(parsed.user, "alice");
        assert_eq!(parsed.domain, "pay.example.com");
        assert_eq!(parsed.raw_address, "alice@pay.example.com");

        assert!(Bip353PaymentAddress::parse_and_validate("invalid_no_at_sign").is_err());
        assert!(Bip353PaymentAddress::parse_and_validate("@domain.com").is_err());
        assert!(Bip353PaymentAddress::parse_and_validate("user@nodot").is_err());
        assert!(Bip353PaymentAddress::parse_and_validate("user@").is_err());
        assert!(Bip353PaymentAddress::parse_and_validate("bad user!@domain.com").is_err());
    }

    #[test]
    fn route_finder_validates_graph_and_amount() {
        let graph = LightningNetworkGraph::new();
        assert_eq!(
            LightningRouter::find_route(
                &graph,
                "A",
                "B",
                1_000,
                &LightningRouteConstraints::default()
            ),
            Err(LightningRouteError::GraphEmpty)
        );

        let mut graph = LightningNetworkGraph::new();
        graph.add_edge(channel("A", "B", 1, 1));
        assert_eq!(
            LightningRouter::find_route(&graph, "A", "B", 0, &LightningRouteConstraints::default()),
            Err(LightningRouteError::AmountBelowMinimum)
        );
    }
}
