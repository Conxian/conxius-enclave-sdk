//! Separated-share FROST threshold signing (Issue #726 finding F4, #745).
//!
//! The historical [`ThresholdEnclaveManager`](crate::enclave::threshold) stored
//! every operator `KeyPackage` in one process and drove all of them on each
//! `sign`. A FROST `KeyPackage` contains that operator's *secret* signing
//! share, so that design both (a) broke the "no party may ever reconstruct the
//! full secret key" invariant — a coordinator holding any `t` shares can
//! reconstruct the key — and (b) required *all* `n` operators to be online even
//! though only `t` are needed.
//!
//! This module provides the separated-share composition instead:
//!
//! * [`ThresholdOperator`] owns exactly **one** key package (its own secret
//!   share) and runs each signing round locally. Secret material never leaves
//!   it.
//! * [`ThresholdCoordinator`] holds **only public material** — the published
//!   `PublicKeyPackage` and the participant identifiers. It assembles signing
//!   packages from public commitments and aggregates public signature shares.
//!   It cannot reconstruct any secret.
//!
//! Any `t`-of-`n` subset can sign: the coordinator picks the participating ids
//! and only those operators produce nonces and shares. A single offline
//! operator no longer halts signing as long as `t` remain.
//!
//! ```no_run
//! use conxius_enclave_sdk::enclave::separated::{
//!     ThresholdCoordinator, ThresholdOperator,
//! };
//! # fn demo(share1: Vec<u8>, share3: Vec<u8>, pubkey_pkg: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
//! // Each operator is constructed on its own device from its own key package.
//! let op1 = ThresholdOperator::from_key_package(1, share1)?;
//! let op3 = ThresholdOperator::from_key_package(3, share3)?;
//!
//! // The coordinator only needs the public key package and the ids it will use.
//! let coordinator = ThresholdCoordinator::new(pubkey_pkg, 2)?;
//! let message = b"release-authorization";
//!
//! // Round 1: participating operators publish commitments (public).
//! let mut ops = [&op1, &op3];
//! let commitments: Vec<(u16, Vec<u8>)> = ops
//!     .iter()
//!     .map(|op| op.commit().map(|(_, c)| (op.identifier(), c)))
//!     .collect::<Result<_, _>>()?;
//!
//! // Coordinator assembles the signing package from public commitments only.
//! let signing_package = coordinator.signing_package(message, &commitments)?;
//!
//! // Round 2: each operator signs locally with its own nonce.
//! let shares: Vec<(u16, Vec<u8>)> = ops
//!     .iter_mut()
//!     .map(|op| op.sign(&signing_package).map(|s| (op.identifier(), s)))
//!     .collect::<Result<_, _>>()?;
//!
//! // Coordinator aggregates public shares -> one Schnorr signature.
//! let signature = coordinator.aggregate(&signing_package, &shares)?;
//! # Ok(())
//! # }
//! ```

use crate::protocol::frost_crypto::{
    aggregate, create_nonces_and_commitments, create_signature_share,
    create_signing_package_with_ids, key_package_identifier,
};
use crate::ConclaveResult;
use std::collections::BTreeMap;
use zeroize::Zeroize;

/// A single ceremony participant. Owns exactly one FROST key package (its own
/// secret signing share) and the nonces for the current signing round.
///
/// Nonces are single-use by construction: [`ThresholdOperator::sign`] consumes
/// them, so a second call returns an error rather than risking nonce reuse
/// (which would leak the signing share).
pub struct ThresholdOperator {
    identifier: u16,
    key_package: Vec<u8>,
    pending_nonces: Option<Vec<u8>>,
}

impl ThresholdOperator {
    /// Build an operator from its serialized FROST `KeyPackage`. The operator
    /// identifier is read from the package and checked against `expected_id`
    /// so a mis-filed share cannot be signed under the wrong identity.
    pub fn from_key_package(expected_id: u16, key_package: Vec<u8>) -> ConclaveResult<Self> {
        let identifier = key_package_identifier(&key_package)?;
        if identifier != expected_id {
            return Err(crate::ConclaveError::InvalidPayload);
        }
        Ok(Self {
            identifier,
            key_package,
            pending_nonces: None,
        })
    }

    /// This operator's FROST identifier.
    pub fn identifier(&self) -> u16 {
        self.identifier
    }

    /// Round 1: produce a fresh nonce (kept locally) and the public commitment
    /// to be sent to the coordinator. Overwrites any unconsumed nonce from a
    /// previous, abandoned round.
    pub fn commit(&mut self) -> ConclaveResult<(Vec<u8>, Vec<u8>)> {
        if let Some(mut stale) = self.pending_nonces.take() {
            stale.zeroize();
        }
        let (nonce, commitment) = create_nonces_and_commitments(&self.key_package)?;
        self.pending_nonces = Some(nonce.clone());
        Ok((nonce, commitment))
    }

    /// Round 2: sign the coordinator's signing package with this operator's own
    /// nonce. Consumes the nonce so it can never be reused.
    pub fn sign(&mut self, signing_package: &[u8]) -> ConclaveResult<Vec<u8>> {
        let mut nonce = self.pending_nonces.take().ok_or_else(|| {
            crate::ConclaveError::CryptoError(
                "operator has no pending nonce; call commit() first".to_string(),
            )
        })?;
        let share = create_signature_share(&self.key_package, &nonce, signing_package, &[]);
        nonce.zeroize();
        share
    }

    /// Restore a nonce produced by an earlier [`Self::commit`] in a *different*
    /// process (the operator CLI's two-step flow). The nonce is still consumed
    /// by [`Self::sign`], so this does not weaken single-use guarantees; it only
    /// lets the commit and sign steps run in separate invocations. Callers must
    /// persist the nonce with the same care as the key package.
    pub fn load_nonce(&mut self, nonce: Vec<u8>) -> ConclaveResult<()> {
        if self.pending_nonces.is_some() {
            return Err(crate::ConclaveError::CryptoError(
                "operator already holds a pending nonce".to_string(),
            ));
        }
        self.pending_nonces = Some(nonce);
        Ok(())
    }
}

impl Drop for ThresholdOperator {
    fn drop(&mut self) {
        self.key_package.zeroize();
        if let Some(mut nonce) = self.pending_nonces.take() {
            nonce.zeroize();
        }
    }
}

/// Holds only public material. Assembles signing packages from participant
/// commitments and aggregates the resulting public signature shares. It never
/// sees a key package, nonce, or signature share secret input.
pub struct ThresholdCoordinator {
    public_key_package: Vec<u8>,
    min_signers: u16,
}

impl ThresholdCoordinator {
    /// Build a coordinator from the published `PublicKeyPackage` (round-3
    /// public output) and the ceremony threshold `t`.
    pub fn new(public_key_package: Vec<u8>, min_signers: u16) -> ConclaveResult<Self> {
        if min_signers == 0 {
            return Err(crate::ConclaveError::InvalidPayload);
        }
        // Validate that the public key package deserializes and yields a key.
        crate::protocol::frost_crypto::public_key_x_only(&public_key_package)?;
        Ok(Self {
            public_key_package,
            min_signers,
        })
    }

    /// The ceremony threshold this coordinator enforces.
    pub fn min_signers(&self) -> u16 {
        self.min_signers
    }

    /// The aggregated x-only public key (BIP-340) the signatures verify against.
    pub fn aggregated_public_key(&self) -> ConclaveResult<Vec<u8>> {
        crate::protocol::frost_crypto::public_key_x_only(&self.public_key_package)
    }

    /// Assemble the signing package from `(identifier, commitment)` pairs
    /// supplied by the participating operators. Requires at least
    /// `min_signers` distinct participants and binds each commitment to its
    /// real identifier (fixes the positional-id defect).
    pub fn signing_package(
        &self,
        message: &[u8],
        commitments: &[(u16, Vec<u8>)],
    ) -> ConclaveResult<Vec<u8>> {
        if (commitments.len() as u16) < self.min_signers {
            return Err(crate::ConclaveError::CryptoError(format!(
                "signing package needs at least {} participants, got {}",
                self.min_signers,
                commitments.len()
            )));
        }
        let mut seen = BTreeMap::new();
        for (id, _) in commitments {
            if seen.insert(*id, ()).is_some() {
                return Err(crate::ConclaveError::CryptoError(format!(
                    "duplicate participant id {id} in signing set"
                )));
            }
        }
        let ids: Vec<u16> = commitments.iter().map(|(id, _)| *id).collect();
        let commitment_bytes: Vec<Vec<u8>> = commitments.iter().map(|(_, c)| c.clone()).collect();
        create_signing_package_with_ids(message, &ids, &commitment_bytes)
    }

    /// Aggregate the participating operators' public signature shares into a
    /// single hex-encoded Schnorr signature.
    pub fn aggregate(
        &self,
        signing_package: &[u8],
        shares: &[(u16, Vec<u8>)],
    ) -> ConclaveResult<String> {
        if (shares.len() as u16) < self.min_signers {
            return Err(crate::ConclaveError::CryptoError(format!(
                "aggregation needs at least {} signature shares, got {}",
                self.min_signers,
                shares.len()
            )));
        }
        aggregate(signing_package, shares, &self.public_key_package)
    }
}
