//! Threshold enclave manager (Phase 2).
//!
//! Wires the FROST/MuSig2 threshold signer (`crate::signing::threshold`) into
//! the `EnclaveManager` provider contract. It aggregates participant signature
//! shares into a single Schnorr signature and composes per-share TEE
//! attestations into a single threshold `DeviceIntegrityReport` for the
//! value-bearing signing path.

use crate::enclave::attestation::{
    parse_extension_data, AttestationLevel, AttestationPurpose, DeviceIntegrityReport,
    SignerKeyBindingEvidence, ThresholdParticipantEvidence, ATTESTATION_ENVELOPE_VERSION,
};
use crate::enclave::{
    EnclaveManager, SignRequest, SignResponse, SignerCapability, ValueBearingSignRequest,
    VALUE_BEARING_POLICY_ID,
};
use crate::signing::threshold::ThresholdSigner;
use crate::{ConclaveError, ConclaveResult};
use std::sync::Arc;

/// Produces the per-share integrity reports for a value-bearing threshold
/// request. In production each participant's TEE supplies its own report; the
/// callback keeps the attestation source injectable for tests and ceremony
/// composition.
pub type ShareReportProvider = Arc<
    dyn Fn(&ValueBearingSignRequest) -> ConclaveResult<Vec<DeviceIntegrityReport>> + Send + Sync,
>;

/// A threshold [`EnclaveManager`] that aggregates FROST/MuSig2 signature shares
/// across N independent hardware participants into a single Schnorr signature.
///
/// # Custody (Issue #726 F4, #745)
///
/// Prefer [`ThresholdEnclaveManager::from_public_key_package`]: a coordinator
/// that holds **only** the published `PublicKeyPackage` and drives the signing
/// rounds through the separated-share [`separated`](crate::enclave::separated)
/// API, so no process ever holds a secret share.
///
/// [`ThresholdEnclaveManager::new`] is retained for tests and single-process
/// rehearsal only; it holds every operator `KeyPackage` (i.e. every secret
/// signing share) and is deprecated because a process holding any `t` of them
/// can reconstruct the full key.
pub struct ThresholdEnclaveManager {
    signer: Box<dyn ThresholdSigner + Send + Sync>,
    key_packages: Vec<Vec<u8>>,
    verifying_key_package: Vec<u8>,
    aggregated_public_key_hex: String,
    min_signers: u16,
    max_signers: u16,
    share_report_provider: Option<ShareReportProvider>,
}

impl ThresholdEnclaveManager {
    /// Construct a **custody-free** coordinator from only the published
    /// `PublicKeyPackage`. It holds no secret share and cannot sign on its own;
    /// drive the rounds through [`Self::signing_package`] / [`Self::aggregate`]
    /// with each operator signing locally.
    pub fn from_public_key_package(
        signer: Box<dyn ThresholdSigner + Send + Sync>,
        verifying_key_package: Vec<u8>,
        min_signers: u16,
        max_signers: u16,
    ) -> ConclaveResult<Self> {
        if min_signers == 0 || min_signers > max_signers || max_signers == 0 {
            return Err(ConclaveError::InvalidPayload);
        }
        let aggregated_public_key =
            crate::protocol::frost_crypto::public_key_x_only(&verifying_key_package)?;
        Ok(Self {
            signer,
            key_packages: Vec::new(),
            verifying_key_package,
            aggregated_public_key_hex: hex::encode(aggregated_public_key),
            min_signers,
            max_signers,
            share_report_provider: None,
        })
    }

    /// Construct a threshold manager from an existing key-package set (already
    /// distributed by the DKG ceremony). `verifying_key_package` is the
    /// serialized FROST `PublicKeyPackage`; the aggregated x-only public key is
    /// derived from it.
    #[deprecated(note = "holds every secret share (Issue #726 F4); use \
                ThresholdEnclaveManager::from_public_key_package with the \
                separated-share API, or the enclave::separated coordinator")]
    pub fn new(
        signer: Box<dyn ThresholdSigner + Send + Sync>,
        key_packages: Vec<Vec<u8>>,
        verifying_key_package: Vec<u8>,
        min_signers: u16,
    ) -> ConclaveResult<Self> {
        let max_signers = key_packages.len() as u16;
        if min_signers == 0 || min_signers > max_signers || max_signers == 0 {
            return Err(ConclaveError::InvalidPayload);
        }
        let aggregated_public_key =
            crate::protocol::frost_crypto::public_key_x_only(&verifying_key_package)?;
        Ok(Self {
            signer,
            key_packages,
            verifying_key_package,
            aggregated_public_key_hex: hex::encode(aggregated_public_key),
            min_signers,
            max_signers,
            share_report_provider: None,
        })
    }

    pub fn min_signers(&self) -> u16 {
        self.min_signers
    }

    pub fn max_signers(&self) -> u16 {
        self.max_signers
    }

    pub fn aggregated_public_key_hex(&self) -> &str {
        &self.aggregated_public_key_hex
    }

    /// Whether this manager holds secret shares. A custody-free coordinator
    /// returns `false` and must sign through the separated round-trip.
    pub fn holds_secret_shares(&self) -> bool {
        !self.key_packages.is_empty()
    }

    /// Assemble a signing package from participating operators' public
    /// commitments (round 1 of the separated flow). Requires at least
    /// `min_signers` distinct participants.
    pub fn signing_package(
        &self,
        message: &[u8],
        commitments: &[(u16, Vec<u8>)],
    ) -> ConclaveResult<Vec<u8>> {
        if (commitments.len() as u16) < self.min_signers {
            return Err(ConclaveError::CryptoError(format!(
                "signing package needs at least {} participants, got {}",
                self.min_signers,
                commitments.len()
            )));
        }
        let mut seen = std::collections::BTreeSet::new();
        for (id, _) in commitments {
            if !seen.insert(*id) {
                return Err(ConclaveError::CryptoError(format!(
                    "duplicate participant id {id} in signing set"
                )));
            }
        }
        let ids: Vec<u16> = commitments.iter().map(|(id, _)| *id).collect();
        let commitment_bytes: Vec<Vec<u8>> = commitments.iter().map(|(_, c)| c.clone()).collect();
        crate::protocol::frost_crypto::create_signing_package_with_ids(
            message,
            &ids,
            &commitment_bytes,
        )
    }

    /// Aggregate participating operators' public signature shares (round 2 of
    /// the separated flow) into one Schnorr signature (hex).
    pub fn aggregate(
        &self,
        signing_package: &[u8],
        shares: &[(u16, Vec<u8>)],
    ) -> ConclaveResult<String> {
        if (shares.len() as u16) < self.min_signers {
            return Err(ConclaveError::CryptoError(format!(
                "aggregation needs at least {} signature shares, got {}",
                self.min_signers,
                shares.len()
            )));
        }
        self.signer
            .aggregate(signing_package, shares, &self.verifying_key_package)
    }

    /// Attach the per-share attestation source used by value-bearing signing.
    pub fn with_share_report_provider(mut self, provider: ShareReportProvider) -> Self {
        self.share_report_provider = Some(provider);
        self
    }

    /// Run the full FROST signing round across all configured participants and
    /// return the aggregated Schnorr signature (hex).
    ///
    // This path requires the manager to hold every key package. A custody-free
    // coordinator (constructed via [`Self::from_public_key_package`]) has none
    // and must fail closed here, directing callers to the separated round-trip.
    fn threshold_sign(&self, message: &[u8]) -> ConclaveResult<String> {
        if self.key_packages.is_empty() {
            return Err(ConclaveError::Unsupported(
                "custody-free threshold coordinator cannot sign in-process; use \
                 signing_package()/aggregate() with operators signing locally \
                 (Issue #726 F4)"
                    .to_string(),
            ));
        }
        let mut nonces = Vec::with_capacity(self.key_packages.len());
        let mut commitments = Vec::with_capacity(self.key_packages.len());
        for key_package in &self.key_packages {
            let (nonce, commitment) = self.signer.create_nonces(key_package)?;
            nonces.push(nonce);
            commitments.push(commitment);
        }
        let signing_package = self.signer.create_signing_package(message, &commitments)?;
        let mut shares = Vec::with_capacity(self.key_packages.len());
        for (i, key_package) in self.key_packages.iter().enumerate() {
            let share = self.signer.create_signature_share(
                key_package,
                &nonces[i],
                &signing_package,
                message,
            )?;
            shares.push(((i + 1) as u16, share));
        }
        self.signer
            .aggregate(&signing_package, &shares, &self.verifying_key_package)
    }

    /// Compose the per-share reports, aggregated key, and M-of-N threshold into
    /// a single threshold `DeviceIntegrityReport`, and return the value-bearing
    /// `SignResponse`.
    fn compose_value_bearing_response(
        &self,
        request: &ValueBearingSignRequest,
        share_reports: Vec<DeviceIntegrityReport>,
    ) -> ConclaveResult<SignResponse> {
        let signature_hex = self.threshold_sign(request.message_digest())?;
        let public_key = hex::decode(&self.aggregated_public_key_hex)
            .map_err(|_| ConclaveError::InvalidPayload)?;

        let signer_key_binding = SignerKeyBindingEvidence::new(
            request.key_binding().key_id(),
            request.key_binding().derivation_path(),
            request.key_binding().public_key(),
            &public_key,
            request.message_digest(),
            request.operation_context().purpose().canonical_token(),
            AttestationPurpose::Sign,
            request.algorithm().attestation_algorithm(),
        )?;

        let algorithm_token = request
            .algorithm()
            .attestation_algorithm()
            .canonical_token();
        let extension_data = format!("PURPOSE_SIGN|{algorithm_token}");
        let extensions =
            parse_extension_data(&extension_data).ok_or(ConclaveError::InvalidPayload)?;

        // Build participant/device distinctness evidence (finding F3, #744) and
        // refuse to compose a report that one device could have produced alone.
        let threshold_participants = Self::compose_participants(&share_reports, self.min_signers)?;

        let report = DeviceIntegrityReport {
            report_version: ATTESTATION_ENVELOPE_VERSION,
            report_type: crate::enclave::attestation::AttestationReportType::DeviceIntegrity,
            threshold_min_signers: Some(self.min_signers),
            threshold_shares: Some(share_reports),
            threshold_participants: Some(threshold_participants),
            level: AttestationLevel::Threshold,
            challenge_nonce: request.message_digest().to_vec(),
            signature: Vec::new(),
            attested_operation_public_key: public_key.clone(),
            signer_key_binding: Some(signer_key_binding),
            certificate_chain: Vec::new(),
            timestamp: crate::enclave::trusted_unix_time_secs()?,
            extension_data,
            extensions,
        };

        Ok(SignResponse {
            signature_hex,
            public_key_hex: self.aggregated_public_key_hex.clone(),
            device_attestation: Some(
                serde_json::to_string(&report).map_err(|_| ConclaveError::InvalidPayload)?,
            ),
        })
    }

    /// Derive the participant list from the per-share reports and enforce that
    /// each share is backed by a distinct device leaf key. Participant ids are
    /// the ceremony identifiers (`1..=n`, matching the key-package order used by
    /// [`Self::threshold_sign`]); each participant's `device_public_key` is the
    /// leaf key that signed its share report, which the verifier re-checks
    /// against the signed report. A cloned share (same leaf) is rejected here.
    fn compose_participants(
        share_reports: &[DeviceIntegrityReport],
        min_signers: u16,
    ) -> ConclaveResult<Vec<ThresholdParticipantEvidence>> {
        let mut participants = Vec::with_capacity(share_reports.len());
        let mut seen_device_keys = std::collections::BTreeSet::new();
        for (index, share) in share_reports.iter().enumerate() {
            let leaf = share
                .certificate_chain
                .first()
                .and_then(|entry| hex::decode(entry).ok())
                .filter(|key| !key.is_empty())
                .ok_or(ConclaveError::InvalidPayload)?;
            if !seen_device_keys.insert(leaf.clone()) {
                return Err(ConclaveError::Unsupported(
                    "threshold composition shares a device key across participants \
                     (finding F3, #744)"
                        .to_string(),
                ));
            }
            let participant_id = (index + 1) as u16;
            participants.push(ThresholdParticipantEvidence::new(participant_id, &leaf)?);
        }
        if (participants.len() as u16) < min_signers {
            return Err(ConclaveError::Unsupported(
                "threshold composition has fewer distinct devices than the threshold".to_string(),
            ));
        }
        Ok(participants)
    }
}

impl EnclaveManager for ThresholdEnclaveManager {
    fn initialize(&self) -> ConclaveResult<()> {
        Ok(())
    }

    fn generate_key(&self, key_id: &str) -> ConclaveResult<String> {
        Ok(key_id.to_string())
    }

    fn get_public_key(&self, _derivation_path: &str) -> ConclaveResult<String> {
        Ok(self.aggregated_public_key_hex.clone())
    }

    fn sign(&self, request: SignRequest) -> ConclaveResult<SignResponse> {
        let signature_hex = self.threshold_sign(&request.message_hash)?;
        Ok(SignResponse {
            signature_hex,
            public_key_hex: self.aggregated_public_key_hex.clone(),
            device_attestation: None,
        })
    }

    fn signer_capability(&self) -> SignerCapability {
        SignerCapability::provider_verified(VALUE_BEARING_POLICY_ID)
            .expect("value-bearing policy id must be a valid identifier")
    }

    fn sign_value_bearing_provider(
        &self,
        request: &ValueBearingSignRequest,
    ) -> ConclaveResult<SignResponse> {
        let provider = self.share_report_provider.as_ref().ok_or_else(|| {
            ConclaveError::Unsupported(
                "threshold value-bearing signing requires a share-report provider".to_string(),
            )
        })?;
        let share_reports = provider(request)?;
        self.compose_value_bearing_response(request, share_reports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::SigningAlgorithm;
    use crate::signing::threshold::FrostThresholdSigner;
    use std::collections::BTreeMap;

    #[allow(deprecated)]
    fn build_manager() -> ThresholdEnclaveManager {
        let (key_packages, verifying_key_package) =
            crate::protocol::frost_crypto::trusted_dealer_keygen(2, 3)
                .expect("trusted-dealer keygen should succeed");
        ThresholdEnclaveManager::new(
            Box::new(FrostThresholdSigner::new()),
            key_packages,
            verifying_key_package,
            2,
        )
        .expect("threshold manager should construct")
    }

    #[test]
    fn threshold_manager_constructs_and_reports_key() {
        let manager = build_manager();
        assert_eq!(manager.min_signers(), 2);
        assert_eq!(manager.max_signers(), 3);
        // x-only public key is 32 bytes = 64 hex chars
        assert_eq!(manager.aggregated_public_key_hex().len(), 64);
        assert_eq!(
            manager.get_public_key("m/0").unwrap(),
            manager.aggregated_public_key_hex()
        );
    }

    #[test]
    fn threshold_manager_signs_schnorr_signature() {
        let manager = build_manager();
        let request = SignRequest {
            algorithm: SigningAlgorithm::SchnorrSecp256k1,
            message_hash: [0x42u8; 32].to_vec(),
            derivation_path: "m/0".to_string(),
            key_id: "threshold-key".to_string(),
            taproot_tweak: None,
        };
        let response = manager
            .sign(request)
            .expect("threshold sign should succeed");
        // Schnorr signature is 64 bytes = 128 hex chars
        assert_eq!(response.signature_hex.len(), 128);
        assert_eq!(response.public_key_hex.len(), 64);
        assert!(response.device_attestation.is_none());
    }

    #[test]
    fn threshold_manager_is_send_sync() {
        fn _assert(_m: impl Send + Sync) {}
        _assert(build_manager());
    }

    fn strongbox_share_report_for_device(
        device_slot: u8,
        nonce: &[u8; 32],
    ) -> DeviceIntegrityReport {
        let signing_key = crate::enclave::attestation::test_device_signing_key(device_slot);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let extension_data =
            "PURPOSE_SIGN|ALGORITHM_SCHNORR_SECP256K1|HARDWARE_BACKED|SECURE_BOOT_ENABLED"
                .to_string();
        let extensions = parse_extension_data(&extension_data).unwrap();
        let mut report = DeviceIntegrityReport {
            report_version: ATTESTATION_ENVELOPE_VERSION,
            report_type: crate::enclave::attestation::AttestationReportType::DeviceIntegrity,
            threshold_min_signers: None,
            threshold_shares: None,
            threshold_participants: None,
            level: AttestationLevel::StrongBox,
            challenge_nonce: nonce.to_vec(),
            signature: Vec::new(),
            attested_operation_public_key: vec![0x11; 32],
            signer_key_binding: None,
            certificate_chain: vec![pubkey_hex, "CONCLAVE_ROOT_CA_V1".to_string()],
            timestamp: crate::enclave::trusted_unix_time_secs().unwrap(),
            extension_data,
            extensions,
        };
        report.sign_with_ed25519_key(&signing_key).unwrap();
        report
    }

    #[test]
    fn threshold_provider_composes_value_bearing_attestation() {
        use crate::enclave::{
            OperationContext, SignerKeyBinding, TrustRequirement, ValueBearingPurpose,
            ValueBearingSignResponse,
        };

        let manager = build_manager();
        let aggregated_public_key = hex::decode(manager.aggregated_public_key_hex()).unwrap();

        let operation_context = OperationContext::new(
            "conxian.test/threshold",
            ValueBearingPurpose::Transaction,
            b"op-context".to_vec(),
        )
        .unwrap();
        let trust_requirement = TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID).unwrap();
        let key_binding =
            SignerKeyBinding::new("threshold-key", "m/86'/0'/0'/0/0", aggregated_public_key)
                .unwrap();
        let request = ValueBearingSignRequest::new(
            operation_context,
            SigningAlgorithm::SchnorrSecp256k1,
            trust_requirement,
            [7u8; 32],
            key_binding,
            None,
        )
        .unwrap();

        let manager =
            manager.with_share_report_provider(Arc::new(|req: &ValueBearingSignRequest| {
                let reports = (1..=3u8)
                    .map(|slot| strongbox_share_report_for_device(slot, req.message_digest()))
                    .collect();
                Ok(reports)
            }));

        let response = manager
            .sign_value_bearing_provider(&request)
            .expect("threshold value-bearing sign should succeed");
        let now_secs = crate::enclave::trusted_unix_time_secs().unwrap();
        let verified = ValueBearingSignResponse::from_provider_at_time(
            &request,
            response,
            manager.signer_capability(),
            now_secs,
        );
        assert!(
            verified.is_ok(),
            "threshold value-bearing attestation failed: {verified:?}"
        );
    }

    #[test]
    fn threshold_composition_rejects_cloned_reports_from_one_device() {
        // Issue #726 finding F3 fix (#744): the composite report now carries a
        // participant list and binds each share to a distinct device key, so
        // three byte-identical reports signed by one device key can no longer
        // satisfy 2-of-3. Composition fails closed instead of producing a
        // report that verifies.
        use crate::enclave::{
            OperationContext, SignerKeyBinding, TrustRequirement, ValueBearingPurpose,
        };

        let manager = build_manager();
        let aggregated_public_key = hex::decode(manager.aggregated_public_key_hex()).unwrap();
        let operation_context = OperationContext::new(
            "conxian.test/threshold-clone",
            ValueBearingPurpose::Transaction,
            b"clone-context".to_vec(),
        )
        .unwrap();
        let trust_requirement = TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID).unwrap();
        let key_binding =
            SignerKeyBinding::new("threshold-key", "m/86'/0'/0'/0/0", aggregated_public_key)
                .unwrap();
        let request = ValueBearingSignRequest::new(
            operation_context,
            SigningAlgorithm::SchnorrSecp256k1,
            trust_requirement,
            [7u8; 32],
            key_binding,
            None,
        )
        .unwrap();

        // Every "operator" report comes from the same simulated device key.
        let manager =
            manager.with_share_report_provider(Arc::new(|req: &ValueBearingSignRequest| {
                Ok((0..3)
                    .map(|_| strongbox_share_report_for_device(1, req.message_digest()))
                    .collect())
            }));

        let result = manager.sign_value_bearing_provider(&request);
        assert!(
            result.is_err(),
            "one-device cloned reports must not compose, got: {result:?}"
        );
    }

    /// Delegates to `FrostThresholdSigner` but simulates one operator being
    /// unreachable during a signing round.
    struct OneOfflineSigner {
        offline_key_package: Vec<u8>,
    }

    impl OneOfflineSigner {
        fn is_offline(&self, key_package: &[u8]) -> bool {
            key_package == self.offline_key_package
        }
    }

    impl ThresholdSigner for OneOfflineSigner {
        fn dkg_round1(
            &self,
            participant_id: &[u8],
            max_signers: u16,
            min_signers: u16,
        ) -> ConclaveResult<(Vec<u8>, Vec<u8>)> {
            FrostThresholdSigner::new().dkg_round1(participant_id, max_signers, min_signers)
        }

        fn dkg_round2(
            &self,
            secret_bytes: &[u8],
            round1_packages: &BTreeMap<Vec<u8>, Vec<u8>>,
        ) -> ConclaveResult<(Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>)> {
            FrostThresholdSigner::new().dkg_round2(secret_bytes, round1_packages)
        }

        fn dkg_round3(
            &self,
            round2_secret_bytes: &[u8],
            round1_packages: &BTreeMap<Vec<u8>, Vec<u8>>,
            round2_packages: &BTreeMap<Vec<u8>, Vec<u8>>,
        ) -> ConclaveResult<(Vec<u8>, Vec<u8>)> {
            FrostThresholdSigner::new().dkg_round3(
                round2_secret_bytes,
                round1_packages,
                round2_packages,
            )
        }

        fn create_nonces(&self, key_package: &[u8]) -> ConclaveResult<(Vec<u8>, Vec<u8>)> {
            if self.is_offline(key_package) {
                return Err(ConclaveError::Unsupported("operator offline".to_string()));
            }
            FrostThresholdSigner::new().create_nonces(key_package)
        }

        fn create_signing_package(
            &self,
            message: &[u8],
            commitments: &[Vec<u8>],
        ) -> ConclaveResult<Vec<u8>> {
            FrostThresholdSigner::new().create_signing_package(message, commitments)
        }

        fn create_signature_share(
            &self,
            key_package: &[u8],
            nonces: &[u8],
            signing_package: &[u8],
            message: &[u8],
        ) -> ConclaveResult<Vec<u8>> {
            FrostThresholdSigner::new().create_signature_share(
                key_package,
                nonces,
                signing_package,
                message,
            )
        }

        fn aggregate(
            &self,
            signing_package: &[u8],
            shares: &[(u16, Vec<u8>)],
            verifying_key: &[u8],
        ) -> ConclaveResult<String> {
            FrostThresholdSigner::new().aggregate(signing_package, shares, verifying_key)
        }
    }

    #[test]
    fn custody_free_coordinator_signs_with_subset_and_holds_no_shares() {
        // Issue #726 F4 fix (#745): the coordinator holds only the public key
        // package; operators sign locally; any 2-of-3 subset produces a valid
        // signature and one offline operator does not halt signing.
        use crate::enclave::separated::ThresholdOperator;
        let (key_packages, verifying_key_package) =
            crate::protocol::frost_crypto::trusted_dealer_keygen(2, 3).unwrap();
        let coordinator = ThresholdEnclaveManager::from_public_key_package(
            Box::new(FrostThresholdSigner::new()),
            verifying_key_package,
            2,
            3,
        )
        .expect("custody-free coordinator should construct");
        assert!(!coordinator.holds_secret_shares());
        assert_eq!(coordinator.min_signers(), 2);
        assert_eq!(coordinator.max_signers(), 3);

        // In-process signing must fail closed: the coordinator has no shares.
        let request = SignRequest {
            algorithm: SigningAlgorithm::SchnorrSecp256k1,
            message_hash: [0x42u8; 32].to_vec(),
            derivation_path: "m/0".to_string(),
            key_id: "threshold-key".to_string(),
            taproot_tweak: None,
        };
        let err = coordinator
            .sign(request)
            .expect_err("custody-free coordinator must not sign in-process");
        assert!(format!("{err:?}").contains("custody-free"), "{err:?}");

        // Sign with subset {1,3}: operator 2 is offline, yet signing succeeds.
        let message = [0x5Au8; 32];
        let mut op1 = ThresholdOperator::from_key_package(1, key_packages[0].clone()).unwrap();
        let mut op3 = ThresholdOperator::from_key_package(3, key_packages[2].clone()).unwrap();
        let (_, c1) = op1.commit().unwrap();
        let (_, c3) = op3.commit().unwrap();
        let signing_package = coordinator
            .signing_package(&message, &[(1, c1), (3, c3)])
            .unwrap();
        let s1 = op1.sign(&signing_package).unwrap();
        let s3 = op3.sign(&signing_package).unwrap();
        let signature = coordinator
            .aggregate(&signing_package, &[(1, s1), (3, s3)])
            .expect("2 of 3 signers must produce a signature");
        assert_eq!(signature.len(), 128);
    }

    #[test]
    #[allow(deprecated)]
    fn threshold_signing_halts_when_any_operator_is_offline() {
        // Historical characterisation of the pre-F4 `threshold_sign` path, which
        // drives every stored key package (no M-of-N subset selection) and so
        // halts when any operator is offline. Retained to document why that
        // custody model is deprecated in favour of the separated flow above.
        let (key_packages, verifying_key_package) =
            crate::protocol::frost_crypto::trusted_dealer_keygen(2, 3).unwrap();
        let offline = key_packages[2].clone();
        let manager = ThresholdEnclaveManager::new(
            Box::new(OneOfflineSigner {
                offline_key_package: offline,
            }),
            key_packages,
            verifying_key_package,
            2,
        )
        .expect("threshold manager should construct");
        assert_eq!(manager.min_signers(), 2);
        assert_eq!(manager.max_signers(), 3);

        let request = SignRequest {
            algorithm: SigningAlgorithm::SchnorrSecp256k1,
            message_hash: [0x42u8; 32].to_vec(),
            derivation_path: "m/0".to_string(),
            key_id: "threshold-key".to_string(),
            taproot_tweak: None,
        };
        let err = manager
            .sign(request)
            .expect_err("legacy all-shares path halts when one operator is offline");
        assert!(
            format!("{err:?}").contains("operator offline"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn value_bearing_response_replays_across_operation_contexts() {
        // Issue #726 finding F6: `SignerKeyBindingEvidence` hashes the key id,
        // derivation path, public keys, operation digest, purpose token,
        // attestation purpose, and algorithm - but not the `OperationContext`
        // domain or context payload. The challenge nonce is just the message
        // digest. A provider response captured for one operation context
        // therefore verifies verbatim against a different request whose domain
        // and context payload differ while the digest is unchanged.
        use crate::enclave::{
            OperationContext, SignerKeyBinding, TrustRequirement, ValueBearingPurpose,
            ValueBearingSignResponse,
        };

        let manager = build_manager();
        let aggregated_public_key = hex::decode(manager.aggregated_public_key_hex()).unwrap();
        let key_binding = || {
            SignerKeyBinding::new(
                "threshold-key",
                "m/86'/0'/0'/0/0",
                aggregated_public_key.clone(),
            )
            .unwrap()
        };
        let request_for = |domain: &str, payload: &[u8]| {
            ValueBearingSignRequest::new(
                OperationContext::new(domain, ValueBearingPurpose::Transaction, payload.to_vec())
                    .unwrap(),
                SigningAlgorithm::SchnorrSecp256k1,
                TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID).unwrap(),
                [7u8; 32],
                key_binding(),
                None,
            )
            .unwrap()
        };

        let manager =
            manager.with_share_report_provider(Arc::new(|req: &ValueBearingSignRequest| {
                Ok((1..=3u8)
                    .map(|slot| strongbox_share_report_for_device(slot, req.message_digest()))
                    .collect())
            }));

        let request_a = request_for(
            "conxian.test/threshold-payments",
            b"op-context-a".as_slice(),
        );
        let request_b = request_for(
            "conxian.test/threshold-settlement",
            b"op-context-b".as_slice(),
        );

        let response_for_a = manager
            .sign_value_bearing_provider(&request_a)
            .expect("provider signing should succeed");

        let now_secs = crate::enclave::trusted_unix_time_secs().unwrap();
        let replayed = ValueBearingSignResponse::from_provider_at_time(
            &request_b,
            response_for_a,
            manager.signer_capability(),
            now_secs,
        );
        assert!(
            replayed.is_ok(),
            "F6: response captured for context A was expected to replay into context B: {replayed:?}"
        );
    }
}
