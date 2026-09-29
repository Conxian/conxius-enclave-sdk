//! Threshold enclave manager (Phase 2).
//!
//! Wires the FROST/MuSig2 threshold signer (`crate::signing::threshold`) into
//! the `EnclaveManager` provider contract. It aggregates participant signature
//! shares into a single Schnorr signature and composes per-share TEE
//! attestations into a single threshold `DeviceIntegrityReport` for the
//! value-bearing signing path.

use crate::enclave::attestation::{
    parse_extension_data, AttestationLevel, AttestationPurpose, DeviceIntegrityReport,
    SignerKeyBindingEvidence, ATTESTATION_ENVELOPE_VERSION,
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
    /// Construct a threshold manager from an existing key-package set (already
    /// distributed by the DKG ceremony). `verifying_key_package` is the
    /// serialized FROST `PublicKeyPackage`; the aggregated x-only public key is
    /// derived from it.
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

    /// Attach the per-share attestation source used by value-bearing signing.
    pub fn with_share_report_provider(mut self, provider: ShareReportProvider) -> Self {
        self.share_report_provider = Some(provider);
        self
    }

    /// Run the full FROST signing round across all configured participants and
    /// return the aggregated Schnorr signature (hex).
    fn threshold_sign(&self, message: &[u8]) -> ConclaveResult<String> {
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

        let report = DeviceIntegrityReport {
            report_version: ATTESTATION_ENVELOPE_VERSION,
            report_type: crate::enclave::attestation::AttestationReportType::DeviceIntegrity,
            threshold_min_signers: Some(self.min_signers),
            threshold_shares: Some(share_reports),
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

    fn strongbox_share_report(nonce: &[u8; 32]) -> DeviceIntegrityReport {
        let signing_key = crate::enclave::attestation::test_signing_key();
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
                let reports = (0..3)
                    .map(|_| strongbox_share_report(req.message_digest()))
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
}
