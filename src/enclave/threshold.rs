//! Threshold enclave manager (Phase 2 step 1).
//!
//! Wires the FROST/MuSig2 threshold signer (`crate::signing::threshold`) into
//! the `EnclaveManager` provider contract. This is the *raw* signing scaffold:
//! it aggregates participant signature shares into a single Schnorr signature
//! but does **not** yet compose a value-bearing `DeviceIntegrityReport` (that
//! is step 3). Until then `sign_value_bearing_provider` fails closed.

use crate::enclave::{
    EnclaveManager, SignRequest, SignResponse, SignerCapability, ValueBearingSignRequest,
    VALUE_BEARING_POLICY_ID,
};
use crate::signing::threshold::ThresholdSigner;
use crate::{ConclaveError, ConclaveResult};

/// A threshold [`EnclaveManager`] that aggregates FROST/MuSig2 signature shares
/// across N independent hardware participants into a single Schnorr signature.
pub struct ThresholdEnclaveManager {
    signer: Box<dyn ThresholdSigner + Send + Sync>,
    key_packages: Vec<Vec<u8>>,
    verifying_key_package: Vec<u8>,
    aggregated_public_key_hex: String,
    min_signers: u16,
    max_signers: u16,
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
        _request: &ValueBearingSignRequest,
    ) -> ConclaveResult<SignResponse> {
        Err(ConclaveError::Unsupported(
            "threshold value-bearing attestation is not yet wired (Phase 2 step 3)".to_string(),
        ))
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
}
