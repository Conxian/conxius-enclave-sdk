use crate::enclave::attestation::{
    parse_extension_data, AttestationLevel, AttestationReportType, DeviceIntegrityReport,
    ATTESTATION_ENVELOPE_VERSION,
};
use crate::{
    enclave::{
        EnclaveManager, SignRequest, SignResponse, SignerCapability, SigningAlgorithm,
        ValueBearingSession, ValueBearingSignRequest, ValueBearingSignResponse,
        ValueBearingUnlockRequest,
    },
    ConclaveError, ConclaveResult,
};
use ed25519_dalek::{Signer as _, SigningKey};
use rand::Rng;
use secp256k1::{Message, SecretKey};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

const SIMULATED_KMS_KEYGEN_MAX_ATTEMPTS: usize = 1024;

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Development-only software simulation.
///
/// `kms_endpoint` is retained for compatibility and configuration-shape tests;
/// this type never contacts a provider KMS and must not be used for
/// value-bearing signing.
pub struct CloudEnclave {
    pub kms_endpoint: String,
    local_dev_key_bytes: Option<Zeroizing<[u8; 32]>>,
    software_simulated_kms_key_bytes: Zeroizing<[u8; 32]>,
}

impl CloudEnclave {
    fn new_inner(kms_endpoint: String) -> ConclaveResult<Self> {
        let software_simulated_kms_key_bytes = Self::generate_simulated_kms_key_bytes()?;
        Ok(Self {
            kms_endpoint,
            local_dev_key_bytes: None,
            software_simulated_kms_key_bytes,
        })
    }

    /// This manager is permanently software-backed and development-only.
    pub const SOFTWARE_ONLY: bool = true;

    pub const fn is_software_only() -> bool {
        Self::SOFTWARE_ONLY
    }

    /// Constructs the software-backed fixture used by this crate's unit tests.
    #[cfg(test)]
    pub fn new(kms_endpoint: String) -> ConclaveResult<Self> {
        Self::new_inner(kms_endpoint)
    }

    /// Constructs an explicitly development-only software simulator.
    #[cfg(all(not(test), feature = "development-simulators"))]
    pub fn new_for_development(kms_endpoint: String) -> ConclaveResult<Self> {
        Self::new_inner(kms_endpoint)
    }

    pub fn with_dev_key(mut self, key_bytes: [u8; 32]) -> ConclaveResult<Self> {
        let dev_key_bytes = Zeroizing::new(key_bytes);
        self.local_dev_key_bytes = Some(dev_key_bytes);
        Ok(self)
    }

    fn generate_simulated_kms_key_bytes() -> ConclaveResult<Zeroizing<[u8; 32]>> {
        let mut rng = rand::rng();
        let mut key_bytes = Zeroizing::new([0u8; 32]);

        for _ in 0..SIMULATED_KMS_KEYGEN_MAX_ATTEMPTS {
            rng.fill_bytes(&mut *key_bytes);
            if Self::is_valid_secret_key_bytes(&key_bytes) {
                return Ok(key_bytes);
            }
        }

        Err(ConclaveError::CryptoError(
            "Failed to generate simulated KMS secret key".to_string(),
        ))
    }

    fn is_valid_secret_key_bytes(key_bytes: &[u8; 32]) -> bool {
        let ok = unsafe {
            secp256k1::ffi::secp256k1_ec_seckey_verify(
                secp256k1::ffi::secp256k1_context_no_precomp,
                key_bytes.as_ptr(),
            )
        };
        ok == 1
    }

    fn get_active_key_bytes(&self) -> &[u8; 32] {
        match self.local_dev_key_bytes.as_ref() {
            Some(key_bytes) => key_bytes,
            None => &self.software_simulated_kms_key_bytes,
        }
    }

    fn get_active_secp_key(&self) -> ConclaveResult<SecretKey> {
        SecretKey::from_secret_bytes(*self.get_active_key_bytes())
            .map_err(|e| ConclaveError::CryptoError(format!("SEC1 Error: {e}")))
    }
    // Test builds use a deterministic fixture; development-simulator builds
    // emit explicitly software-only evidence. Neither path is production
    // provider attestation.
    fn generate_attestation_report(
        &self,
        challenge: &[u8],
        algorithm: &SigningAlgorithm,
        operation_public_key: &[u8],
    ) -> ConclaveResult<DeviceIntegrityReport> {
        let timestamp = unix_time_secs();
        let algorithm_token = match algorithm {
            SigningAlgorithm::EcdsaSecp256k1 => "ALGORITHM_ECDSA_SECP256K1",
            SigningAlgorithm::SchnorrSecp256k1 => "ALGORITHM_SCHNORR_SECP256K1",
            SigningAlgorithm::Ed25519 => "ALGORITHM_ED25519",
        };

        #[cfg(test)]
        let (signing_key, level, certificate_chain, extension_data) = {
            let signing_key = crate::enclave::attestation::test_signing_key();
            let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
            (
                signing_key,
                AttestationLevel::TEE,
                vec![pubkey_hex, "CONCLAVE_ROOT_CA_V1".to_string()],
                format!(
                    "PURPOSE_SIGN|{algorithm_token}|TEE_ENABLED|HARDWARE_ROOT_OF_TRUST|OS_VERSION_14"
                ),
            )
        };

        #[cfg(not(test))]
        let (signing_key, level, certificate_chain, extension_data) = {
            let key_bytes = self.get_active_key_bytes();
            let signing_key = SigningKey::from_bytes(key_bytes);
            let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
            (
                signing_key,
                AttestationLevel::Software,
                vec![pubkey_hex],
                format!("SIMULATED_SOFTWARE_ONLY|PURPOSE_SIGN|{algorithm_token}|PLATFORM_CLOUD"),
            )
        };

        let extensions = parse_extension_data(&extension_data).ok_or_else(|| {
            ConclaveError::CryptoError("Invalid simulated attestation extensions".to_string())
        })?;

        let mut report = DeviceIntegrityReport {
            report_version: ATTESTATION_ENVELOPE_VERSION,
            report_type: AttestationReportType::DeviceIntegrity,
            level,
            challenge_nonce: challenge.to_vec(),
            signature: Vec::new(),
            attested_operation_public_key: operation_public_key.to_vec(),
            certificate_chain,
            timestamp,
            extension_data,
            extensions,
        };
        report.sign_with_ed25519_key(&signing_key)?;
        Ok(report)
    }
}

impl EnclaveManager for CloudEnclave {
    fn initialize(&self) -> ConclaveResult<()> {
        if self.kms_endpoint.is_empty() {
            return Err(ConclaveError::EnclaveFailure(
                "KMS endpoint not configured".to_string(),
            ));
        }
        Ok(())
    }

    fn signer_capability(&self) -> SignerCapability {
        SignerCapability::software_unverified()
    }

    fn generate_key(&self, key_id: &str) -> ConclaveResult<String> {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let key_handle = format!("cloud_key_{}_{}", key_id, hex::encode(&seed[..4]));
        seed.zeroize();
        Ok(key_handle)
    }

    fn get_public_key(&self, _derivation_path: &str) -> ConclaveResult<String> {
        let secret_key = self.get_active_secp_key()?;
        let public_key = secret_key.public_key();
        Ok(hex::encode(public_key.serialize()))
    }

    fn sign(&self, request: SignRequest) -> ConclaveResult<SignResponse> {
        let public_key_hex: String;
        let signature_hex: String;

        match request.algorithm {
            SigningAlgorithm::EcdsaSecp256k1 => {
                let secret_key = self.get_active_secp_key()?;
                let public_key = secret_key.public_key();
                public_key_hex = hex::encode(public_key.serialize());
                let message_bytes: [u8; 32] = request
                    .message_hash
                    .clone()
                    .try_into()
                    .map_err(|_| ConclaveError::InvalidPayload)?;
                let message = Message::from_digest(message_bytes);
                let sig = secp256k1::ecdsa::sign(message, &secret_key);
                signature_hex = hex::encode(sig.serialize_compact());
            }
            SigningAlgorithm::SchnorrSecp256k1 => {
                return Err(ConclaveError::Unsupported(
                    "Schnorr signing is unavailable in the software-only cloud simulation"
                        .to_string(),
                ));
            }
            SigningAlgorithm::Ed25519 => {
                let key_bytes = self.get_active_key_bytes();
                let signing_key = SigningKey::from_bytes(key_bytes);
                public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
                let sig = signing_key.sign(&request.message_hash);
                signature_hex = hex::encode(sig.to_bytes());
            }
        };

        let operation_public_key = hex::decode(&public_key_hex)
            .map_err(|_| ConclaveError::CryptoError("Invalid operation public key".to_string()))?;
        let attestation = self.generate_attestation_report(
            &request.message_hash,
            &request.algorithm,
            &operation_public_key,
        )?;
        let attestation_json = serde_json::to_string(&attestation)
            .map_err(|e| ConclaveError::CryptoError(format!("Serialization error: {}", e)))?;

        Ok(SignResponse {
            signature_hex,
            public_key_hex,
            device_attestation: Some(attestation_json),
        })
    }

    fn unlock_value_bearing(
        &self,
        _request: ValueBearingUnlockRequest,
    ) -> ConclaveResult<ValueBearingSession> {
        Err(ConclaveError::Unsupported(
            "CloudEnclave is software-only and cannot unlock value-bearing operations".to_string(),
        ))
    }

    fn sign_value_bearing(
        &self,
        _request: ValueBearingSignRequest,
    ) -> ConclaveResult<ValueBearingSignResponse> {
        Err(ConclaveError::Unsupported(
            "CloudEnclave is software-only and cannot sign value-bearing operations".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::{
        attestation::AttestationPolicy, EnclaveManager, SignRequest, SigningAlgorithm,
    };
    use ed25519_dalek::{Signature as Ed25519Signature, Verifier as _, VerifyingKey};

    fn enclave() -> CloudEnclave {
        CloudEnclave::new("https://kms.test".to_string())
            .unwrap()
            .with_dev_key([7u8; 32])
            .unwrap()
    }

    fn request(algorithm: SigningAlgorithm, message_hash: Vec<u8>) -> SignRequest {
        SignRequest {
            algorithm,
            message_hash,
            derivation_path: "m/44'/0'/0'".to_string(),
            key_id: "test-key".to_string(),
            taproot_tweak: None,
        }
    }

    #[test]
    fn cloud_ecdsa_signature_is_verifiable_and_nonzero() {
        let message = [1u8; 32];
        let response = enclave()
            .sign(request(SigningAlgorithm::EcdsaSecp256k1, message.to_vec()))
            .unwrap();
        let signature_bytes = hex::decode(response.signature_hex).unwrap();
        let public_key =
            secp256k1::PublicKey::from_slice(&hex::decode(response.public_key_hex).unwrap())
                .unwrap();
        let signature = secp256k1::ecdsa::Signature::from_compact(&signature_bytes).unwrap();
        assert!(signature_bytes.iter().any(|byte| *byte != 0));
        assert!(
            secp256k1::ecdsa::verify(&signature, Message::from_digest(message), &public_key)
                .is_ok()
        );
    }

    #[test]
    fn cloud_schnorr_signing_is_explicitly_unsupported() {
        let message = [0x31u8; 32];
        let result = enclave().sign(request(
            SigningAlgorithm::SchnorrSecp256k1,
            message.to_vec(),
        ));

        assert!(matches!(
            result,
            Err(ConclaveError::Unsupported(message))
                if message.contains("Schnorr")
        ));
    }

    #[test]
    fn cloud_ed25519_signature_is_verifiable_and_nonzero() {
        let message = b"cloud ed25519 message";
        let response = enclave()
            .sign(request(SigningAlgorithm::Ed25519, message.to_vec()))
            .unwrap();
        let signature_bytes = hex::decode(response.signature_hex).unwrap();
        let public_key_bytes: [u8; 32] = hex::decode(response.public_key_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();
        let signature = Ed25519Signature::from_slice(&signature_bytes).unwrap();

        assert!(signature_bytes.iter().any(|byte| *byte != 0));
        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn cloud_test_fixture_attestation_is_not_production_evidence() {
        let message = b"software cloud simulation";
        let response = enclave()
            .sign(request(SigningAlgorithm::Ed25519, message.to_vec()))
            .unwrap();
        let attestation = response.device_attestation.unwrap();
        let report: DeviceIntegrityReport = serde_json::from_str(&attestation).unwrap();

        assert_eq!(report.level, AttestationLevel::TEE);
        assert!(!report.verify_with_policy(message, &AttestationPolicy::production()));
    }
}
