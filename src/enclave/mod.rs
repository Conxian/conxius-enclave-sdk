#[cfg(any(test, feature = "development-simulators"))]
pub mod android_strongbox;
pub mod attestation;
#[cfg(any(test, feature = "development-simulators"))]
pub mod cloud;
pub mod replay_guard;

#[cfg(test)]
mod hardware_attestation_tests;

use crate::enclave::attestation::{
    AttestationAlgorithm, AttestationExtension, AttestationPolicy, AttestationPurpose,
    DeviceIntegrityReport,
};
use crate::{ConclaveError, ConclaveResult};
use ed25519_dalek::Verifier as _;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SigningAlgorithm {
    EcdsaSecp256k1,
    SchnorrSecp256k1,
    Ed25519,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub algorithm: SigningAlgorithm,
    pub message_hash: Vec<u8>,
    pub derivation_path: String,
    pub key_id: String,
    pub taproot_tweak: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    pub signature_hex: String,
    pub public_key_hex: String,
    pub device_attestation: Option<String>,
}

/// Typed request used by every value-bearing signing surface.
///
/// The low-level [`EnclaveManager::sign`] request remains available to enclave
/// implementations and explicitly isolated development/test fixtures. Protocol
/// code must use this envelope so the exact digest, signing purpose, algorithm,
/// derivation path, key identity, and expected public key are checked together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueBearingSignRequest {
    pub operation_digest: [u8; 32],
    pub purpose: AttestationPurpose,
    pub algorithm: SigningAlgorithm,
    pub derivation_path: String,
    pub key_id: String,
    pub expected_public_key_hex: String,
    pub taproot_tweak: Option<Vec<u8>>,
}

impl ValueBearingSignRequest {
    pub fn new(
        operation_digest: [u8; 32],
        algorithm: SigningAlgorithm,
        derivation_path: String,
        key_id: String,
        expected_public_key_hex: String,
        taproot_tweak: Option<Vec<u8>>,
    ) -> Self {
        Self {
            operation_digest,
            purpose: AttestationPurpose::Sign,
            algorithm,
            derivation_path,
            key_id,
            expected_public_key_hex,
            taproot_tweak,
        }
    }

    fn low_level_request(&self) -> SignRequest {
        SignRequest {
            algorithm: self.algorithm,
            message_hash: self.operation_digest.to_vec(),
            derivation_path: self.derivation_path.clone(),
            key_id: self.key_id.clone(),
            taproot_tweak: self.taproot_tweak.clone(),
        }
    }
}

pub trait EnclaveManager: Send + Sync {
    fn initialize(&self) -> ConclaveResult<()>;
    fn unlock(&self, _secret: &str, _salt: &[u8]) -> ConclaveResult<()> {
        Err(ConclaveError::Unsupported(
            "an explicit enclave provider must implement unlock".to_string(),
        ))
    }
    fn generate_key(&self, key_id: &str) -> ConclaveResult<String>;
    fn get_public_key(&self, derivation_path: &str) -> ConclaveResult<String>;
    fn sign(&self, request: SignRequest) -> ConclaveResult<SignResponse>;
}

/// Production-safe placeholder used until an authenticated hardware provider
/// is configured. It never fabricates keys, signatures, or attestation data.
#[derive(Debug, Default)]
pub struct UnavailableEnclave;

impl EnclaveManager for UnavailableEnclave {
    fn initialize(&self) -> ConclaveResult<()> {
        Err(ConclaveError::Unsupported(
            "hardware-backed enclave provider is unavailable".to_string(),
        ))
    }

    fn generate_key(&self, _key_id: &str) -> ConclaveResult<String> {
        Err(ConclaveError::Unsupported(
            "hardware-backed key generation is unavailable".to_string(),
        ))
    }

    fn get_public_key(&self, _derivation_path: &str) -> ConclaveResult<String> {
        Err(ConclaveError::Unsupported(
            "hardware-backed public-key derivation is unavailable".to_string(),
        ))
    }

    fn sign(&self, _request: SignRequest) -> ConclaveResult<SignResponse> {
        Err(ConclaveError::Unsupported(
            "hardware-backed signing provider is unavailable".to_string(),
        ))
    }
}

/// Route a value-bearing operation through the common fail-closed boundary.
pub(crate) fn sign_value_bearing(
    enclave: &dyn EnclaveManager,
    request: ValueBearingSignRequest,
) -> ConclaveResult<SignResponse> {
    if request.purpose != AttestationPurpose::Sign {
        return Err(ConclaveError::Unsupported(
            "value-bearing signing requires the signing purpose".to_string(),
        ));
    }

    let response = enclave.sign(request.low_level_request())?;
    let policy = value_bearing_policy().with_required_algorithm(match request.algorithm {
        SigningAlgorithm::EcdsaSecp256k1 => AttestationAlgorithm::EcdsaSecp256k1,
        SigningAlgorithm::SchnorrSecp256k1 => AttestationAlgorithm::SchnorrSecp256k1,
        SigningAlgorithm::Ed25519 => AttestationAlgorithm::Ed25519,
    });
    validate_value_bearing_response(&request, &response, &policy)?;
    Ok(response)
}

fn value_bearing_policy() -> AttestationPolicy {
    #[cfg(test)]
    {
        AttestationPolicy::test_fixture()
    }

    #[cfg(not(test))]
    {
        AttestationPolicy::production()
    }
}

pub(crate) fn validate_value_bearing_response(
    request: &ValueBearingSignRequest,
    response: &SignResponse,
    policy: &AttestationPolicy,
) -> ConclaveResult<()> {
    if request.key_id.trim().is_empty() || request.expected_public_key_hex.trim().is_empty() {
        return Err(ConclaveError::InvalidPayload);
    }
    if response.signature_hex.is_empty() || response.public_key_hex.is_empty() {
        return Err(ConclaveError::EnclaveFailure(
            "value-bearing signer returned an incomplete signature".to_string(),
        ));
    }

    let expected_public_key =
        hex::decode(&request.expected_public_key_hex).map_err(|_| ConclaveError::InvalidPayload)?;
    let returned_public_key =
        hex::decode(&response.public_key_hex).map_err(|_| ConclaveError::InvalidPayload)?;
    if expected_public_key != returned_public_key {
        return Err(ConclaveError::EnclaveFailure(
            "value-bearing signer returned a public key that is not bound to the request"
                .to_string(),
        ));
    }

    let attestation_json = response.device_attestation.as_ref().ok_or_else(|| {
        ConclaveError::EnclaveFailure(
            "value-bearing signing requires device attestation".to_string(),
        )
    })?;
    let report: DeviceIntegrityReport = serde_json::from_str(attestation_json).map_err(|e| {
        ConclaveError::EnclaveFailure(format!("invalid value-bearing attestation: {e}"))
    })?;

    if report.challenge_nonce != request.operation_digest {
        return Err(ConclaveError::EnclaveFailure(
            "value-bearing attestation is not bound to the exact operation digest".to_string(),
        ));
    }

    let now_secs = unix_time_secs();
    if !report.verify_at_time_with_policy(&request.operation_digest, now_secs, policy) {
        return Err(ConclaveError::Unsupported(
            "value-bearing signing requires a verified hardware provider".to_string(),
        ));
    }

    let expected_algorithm_extension = match request.algorithm {
        SigningAlgorithm::EcdsaSecp256k1 => AttestationExtension::AlgorithmEcdsaSecp256k1,
        SigningAlgorithm::SchnorrSecp256k1 => AttestationExtension::AlgorithmSchnorrSecp256k1,
        SigningAlgorithm::Ed25519 => AttestationExtension::AlgorithmEd25519,
    };
    if !report
        .extensions
        .contains(&AttestationExtension::PurposeSign)
        || !report.extensions.contains(&expected_algorithm_extension)
    {
        return Err(ConclaveError::EnclaveFailure(
            "attestation purpose or algorithm does not match the signing request".to_string(),
        ));
    }

    verify_operation_signature(request, response)
}

fn verify_operation_signature(
    request: &ValueBearingSignRequest,
    response: &SignResponse,
) -> ConclaveResult<()> {
    let signature_bytes =
        hex::decode(&response.signature_hex).map_err(|_| ConclaveError::InvalidPayload)?;
    let public_key_bytes =
        hex::decode(&response.public_key_hex).map_err(|_| ConclaveError::InvalidPayload)?;

    let valid = match request.algorithm {
        SigningAlgorithm::EcdsaSecp256k1 => {
            if !(signature_bytes.len() == 64 || signature_bytes.len() == 65)
                || (signature_bytes.len() == 65 && signature_bytes[64] > 3)
            {
                false
            } else {
                let signature = secp256k1::ecdsa::Signature::from_compact(&signature_bytes[..64]);
                let public_key = secp256k1::PublicKey::from_slice(&public_key_bytes);
                match (signature, public_key) {
                    (Ok(signature), Ok(public_key)) => secp256k1::ecdsa::verify(
                        &signature,
                        secp256k1::Message::from_digest(request.operation_digest),
                        &public_key,
                    )
                    .is_ok(),
                    _ => false,
                }
            }
        }
        SigningAlgorithm::SchnorrSecp256k1 => {
            let signature_array: [u8; 64] = signature_bytes
                .try_into()
                .map_err(|_| ConclaveError::InvalidPayload)?;
            let public_key_array: [u8; 32] = public_key_bytes
                .try_into()
                .map_err(|_| ConclaveError::InvalidPayload)?;
            let signature = secp256k1::schnorr::Signature::from_byte_array(signature_array);
            let public_key = secp256k1::XOnlyPublicKey::from_byte_array(public_key_array)
                .map_err(|_| ConclaveError::InvalidPayload)?;
            secp256k1::schnorr::verify(&signature, &request.operation_digest, &public_key).is_ok()
        }
        SigningAlgorithm::Ed25519 => {
            let public_key_array: [u8; 32] = public_key_bytes
                .try_into()
                .map_err(|_| ConclaveError::InvalidPayload)?;
            let public_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_array)
                .map_err(|_| ConclaveError::InvalidPayload)?;
            let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
                .map_err(|_| ConclaveError::InvalidPayload)?;
            public_key
                .verify(&request.operation_digest, &signature)
                .is_ok()
        }
    };

    if valid {
        Ok(())
    } else {
        Err(ConclaveError::CryptoError(
            "value-bearing signature does not verify against its exact operation digest"
                .to_string(),
        ))
    }
}

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod enclave_tests {
    use super::*;
    use crate::enclave::android_strongbox::CoreEnclaveManager;
    use crate::enclave::cloud::CloudEnclave;

    #[test]
    fn test_cloud_enclave_ed25519_signing() {
        let enclave = CloudEnclave::new("https://kms.test".to_string()).unwrap();
        let message = b"hello world";
        let request = SignRequest {
            algorithm: SigningAlgorithm::Ed25519,
            message_hash: message.to_vec(),
            derivation_path: "m/44'/501'/0'/0'".to_string(),
            key_id: "test-key".to_string(),
            taproot_tweak: None,
        };

        let response = enclave.sign(request).unwrap();
        assert!(!response.signature_hex.is_empty());
        assert_eq!(response.public_key_hex.len(), 64); // 32 bytes hex
        assert!(response.device_attestation.is_some());
    }

    #[test]
    fn unavailable_enclave_fails_closed_for_all_operations() {
        let enclave = UnavailableEnclave;
        let request = SignRequest {
            algorithm: SigningAlgorithm::EcdsaSecp256k1,
            message_hash: vec![0; 32],
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            key_id: "key".to_string(),
            taproot_tweak: None,
        };

        assert!(enclave.initialize().is_err());
        assert!(enclave.unlock("secret", b"salt").is_err());
        assert!(enclave.generate_key("key").is_err());
        assert!(enclave.get_public_key("m/44'/0'/0'/0/0").is_err());
        assert!(enclave.sign(request).is_err());
    }

    #[test]
    fn production_value_signing_rejects_simulated_provider() {
        let enclave = CloudEnclave::new("https://kms.test".to_string()).unwrap();
        let digest = [0xA5; 32];
        let public_key = enclave.get_public_key("m/44'/0'/0'/0/0").unwrap();
        let request = ValueBearingSignRequest::new(
            digest,
            SigningAlgorithm::EcdsaSecp256k1,
            "m/44'/0'/0'/0/0".to_string(),
            "production-test-key".to_string(),
            public_key,
            None,
        );
        let result = validate_value_bearing_response(
            &request,
            &enclave.sign(request.low_level_request()).unwrap(),
            &AttestationPolicy::production(),
        );
        assert!(matches!(
            result,
            Err(ConclaveError::Unsupported(message))
                if message.contains("verified hardware provider")
        ));
    }

    #[test]
    fn production_value_signing_rejects_core_simulator() {
        let enclave = CoreEnclaveManager::new();
        enclave.unlock("test-pin", b"test-salt").unwrap();
        let derivation_path = "m/44'/0'/0'/0/0".to_string();
        let digest = [0x5A; 32];
        let public_key = enclave.get_public_key(&derivation_path).unwrap();
        let request = ValueBearingSignRequest::new(
            digest,
            SigningAlgorithm::EcdsaSecp256k1,
            derivation_path,
            "production-core-test-key".to_string(),
            public_key,
            None,
        );
        let result = validate_value_bearing_response(
            &request,
            &enclave.sign(request.low_level_request()).unwrap(),
            &AttestationPolicy::production(),
        );
        assert!(matches!(
            result,
            Err(ConclaveError::Unsupported(message))
                if message.contains("verified hardware provider")
        ));
    }
}
