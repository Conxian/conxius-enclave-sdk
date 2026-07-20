#[cfg(any(test, feature = "development-simulators"))]
pub mod android_strongbox;
pub mod attestation;
#[cfg(any(test, feature = "development-simulators"))]
pub mod cloud;
pub mod replay_guard;

#[cfg(test)]
mod hardware_attestation_tests;

use crate::enclave::attestation::{
    AttestationAlgorithm, AttestationExtension, AttestationPolicy, DeviceIntegrityReport,
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

/// A production-safe placeholder for a provider that has not been configured.
/// Every operation fails closed; it never fabricates keys, signatures, or
/// attestation evidence.
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

/// Signs a value-bearing operation through the common fail-closed boundary.
///
/// Raw `EnclaveManager::sign` remains available for explicitly isolated
/// development/test drivers, but every protocol wrapper that can produce a
/// transaction or settlement signature must use this helper. Production uses
/// the unavailable provider policy until a real provider verifier is wired in.
pub(crate) fn sign_value_bearing(
    enclave: &dyn EnclaveManager,
    request: SignRequest,
) -> ConclaveResult<SignResponse> {
    let response = enclave.sign(request.clone())?;
    let required_algorithm = match request.algorithm {
        SigningAlgorithm::EcdsaSecp256k1 => AttestationAlgorithm::EcdsaSecp256k1,
        SigningAlgorithm::SchnorrSecp256k1 => AttestationAlgorithm::SchnorrSecp256k1,
        SigningAlgorithm::Ed25519 => AttestationAlgorithm::Ed25519,
    };
    let policy = value_bearing_policy().with_required_algorithm(required_algorithm);
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
    request: &SignRequest,
    response: &SignResponse,
    policy: &AttestationPolicy,
) -> ConclaveResult<()> {
    if response.signature_hex.is_empty() || response.public_key_hex.is_empty() {
        return Err(ConclaveError::EnclaveFailure(
            "value-bearing signer returned an incomplete signature".to_string(),
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

    if report.challenge_nonce != request.message_hash {
        return Err(ConclaveError::EnclaveFailure(
            "value-bearing attestation is not bound to the signing request".to_string(),
        ));
    }

    if !report.verify_with_policy(&request.message_hash, policy) {
        return Err(ConclaveError::Unsupported(
            "value-bearing signing requires a verified hardware provider".to_string(),
        ));
    }

    let expected_algorithm_extension = match request.algorithm {
        SigningAlgorithm::EcdsaSecp256k1 => AttestationExtension::AlgorithmEcdsaSecp256k1,
        SigningAlgorithm::SchnorrSecp256k1 => AttestationExtension::AlgorithmSchnorrSecp256k1,
        SigningAlgorithm::Ed25519 => AttestationExtension::AlgorithmEd25519,
    };
    if !report.extensions.contains(&expected_algorithm_extension) {
        return Err(ConclaveError::EnclaveFailure(
            "attestation algorithm does not match the signing request".to_string(),
        ));
    }

    verify_operation_signature(request, response)
}

fn verify_operation_signature(
    request: &SignRequest,
    response: &SignResponse,
) -> ConclaveResult<()> {
    let signature_bytes = hex::decode(&response.signature_hex)
        .map_err(|_| ConclaveError::CryptoError("invalid signature encoding".to_string()))?;
    let public_key_bytes = hex::decode(&response.public_key_hex)
        .map_err(|_| ConclaveError::CryptoError("invalid public-key encoding".to_string()))?;

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
                        secp256k1::Message::from_digest(
                            request
                                .message_hash
                                .as_slice()
                                .try_into()
                                .map_err(|_| ConclaveError::InvalidPayload)?,
                        ),
                        &public_key,
                    )
                    .is_ok(),
                    _ => false,
                }
            }
        }
        SigningAlgorithm::SchnorrSecp256k1 => {
            let signature_array: [u8; 64] = match signature_bytes.try_into() {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Err(ConclaveError::CryptoError(
                        "invalid Schnorr signature".to_string(),
                    ))
                }
            };
            let public_key_array: [u8; 32] = match public_key_bytes.try_into() {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Err(ConclaveError::CryptoError(
                        "invalid Schnorr public key".to_string(),
                    ))
                }
            };
            let signature = secp256k1::schnorr::Signature::from_byte_array(signature_array);
            let public_key =
                secp256k1::XOnlyPublicKey::from_byte_array(public_key_array).map_err(|_| {
                    ConclaveError::CryptoError("invalid Schnorr public key".to_string())
                })?;
            let message: [u8; 32] = request
                .message_hash
                .as_slice()
                .try_into()
                .map_err(|_| ConclaveError::InvalidPayload)?;
            secp256k1::schnorr::verify(&signature, &message, &public_key).is_ok()
        }
        SigningAlgorithm::Ed25519 => {
            let public_key_array: [u8; 32] = match public_key_bytes.try_into() {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Err(ConclaveError::CryptoError(
                        "invalid Ed25519 public key".to_string(),
                    ))
                }
            };
            let public_key =
                ed25519_dalek::VerifyingKey::from_bytes(&public_key_array).map_err(|_| {
                    ConclaveError::CryptoError("invalid Ed25519 public key".to_string())
                })?;
            let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
                .map_err(|_| ConclaveError::CryptoError("invalid Ed25519 signature".to_string()))?;
            public_key.verify(&request.message_hash, &signature).is_ok()
        }
    };

    if valid {
        Ok(())
    } else {
        Err(ConclaveError::CryptoError(
            "value-bearing signature does not verify against its request".to_string(),
        ))
    }
}

#[cfg(test)]
mod enclave_tests {
    use super::*;
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
    fn production_value_signing_rejects_simulated_provider() {
        let enclave = CloudEnclave::new("https://kms.test".to_string()).unwrap();
        let request = SignRequest {
            algorithm: SigningAlgorithm::Ed25519,
            message_hash: b"production boundary".to_vec(),
            derivation_path: "m/44'/501'/0'/0'".to_string(),
            key_id: "test-key".to_string(),
            taproot_tweak: None,
        };
        let response = enclave.sign(request.clone()).unwrap();

        let result =
            validate_value_bearing_response(&request, &response, &AttestationPolicy::production());
        assert!(matches!(
            result,
            Err(ConclaveError::Unsupported(message))
                if message.contains("verified hardware provider")
        ));
    }

    #[test]
    fn test_fixture_value_signing_requires_matching_typed_algorithm() {
        let enclave = CloudEnclave::new("https://kms.test".to_string()).unwrap();

        for algorithm in [
            SigningAlgorithm::EcdsaSecp256k1,
            SigningAlgorithm::SchnorrSecp256k1,
            SigningAlgorithm::Ed25519,
        ] {
            let request = SignRequest {
                algorithm,
                message_hash: vec![0xA5; 32],
                derivation_path: "m/44'/501'/0'/0'".to_string(),
                key_id: "test-key".to_string(),
                taproot_tweak: None,
            };

            let response = enclave.sign(request.clone()).unwrap();
            sign_value_bearing(&enclave, request).expect("typed fixture must verify");
            assert!(!response.signature_hex.is_empty());
        }
    }
}
