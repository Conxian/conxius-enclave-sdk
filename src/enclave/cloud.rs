use crate::enclave::attestation::{
    parse_extension_data, AttestationLevel, AttestationReportType, DeviceIntegrityReport,
    ATTESTATION_ENVELOPE_VERSION,
};
use crate::{
    enclave::{EnclaveManager, SignRequest, SignResponse, SigningAlgorithm},
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

pub struct CloudEnclave {
    pub kms_endpoint: String,
    local_dev_key_bytes: Option<Zeroizing<[u8; 32]>>,
    simulated_kms_key_bytes: Zeroizing<[u8; 32]>,
}

impl CloudEnclave {
    pub fn new(kms_endpoint: String) -> ConclaveResult<Self> {
        let simulated_kms_key_bytes = Self::generate_simulated_kms_key_bytes()?;
        Ok(Self {
            kms_endpoint,
            local_dev_key_bytes: None,
            simulated_kms_key_bytes,
        })
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
            None => &self.simulated_kms_key_bytes,
        }
    }

    fn get_active_secp_key(&self) -> ConclaveResult<SecretKey> {
        SecretKey::from_secret_bytes(*self.get_active_key_bytes())
            .map_err(|e| ConclaveError::CryptoError(format!("SEC1 Error: {e}")))
    }

    fn generate_attestation_report(
        &self,
        challenge: &[u8],
    ) -> ConclaveResult<DeviceIntegrityReport> {
        let key_bytes = self.get_active_key_bytes();
        let signing_key = SigningKey::from_bytes(key_bytes);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

        let timestamp = unix_time_secs();
        let extension_data =
            "SIMULATED_SOFTWARE_ONLY|PURPOSE_SIGN|ALGORITHM_ED25519|PLATFORM_CLOUD".to_string();
        let extensions = parse_extension_data(&extension_data).ok_or_else(|| {
            ConclaveError::CryptoError("Invalid simulated attestation extensions".to_string())
        })?;

        let mut report = DeviceIntegrityReport {
            report_version: ATTESTATION_ENVELOPE_VERSION,
            report_type: AttestationReportType::DeviceIntegrity,
            // This implementation is a local software simulation. It must not
            // present itself as provider-backed hardware before a real provider
            // integration exists.
            level: AttestationLevel::Software,
            challenge_nonce: challenge.to_vec(),
            signature: Vec::new(),
            // No provider certificate chain exists for this software-only
            // simulation. The single leaf identity is intentionally rejected
            // by all production verification paths.
            certificate_chain: vec![pubkey_hex],
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
                let message: [u8; 32] = request
                    .message_hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| ConclaveError::InvalidPayload)?;
                let secret_key = self.get_active_secp_key()?;
                let keypair = secret_key.keypair();
                let (x_only_public_key, _) = keypair.x_only_public_key();
                public_key_hex = hex::encode(x_only_public_key.serialize());
                let signature = secp256k1::schnorr::sign_no_aux_rand(&message, &keypair);
                signature_hex = hex::encode(signature.to_byte_array());
            }
            SigningAlgorithm::Ed25519 => {
                let key_bytes = self.get_active_key_bytes();
                let signing_key = SigningKey::from_bytes(key_bytes);
                public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
                let sig = signing_key.sign(&request.message_hash);
                signature_hex = hex::encode(sig.to_bytes());
            }
        };

        let attestation = self.generate_attestation_report(&request.message_hash)?;
        let attestation_json = serde_json::to_string(&attestation)
            .map_err(|e| ConclaveError::CryptoError(format!("Serialization error: {}", e)))?;

        Ok(SignResponse {
            signature_hex,
            public_key_hex,
            device_attestation: Some(attestation_json),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::{EnclaveManager, SignRequest, SigningAlgorithm};
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
    fn cloud_schnorr_signature_is_verifiable_and_nonzero() {
        let message = [0x31u8; 32];
        let response = enclave()
            .sign(request(
                SigningAlgorithm::SchnorrSecp256k1,
                message.to_vec(),
            ))
            .unwrap();
        let signature_bytes = hex::decode(response.signature_hex).unwrap();
        let public_key_bytes = hex::decode(response.public_key_hex).unwrap();
        let signature_array: [u8; 64] = signature_bytes.as_slice().try_into().unwrap();
        let signature = secp256k1::schnorr::Signature::from_byte_array(signature_array);
        let public_key =
            secp256k1::XOnlyPublicKey::from_byte_array(public_key_bytes.try_into().unwrap())
                .unwrap();

        assert!(signature_bytes.iter().any(|byte| *byte != 0));
        assert!(secp256k1::schnorr::verify(&signature, &message, &public_key).is_ok());
    }

    #[test]
    fn cloud_schnorr_matches_bip340_reference_vector() {
        let mut vector_secret_key = [0u8; 32];
        vector_secret_key[31] = 3;
        let enclave = CloudEnclave::new("https://kms.test".to_string())
            .unwrap()
            .with_dev_key(vector_secret_key)
            .unwrap();
        let message = [0u8; 32];
        let response = enclave
            .sign(request(
                SigningAlgorithm::SchnorrSecp256k1,
                message.to_vec(),
            ))
            .unwrap();

        let expected_signature = hex::decode(
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215\
             25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
        )
        .unwrap();
        assert_eq!(
            hex::decode(response.signature_hex).unwrap(),
            expected_signature
        );
        assert_eq!(
            response.public_key_hex,
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9".to_lowercase()
        );
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
    fn cloud_simulation_attestation_is_not_accepted_as_hardware() {
        let message = b"software cloud simulation";
        let response = enclave()
            .sign(request(SigningAlgorithm::Ed25519, message.to_vec()))
            .unwrap();
        let attestation = response.device_attestation.unwrap();
        let report: DeviceIntegrityReport = serde_json::from_str(&attestation).unwrap();

        assert_eq!(report.level, AttestationLevel::Software);
        assert!(!report.verify(message));
    }
}
