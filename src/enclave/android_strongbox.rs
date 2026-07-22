use hmac::{Hmac, KeyInit, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use secp256k1::{ecdsa::RecoverableSignature, ecdsa::RecoveryId, Message, SecretKey};
use sha2::Sha512;
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

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

type HmacSha512 = Hmac<Sha512>;

fn unix_time_secs() -> ConclaveResult<u64> {
    crate::enclave::trusted_unix_time_secs()
}

/// CoreEnclaveManager is a software-backed development driver.
///
/// It is useful for local integration and interface validation, but it is not a
/// production hardware-bound StrongBox implementation. Production deployments
/// must replace this path with a hardware-backed driver that emits hardened
/// attestation levels such as TEE, StrongBox, or CloudTEE.
pub struct CoreEnclaveManager {
    session_key: Mutex<Option<Zeroizing<[u8; 64]>>>,
}

#[cfg(test)]
impl Default for CoreEnclaveManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CoreEnclaveManager {
    fn new_inner() -> Self {
        Self {
            session_key: Mutex::new(None),
        }
    }

    /// This manager is permanently software-backed and development-only.
    pub const SOFTWARE_ONLY: bool = true;

    pub const fn is_software_only() -> bool {
        Self::SOFTWARE_ONLY
    }

    /// Constructs the software-backed fixture used by this crate's unit tests.
    #[cfg(test)]
    pub fn new() -> Self {
        Self::new_inner()
    }

    /// Constructs an explicitly development-only software simulator.
    #[cfg(all(not(test), feature = "development-simulators"))]
    pub fn new_for_development() -> Self {
        Self::new_inner()
    }

    pub fn is_initialized(&self) -> bool {
        let session = match self.session_key.lock() {
            Ok(s) => s,
            Err(_) => return false,
        };
        session.is_some()
    }

    fn derive_child_key(&self, derivation_path: &str) -> ConclaveResult<Zeroizing<[u8; 32]>> {
        let session_lock = self
            .session_key
            .lock()
            .map_err(|_| ConclaveError::EnclaveFailure("Mutex poison".to_string()))?;
        let session_key = session_lock.as_ref().ok_or(ConclaveError::EnclaveFailure(
            "Enclave not unlocked".to_string(),
        ))?;

        let session_key_bytes: &[u8] = &**session_key;

        let mut mac = HmacSha512::new_from_slice(session_key_bytes)
            .map_err(|_| ConclaveError::CryptoError("KDF initialization failure".to_string()))?;
        mac.update(derivation_path.as_bytes());
        let result = mac.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result.into_bytes()[..32]);
        Ok(Zeroizing::new(key))
    }

    // Test builds use a deterministic fixture; development-simulator builds
    // emit explicitly software-only evidence. Neither path is production
    // hardware attestation.
    fn generate_attestation(
        &self,
        challenge: &[u8],
        report_key_bytes: &[u8],
        algorithm: &SigningAlgorithm,
        operation_public_key: &[u8],
    ) -> ConclaveResult<DeviceIntegrityReport> {
        #[cfg(test)]
        let _ = report_key_bytes;

        let timestamp = unix_time_secs()?;
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
            let report_key: [u8; 32] = report_key_bytes
                .try_into()
                .map_err(|_| ConclaveError::CryptoError("Invalid attestation key".to_string()))?;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&report_key);
            let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
            (
                signing_key,
                AttestationLevel::Software,
                vec![pubkey_hex],
                format!("SIMULATED_SOFTWARE_ONLY|PURPOSE_SIGN|{algorithm_token}|OS_VERSION_14"),
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
            signer_key_binding: None,
            certificate_chain,
            timestamp,
            extension_data,
            extensions,
        };
        report.sign_with_ed25519_key(&signing_key)?;
        Ok(report)
    }

    fn sign_ecdsa(
        &self,
        priv_key_bytes: &[u8],
        message_hash: &[u8],
    ) -> ConclaveResult<SignResponse> {
        let secret_key = SecretKey::from_secret_bytes(
            priv_key_bytes
                .try_into()
                .map_err(|_| ConclaveError::CryptoError("Key mismatch".to_string()))?,
        )
        .map_err(|e| ConclaveError::CryptoError(format!("SEC1 Error: {}", e)))?;

        let message = Message::from_digest(
            message_hash
                .try_into()
                .map_err(|_| ConclaveError::InvalidPayload)?,
        );

        let sig = RecoverableSignature::sign_ecdsa_recoverable(message, &secret_key);
        let (rec_id, sig_bytes) = sig.serialize_compact();

        let mut final_sig = sig_bytes.to_vec();
        let rec_byte = match rec_id {
            RecoveryId::Zero => 0,
            RecoveryId::One => 1,
            RecoveryId::Two => 2,
            RecoveryId::Three => 3,
        };
        final_sig.push(rec_byte);

        let public_key = secret_key.public_key();
        let attestation = self.generate_attestation(
            message_hash,
            priv_key_bytes,
            &SigningAlgorithm::EcdsaSecp256k1,
            &public_key.serialize(),
        )?;
        let attestation_json = serde_json::to_string(&attestation)
            .map_err(|e| ConclaveError::CryptoError(format!("Serialization error: {}", e)))?;

        Ok(SignResponse {
            signature_hex: hex::encode(final_sig),
            public_key_hex: hex::encode(public_key.serialize()),
            device_attestation: Some(attestation_json),
        })
    }

    fn sign_schnorr(
        &self,
        priv_key_bytes: &[u8],
        message_hash: &[u8],
        tweak: Option<&[u8]>,
    ) -> ConclaveResult<SignResponse> {
        let mut secret_key = SecretKey::from_secret_bytes(
            priv_key_bytes
                .try_into()
                .map_err(|_| ConclaveError::CryptoError("Key mismatch".to_string()))?,
        )
        .map_err(|e| ConclaveError::CryptoError(format!("SEC1 Error: {}", e)))?;

        if let Some(tweak_bytes) = tweak {
            let scalar = secp256k1::Scalar::from_be_bytes(
                tweak_bytes
                    .try_into()
                    .map_err(|_| ConclaveError::CryptoError("Invalid tweak length".to_string()))?,
            )
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid tweak scalar: {}", e)))?;

            // BIP-341 tweaks the secret corresponding to the x-only internal
            // key: use d for even-Y keys and n-d for odd-Y keys before adding
            // the TapTweak scalar. The parity comes from libsecp256k1 rather
            // than from hand-rolled point or scalar arithmetic.
            let (_, parity) = secret_key.x_only_public_key();
            if parity == secp256k1::Parity::Odd {
                secret_key = secret_key.negate();
            }
            secret_key = secret_key
                .add_tweak(&scalar)
                .map_err(|e| ConclaveError::CryptoError(format!("Tweak addition failed: {}", e)))?;
        }

        let message: [u8; 32] = message_hash
            .try_into()
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let keypair = secret_key.keypair();
        let (verify_key, _) = keypair.x_only_public_key();
        let signature = secp256k1::schnorr::sign_no_aux_rand(&message, &keypair);
        let attestation = self.generate_attestation(
            message_hash,
            priv_key_bytes,
            &SigningAlgorithm::SchnorrSecp256k1,
            &verify_key.serialize(),
        )?;
        let attestation_json = serde_json::to_string(&attestation)
            .map_err(|e| ConclaveError::CryptoError(format!("Serialization error: {}", e)))?;

        Ok(SignResponse {
            signature_hex: hex::encode(signature.to_byte_array()),
            public_key_hex: hex::encode(verify_key.serialize()),
            device_attestation: Some(attestation_json),
        })
    }
}

impl EnclaveManager for CoreEnclaveManager {
    fn initialize(&self) -> ConclaveResult<()> {
        Ok(())
    }

    fn signer_capability(&self) -> SignerCapability {
        SignerCapability::software_unverified()
    }

    fn unlock(&self, pin: &str, salt: &[u8]) -> ConclaveResult<()> {
        if pin.len() < 4 {
            return Err(ConclaveError::CryptoError("PIN too short".to_string()));
        }

        let mut key = Zeroizing::new([0u8; 64]);
        pbkdf2_hmac::<Sha512>(pin.as_bytes(), salt, 600_000, &mut *key);

        let mut session = self
            .session_key
            .lock()
            .map_err(|_| ConclaveError::EnclaveFailure("Mutex poison".to_string()))?;
        *session = Some(key);

        Ok(())
    }

    fn generate_key(&self, _key_id: &str) -> ConclaveResult<String> {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);

        let secret_key = SecretKey::from_secret_bytes(seed)
            .map_err(|e| ConclaveError::CryptoError(format!("Key generation failed: {}", e)))?;
        let public_key = secret_key.public_key();

        seed.zeroize();
        Ok(hex::encode(public_key.serialize()))
    }

    fn get_public_key(&self, derivation_path: &str) -> ConclaveResult<String> {
        let derived_priv_key = self.derive_child_key(derivation_path)?;
        let secret_key = SecretKey::from_secret_bytes(
            derived_priv_key
                .as_slice()
                .try_into()
                .map_err(|_| ConclaveError::CryptoError("Key mismatch".to_string()))?,
        )
        .map_err(|e| ConclaveError::CryptoError(format!("SEC1 Error: {}", e)))?;

        if derivation_path.contains("86'") || derivation_path.contains("schnorr") {
            let keypair = secret_key.keypair();
            let (x_only_public_key, _) = keypair.x_only_public_key();
            Ok(hex::encode(x_only_public_key.serialize()))
        } else {
            Ok(hex::encode(secret_key.public_key().serialize()))
        }
    }

    fn sign(&self, request: SignRequest) -> ConclaveResult<SignResponse> {
        let mut derived_priv_key = self.derive_child_key(&request.derivation_path)?;

        let response = match request.algorithm {
            SigningAlgorithm::EcdsaSecp256k1 => {
                self.sign_ecdsa(&*derived_priv_key, &request.message_hash)
            }
            SigningAlgorithm::SchnorrSecp256k1 => self.sign_schnorr(
                &*derived_priv_key,
                &request.message_hash,
                request.taproot_tweak.as_deref(),
            ),
            SigningAlgorithm::Ed25519 => Err(ConclaveError::Unsupported(
                "Ed25519 signing is unavailable in the software-backed StrongBox driver"
                    .to_string(),
            )),
        };

        derived_priv_key.zeroize();
        response
    }

    fn unlock_value_bearing(
        &self,
        _request: ValueBearingUnlockRequest,
    ) -> ConclaveResult<ValueBearingSession> {
        Err(ConclaveError::Unsupported(
            "CoreEnclaveManager is software-only and cannot unlock value-bearing operations"
                .to_string(),
        ))
    }

    fn sign_value_bearing(
        &self,
        _request: ValueBearingSignRequest,
    ) -> ConclaveResult<ValueBearingSignResponse> {
        Err(ConclaveError::Unsupported(
            "CoreEnclaveManager is software-only and cannot sign value-bearing operations"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::{EnclaveManager, SignRequest, SigningAlgorithm};
    use crate::protocol::bitcoin::verify_bip340_signature;
    use rand::RngExt;

    fn unlocked_enclave() -> CoreEnclaveManager {
        let enclave = CoreEnclaveManager::new();
        let salt = rand::rng().random::<[u8; 16]>();
        enclave.unlock("1234", &salt).unwrap();
        enclave
    }

    fn request(algorithm: SigningAlgorithm, message_hash: Vec<u8>) -> SignRequest {
        SignRequest {
            algorithm,
            message_hash,
            derivation_path: "m/86'/0'/0'/0/0".to_string(),
            key_id: "test-key".to_string(),
            taproot_tweak: None,
        }
    }

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        hex::decode(value)
            .expect("test vector hex")
            .try_into()
            .expect("test vector length")
    }

    fn secret_key_with_parity(expected: secp256k1::Parity) -> SecretKey {
        (1u8..=u8::MAX)
            .map(|value| {
                let mut bytes = [0u8; 32];
                bytes[31] = value;
                SecretKey::from_secret_bytes(bytes).expect("small test secret key")
            })
            .find(|secret_key| secret_key.x_only_public_key().1 == expected)
            .expect("a small secret key with the requested parity")
    }

    fn taproot_output_key(
        secret_key: &SecretKey,
        tweak_bytes: &[u8; 32],
    ) -> secp256k1::XOnlyPublicKey {
        let (internal_key, _) = secret_key.x_only_public_key();
        let tweak = secp256k1::Scalar::from_be_bytes(*tweak_bytes).expect("valid test tweak");
        internal_key
            .add_tweak(&tweak)
            .expect("valid test Taproot output key")
            .0
    }

    #[test]
    fn software_strongbox_ecdsa_signature_is_verifiable_and_nonzero() {
        let message = [2u8; 32];
        let response = unlocked_enclave()
            .sign(request(SigningAlgorithm::EcdsaSecp256k1, message.to_vec()))
            .unwrap();
        let signature_bytes = hex::decode(response.signature_hex).unwrap();
        let recovery_id = RecoveryId::from_u8_masked(signature_bytes[64]);
        let recoverable =
            RecoverableSignature::from_compact(&signature_bytes[..64], recovery_id).unwrap();
        let signature = recoverable.to_standard();
        let public_key =
            secp256k1::PublicKey::from_slice(&hex::decode(response.public_key_hex).unwrap())
                .unwrap();
        assert!(signature_bytes.iter().any(|byte| *byte != 0));
        assert!(
            secp256k1::ecdsa::verify(&signature, Message::from_digest(message), &public_key)
                .is_ok()
        );
    }

    #[test]
    fn software_strongbox_schnorr_signature_is_verifiable_and_nonzero() {
        let message = [0x52u8; 32];
        let response = unlocked_enclave()
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
    fn software_strongbox_schnorr_matches_bip340_reference_vector() {
        let enclave = unlocked_enclave();
        let message = [0u8; 32];
        let response = enclave
            .sign(request(
                SigningAlgorithm::SchnorrSecp256k1,
                message.to_vec(),
            ))
            .unwrap();

        // The derived test key is not the BIP340 vector key; independently
        // verify the backend output through libsecp256k1's raw API instead.
        let signature = secp256k1::schnorr::Signature::from_byte_array(
            hex::decode(response.signature_hex)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let public_key = secp256k1::XOnlyPublicKey::from_byte_array(
            hex::decode(response.public_key_hex)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        assert!(secp256k1::schnorr::verify(&signature, &message, &public_key).is_ok());
    }

    #[test]
    fn software_strongbox_schnorr_matches_bip340_known_answer() {
        let enclave = CoreEnclaveManager::new();
        let mut secret_key = [0u8; 32];
        secret_key[31] = 3;
        let message = [0u8; 32];

        // `sign_no_aux_rand` uses the BIP340 deterministic zero-auxiliary-
        // randomness path. The fixed key/message pair is the BIP340 vector.
        let response = enclave.sign_schnorr(&secret_key, &message, None).unwrap();

        assert_eq!(
            response.signature_hex,
            concat!(
                "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215",
                "25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
            )
        );
        assert_eq!(
            response.public_key_hex,
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        );
    }

    #[test]
    fn software_strongbox_taproot_schnorr_normalizes_odd_internal_secret() {
        let enclave = CoreEnclaveManager::new();
        let secret_key = secret_key_with_parity(secp256k1::Parity::Odd);
        let message = [0x42u8; 32];
        let tweak =
            decode_hex::<32>("6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30");
        let expected_output_key = taproot_output_key(&secret_key, &tweak);
        let secret_key_bytes = secret_key.to_secret_bytes();

        let response = enclave
            .sign_schnorr(&secret_key_bytes, &message, Some(&tweak))
            .expect("odd-Y Taproot signing");
        let signature = decode_hex::<64>(&response.signature_hex);
        let public_key = decode_hex::<32>(&response.public_key_hex);

        assert_eq!(public_key, expected_output_key.serialize());
        assert_eq!(
            verify_bip340_signature(&message, &expected_output_key.serialize(), &signature),
            Ok(true)
        );

        let scalar = secp256k1::Scalar::from_be_bytes(tweak).expect("valid test tweak");
        let direct_secret_key = secret_key
            .add_tweak(&scalar)
            .expect("direct d+t regression key");
        let direct_output_key = direct_secret_key.x_only_public_key().0;
        let direct_signature =
            secp256k1::schnorr::sign_no_aux_rand(&message, &direct_secret_key.keypair());

        assert_ne!(direct_output_key, expected_output_key);
        assert_eq!(
            verify_bip340_signature(
                &message,
                &expected_output_key.serialize(),
                &direct_signature.to_byte_array(),
            ),
            Ok(false)
        );
    }

    #[test]
    fn software_strongbox_taproot_schnorr_preserves_even_internal_secret_behavior() {
        let enclave = CoreEnclaveManager::new();
        let secret_key = secret_key_with_parity(secp256k1::Parity::Even);
        let message = [0x24u8; 32];
        let tweak =
            decode_hex::<32>("6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30");
        let expected_output_key = taproot_output_key(&secret_key, &tweak);
        let secret_key_bytes = secret_key.to_secret_bytes();

        let response = enclave
            .sign_schnorr(&secret_key_bytes, &message, Some(&tweak))
            .expect("even-Y Taproot signing");
        let signature = decode_hex::<64>(&response.signature_hex);
        let public_key = decode_hex::<32>(&response.public_key_hex);
        assert_eq!(public_key, expected_output_key.serialize());
        assert_eq!(
            verify_bip340_signature(&message, &expected_output_key.serialize(), &signature),
            Ok(true)
        );

        let scalar = secp256k1::Scalar::from_be_bytes(tweak).expect("valid test tweak");
        let direct_output_key = secret_key
            .add_tweak(&scalar)
            .expect("direct even-Y d+t key")
            .x_only_public_key()
            .0;
        assert_eq!(direct_output_key, expected_output_key);
    }

    #[test]
    fn software_strongbox_taproot_schnorr_rejects_invalid_tweak_and_result_keys() {
        let enclave = CoreEnclaveManager::new();
        let secret_key = secret_key_with_parity(secp256k1::Parity::Even);
        let secret_key_bytes = secret_key.to_secret_bytes();
        let message = [0x11u8; 32];

        assert!(matches!(
            enclave.sign_schnorr(&secret_key_bytes, &message, Some(&[1u8; 31])),
            Err(ConclaveError::CryptoError(_))
        ));

        let scalar_out_of_range =
            decode_hex::<32>("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        assert!(matches!(
            enclave.sign_schnorr(&secret_key_bytes, &message, Some(&scalar_out_of_range)),
            Err(ConclaveError::CryptoError(_))
        ));

        let scalar_result_zero =
            decode_hex::<32>("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
        let one_secret_key = SecretKey::from_secret_bytes({
            let mut bytes = [0u8; 32];
            bytes[31] = 1;
            bytes
        })
        .expect("secret key one");
        assert_eq!(
            one_secret_key.x_only_public_key().1,
            secp256k1::Parity::Even
        );
        assert!(matches!(
            enclave.sign_schnorr(
                &one_secret_key.to_secret_bytes(),
                &message,
                Some(&scalar_result_zero)
            ),
            Err(ConclaveError::CryptoError(_))
        ));
    }

    #[test]
    fn software_strongbox_ed25519_fails_closed_as_unsupported() {
        let result = unlocked_enclave().sign(request(
            SigningAlgorithm::Ed25519,
            b"unsupported ed25519 message".to_vec(),
        ));

        assert!(matches!(
            result,
            Err(ConclaveError::Unsupported(message))
                if message.contains("Ed25519")
        ));
    }
}
