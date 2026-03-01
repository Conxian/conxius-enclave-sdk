use std::sync::Mutex;
use aes::Aes256;
use gcm::{Gcm, aead::{Aead, KeyInit}};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use k256::{
    ecdsa::{SigningKey, VerifyingKey},
    schnorr::signature::Signer,
};
use secp256k1::{Secp256k1, Message, SecretKey};

use crate::{ConclaveResult, ConclaveError, enclave::{HeadlessEnclave, SignRequest, SignResponse}};


/// Struct managing Android StrongBox equivalent logic in Rust.
/// In a true native Android context, this interfaces via JNI to the hardware Keystore.
/// For the WASM/Headless cross-platform core, this provides the deterministic derivation
/// and secure memory handling equivalent.
pub struct CoreEnclaveManager {
    // In memory representation of the derived session key. 
    // In true StrongBox, this key never leaves the hardware.
    session_key: Mutex<Option<[u8; 32]>>,
}

impl CoreEnclaveManager {
    pub fn new() -> Self {
        Self {
            session_key: Mutex::new(None),
        }
    }

    /// Replicates the PBKDF2 vault derivation from SecureEnclavePlugin.java
    pub fn derive_session_key(&self, pin: &str, salt: &[u8]) -> ConclaveResult<()> {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(pin.as_bytes(), salt, 100_000, &mut key);
        
        let mut session = self.session_key.lock().map_err(|_| ConclaveError::EnclaveFailure("Mutex lock failed".to_string()))?;
        *session = Some(key);
        
        Ok(())
    }

    /// ECDSA Signing for EVM / Stacks / Bitcoin
    fn sign_ecdsa(&self, priv_key_bytes: &[u8], message_hash: &[u8]) -> ConclaveResult<SignResponse> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(priv_key_bytes)
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid secret key: {}", e)))?;
            
        let message = Message::from_digest_slice(message_hash)
            .map_err(|_| ConclaveError::InvalidPayload)?;

        let sig = secp.sign_ecdsa_recoverable(&message, &secret_key);
        let (rec_id, sig_bytes) = sig.serialize_compact();
        
        // Append recovery ID to make it 65 bytes (EVM standard)
        let mut final_sig = sig_bytes.to_vec();
        final_sig.push(rec_id.to_i32() as u8);

        let public_key = secret_key.public_key(&secp);
        
        Ok(SignResponse {
            signature_hex: hex::encode(final_sig),
            public_key_hex: hex::encode(public_key.serialize()),
            device_attestation: Some("CORE_TEE_EMULATION".to_string()),
        })
    }

    /// BIP340 Schnorr Signing for Taproot / RGB / BitVM
    fn sign_schnorr(&self, priv_key_bytes: &[u8], message_hash: &[u8]) -> ConclaveResult<SignResponse> {
        let signing_key = k256::schnorr::SigningKey::from_bytes(priv_key_bytes.into())
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid Schnorr key: {}", e)))?;
            
        let signature: k256::schnorr::Signature = signing_key.sign(message_hash);
        let verify_key = k256::schnorr::VerifyingKey::from(&signing_key);
        
        Ok(SignResponse {
            signature_hex: hex::encode(signature.to_bytes()),
            public_key_hex: hex::encode(verify_key.to_bytes()),
            device_attestation: Some("CORE_TEE_EMULATION".to_string()),
        })
    }
}

impl HeadlessEnclave for CoreEnclaveManager {
    fn initialize(&self) -> ConclaveResult<()> {
        // Here we would probe for StrongBox/TEE presence in a native wrapper.
        Ok(())
    }

    fn generate_key(&self, _key_id: &str) -> ConclaveResult<String> {
        // Generate random bytes for a new vault seed
        let mut seed = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
        Ok(hex::encode(seed))
    }

    fn sign(&self, request: SignRequest) -> ConclaveResult<SignResponse> {
        // 1. In a real environment, we use the active session_key to decrypt the 
        // underlying root seed from storage. For the SDK, we expect the derived child key bytes.
        // We will mock the derivation step for the headless interface.
        
        let mock_priv_key = [1u8; 32]; // DUMMY: In reality, derive from HD path via bdk

        if request.derivation_path.contains("86'") || request.derivation_path.contains("rgb") {
            self.sign_schnorr(&mock_priv_key, &request.message_hash)
        } else {
            self.sign_ecdsa(&mock_priv_key, &request.message_hash)
        }
    }
}
    }
}
