pub mod enclave;
pub mod protocol;

// Re-export core WebAssembly bindings if the target is WASM
#[cfg(target_arch = "wasm32")]
pub mod wasm_bindings;

// Re-export JNI bindings if the target is Android
#[cfg(target_os = "android")]
pub mod android;

/// The core Conclave SDK result type
pub type ConclaveResult<T> = Result<T, ConclaveError>;

#[derive(Debug, thiserror::Error)]
pub enum ConclaveError {
    #[error("Hardware Enclave Error: {0}")]
    EnclaveFailure(String),
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
    #[error("Invalid Payload provided")]
    InvalidPayload,
}

#[cfg(test)]
mod tests {
    use crate::enclave::android_strongbox::CoreEnclaveManager;
    use crate::enclave::{HeadlessEnclave, SignRequest};
    use crate::protocol::stacks::StacksManager;
    use crate::protocol::musig2::MuSig2Session;
    use secp256k1::{Secp256k1, SecretKey, PublicKey};

    #[test]
    fn test_enclave_signing() {
        let manager = CoreEnclaveManager::new();
        manager.derive_session_key("1234", b"salt").unwrap();

        let request = SignRequest {
            message_hash: vec![0u8; 32],
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            key_id: "test".to_string(),
        };

        let response = manager.sign(request).unwrap();
        assert!(!response.signature_hex.is_empty());
        assert!(!response.public_key_hex.is_empty());
    }

    #[test]
    fn test_stacks_signing() {
        let manager = CoreEnclaveManager::new();
        manager.derive_session_key("1234", b"salt").unwrap();
        let stacks = StacksManager::new(&manager);

        let sig = stacks.sign_message("Hello Conclave", "test").unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_musig2_simple() {
        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_byte_array([1u8; 32]).unwrap();
        let sk2 = SecretKey::from_byte_array([2u8; 32]).unwrap();
        let pk1 = PublicKey::from_secret_key(&secp, &sk1);
        let pk2 = PublicKey::from_secret_key(&secp, &sk2);

        let session = MuSig2Session::new(&[pk1, pk2]).unwrap();
        let (sn1, pn1) = session.generate_nonce(&sk1);
        let (sn2, pn2) = session.generate_nonce(&sk2);

        let msg = [0u8; 32];
        let ps1 = session.partial_sign(sn1, vec![pn1.clone(), pn2.clone()], &sk1, msg).unwrap();
        let ps2 = session.partial_sign(sn2, vec![pn1.clone(), pn2.clone()], &sk2, msg).unwrap();

        let final_sig = session.aggregate_signatures(vec![pn1, pn2], vec![ps1, ps2], msg).unwrap();
        assert_eq!(final_sig.len(), 64);
    }
}
