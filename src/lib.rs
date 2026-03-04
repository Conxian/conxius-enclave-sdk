pub mod enclave;
pub mod protocol;

#[cfg(target_arch = "wasm32")]
pub mod wasm_bindings;

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
    use crate::enclave::attestation::DeviceIntegrityReport;
    use crate::protocol::stacks::StacksManager;
    use crate::protocol::musig2::MuSig2Session;
    use crate::protocol::rails::{RailProxy, RailType, SwapRequest, SovereignHandshake};
    use crate::protocol::affiliate::AffiliateManager;
    use crate::protocol::bitcoin::TaprootManager;
    use secp256k1::{Secp256k1, SecretKey, PublicKey};

    #[tokio::test]
    async fn test_sovereign_rail_swap_btc() {
        let manager = CoreEnclaveManager::new();
        manager.derive_session_key("1234", b"salt").unwrap();

        let proxy = RailProxy::new(RailType::Changelly, "https://api.changelly.com".to_string(), None);
        let req = SwapRequest {
            from_chain: "BTC".to_string(),
            to_chain: "ETH".to_string(),
            from_asset: "BTC".to_string(),
            to_asset: "ETH".to_string(),
            amount: 1000,
            recipient_address: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh".to_string(),
        };

        // 1. Prepare intent
        let intent = proxy.prepare_intent(req).unwrap();
        assert_eq!(intent.chain_context, Some("BTC_SPV_VALIDATED".to_string()));

        // 2. Sign in enclave
        let sig_resp = manager.sign(SignRequest {
            message_hash: intent.signable_hash.clone(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            key_id: "test".to_string(),
        }).unwrap();

        // 3. Broadcast
        let response = proxy.broadcast_signed_intent(intent, sig_resp.signature_hex).await.unwrap();
        assert!(response.transaction_id.starts_with("CHG-PX-"));
    }

    #[test]
    fn test_bitcoin_taproot_signing() {
        let manager = CoreEnclaveManager::new();
        manager.derive_session_key("1234", b"salt").unwrap();
        let btc = TaprootManager::new(&manager);

        let sighash = [0u8; 32];
        let sig = btc.sign_taproot_sighash(sighash, "m/86'/0'/0'/0/0", "btc_test").unwrap();
        assert!(!sig.is_empty());
        // Schnorr signature should be 64 bytes hex = 128 chars
        assert_eq!(sig.len(), 128);
    }

    #[test]
    fn test_enclave_signing_and_attestation() {
        let manager = CoreEnclaveManager::new();
        manager.derive_session_key("1234", b"salt").unwrap();

        let message_hash = vec![0u8; 32];
        let request = SignRequest {
            message_hash: message_hash.clone(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            key_id: "test".to_string(),
        };

        let response = manager.sign(request).unwrap();
        assert!(!response.signature_hex.is_empty());

        let attestation_json = response.device_attestation.unwrap();
        let attestation: DeviceIntegrityReport = serde_json::from_str(&attestation_json).unwrap();
        assert!(attestation.verify(&message_hash));
    }

    #[test]
    fn test_stacks_sovereign_signing() {
        let manager = CoreEnclaveManager::new();
        manager.derive_session_key("1234", b"salt").unwrap();
        let stacks = StacksManager::new(&manager);

        let intent = stacks.prepare_transaction(b"transaction_payload").unwrap();
        let sig = stacks.sign_prepared_transaction(intent, "test").unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_affiliate_proof_generation() {
        let manager = CoreEnclaveManager::new();
        manager.derive_session_key("1234", b"salt").unwrap();
        let affiliate = AffiliateManager::new(&manager);
        let proof = affiliate.generate_referral_proof("partner1", "user1").unwrap();
        assert_eq!(proof.partner_id, "partner1");
        assert!(proof.expiration > proof.timestamp);
    }
}
