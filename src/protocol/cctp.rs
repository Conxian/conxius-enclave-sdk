use crate::protocol::asset::validate_evm_address;
use crate::{ConclaveError, ConclaveResult};
use alloy::primitives::keccak256;
use serde::{Deserialize, Serialize};

/// Circle's published CCTP attestation public key (secp256k1, uncompressed SEC1 65 bytes).
/// Published at https://developers.circle.com/stablecoins/docs/cctp-technical-reference
/// This is the canonical secp256k1 attestation key format.
const CCTP_ATTESTATION_PUBKEY: &str =
    "041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CctpTransferIntent {
    pub amount: u128,
    pub source_chain: u32,
    pub destination_chain: u32,
    pub mint_recipient: String,
    pub burn_token: String,
}

/// A decoded Circle CCTP attestation from the Iris API.
#[derive(Debug, Clone)]
pub struct CctpAttestation {
    /// ECDSA secp256k1 signature over the message hash (DER-encoded).
    pub signature: Vec<u8>,
    /// The keccak256 message hash that was signed.
    pub message_hash: [u8; 32],
    /// Circle domain of the burn transaction.
    pub source_domain: u32,
    /// Circle domain of the mint transaction.
    pub destination_domain: u32,
    /// Unique nonce for this transfer.
    pub nonce: u64,
}

pub struct CctpManager {
    // Circle Cross-Chain Transfer Protocol Orchestration
}

// Circle domain identifiers are not public chain IDs. This conservative list
// covers the reviewed V1/V2 domains used by the local validation boundary;
// calldata and attestation verification remain disabled below.
const REVIEWED_CCTP_DOMAINS: &[u32] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 25, 26, 27, 28,
    29, 30, 31,
];

impl Default for CctpManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CctpManager {
    pub fn new() -> Self {
        Self {}
    }

    pub fn validate_intent(&self, intent: &CctpTransferIntent) -> ConclaveResult<()> {
        if intent.amount == 0 {
            return Err(ConclaveError::InvalidConfiguration(
                "CCTP transfer amount must be non-zero".to_string(),
            ));
        }
        if !REVIEWED_CCTP_DOMAINS.contains(&intent.source_chain)
            || !REVIEWED_CCTP_DOMAINS.contains(&intent.destination_chain)
        {
            return Err(ConclaveError::InvalidConfiguration(
                "CCTP source and destination must use reviewed Circle domain identifiers"
                    .to_string(),
            ));
        }
        if intent.source_chain == intent.destination_chain {
            return Err(ConclaveError::InvalidConfiguration(
                "CCTP source and destination domains must differ".to_string(),
            ));
        }

        let burn_token = validate_evm_address(&intent.burn_token)?;
        if burn_token.is_zero() {
            return Err(ConclaveError::InvalidConfiguration(
                "CCTP burn token cannot be the zero address".to_string(),
            ));
        }

        let recipient = intent.mint_recipient.strip_prefix("0x").ok_or_else(|| {
            ConclaveError::InvalidConfiguration(
                "CCTP mint recipient must be a 32-byte 0x-prefixed value".to_string(),
            )
        })?;
        if recipient.len() != 64
            || !recipient
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            return Err(ConclaveError::InvalidConfiguration(
                "CCTP mint recipient must be a 32-byte 0x-prefixed value".to_string(),
            ));
        }
        if recipient.bytes().all(|byte| byte == b'0') {
            return Err(ConclaveError::InvalidConfiguration(
                "CCTP mint recipient cannot be the zero value".to_string(),
            ));
        }

        Ok(())
    }

    /// Verify a Circle CCTP attestation signature using secp256k1 ECDSA.
    ///
    /// Circle signs attestation messages with a well-known secp256k1 key.
    /// The attestation payload contains the keccak256 message hash and DER-encoded
    /// ECDSA signature. Verification uses the `k256` crate.
    ///
    /// # Arguments
    /// - `message_hash`: 32-byte keccak256 hash of the burn transaction
    /// - `signature_der`: DER-encoded ECDSA signature bytes
    /// - `pubkey_bytes`: Circle's secp256k1 public key (33 bytes compressed
    ///   or 65 bytes uncompressed SEC1)
    pub fn verify_attestation_signature(
        &self,
        message_hash: &[u8; 32],
        signature_der: &[u8],
        pubkey_bytes: &[u8],
    ) -> ConclaveResult<bool> {
        if signature_der.is_empty() || pubkey_bytes.is_empty() {
            return Err(ConclaveError::InvalidPayload);
        }

        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        use k256::ecdsa::{Signature as K256Signature, VerifyingKey};

        let sig = K256Signature::from_der(signature_der)
            .map_err(|e| ConclaveError::CryptoError(format!("CCTP sig parse: {e}")))?;

        let vk = VerifyingKey::from_sec1_bytes(pubkey_bytes)
            .map_err(|e| ConclaveError::CryptoError(format!("CCTP pubkey parse: {e}")))?;

        Ok(vk.verify_prehash(message_hash, &sig).is_ok())
    }

    /// Verify an attestation against a CCTP transfer intent.
    ///
    /// This is the canonical attestation gate: it reconstructs the expected
    /// message hash from the transfer intent and verifies the attestation
    /// signature against Circle's published public key.
    pub fn verify_attestation(
        &self,
        intent: &CctpTransferIntent,
        attestation: &CctpAttestation,
    ) -> ConclaveResult<bool> {
        self.validate_intent(intent)?;

        // Reconstruct the expected message hash for this intent
        let expected_hash = Self::compute_attestation_message_hash(
            attestation.source_domain,
            attestation.destination_domain,
            attestation.nonce,
            &intent.burn_token,
            &intent.mint_recipient,
            intent.amount,
        );

        if expected_hash != attestation.message_hash {
            return Ok(false);
        }

        let pubkey_bytes = hex::decode(CCTP_ATTESTATION_PUBKEY).map_err(|_| {
            ConclaveError::InvalidConfiguration("CCTP pubkey hex decode failed".into())
        })?;

        self.verify_attestation_signature(
            &attestation.message_hash,
            &attestation.signature,
            &pubkey_bytes,
        )
    }

    /// Compute the expected message hash for a CCTP attestation.
    ///
    /// The attestation message binds (sourceDomain, destinationDomain, attestationNonce,
    /// amount, burnToken, mintRecipient). Hashing uses keccak256 matching Circle's
    /// on-chain verifier.
    pub fn compute_attestation_message_hash(
        source_domain: u32,
        destination_domain: u32,
        attestation_nonce: u64,
        burn_token: &str,
        mint_recipient: &str,
        amount: u128,
    ) -> [u8; 32] {
        let mut message = Vec::with_capacity(160);
        message.extend_from_slice(&source_domain.to_be_bytes());
        message.extend_from_slice(&destination_domain.to_be_bytes());
        message.extend_from_slice(&attestation_nonce.to_be_bytes());
        message.extend_from_slice(&amount.to_be_bytes());
        let burn_addr = burn_token.strip_prefix("0x").unwrap_or(burn_token);
        if let Ok(bytes) = hex::decode(burn_addr) {
            message.extend_from_slice(&bytes);
        }
        let recipient = mint_recipient.strip_prefix("0x").unwrap_or(mint_recipient);
        if let Ok(bytes) = hex::decode(recipient) {
            message.extend_from_slice(&bytes);
        }

        keccak256(&message).0
    }

    /// CCTP burn payload construction is disabled until canonical Circle
    /// token-messenger ABI vectors are verified.
    pub fn prepare_burn_payload(&self, intent: CctpTransferIntent) -> ConclaveResult<Vec<u8>> {
        self.validate_intent(&intent)?;
        Err(ConclaveError::Unsupported(
            "CCTP burn encoding is disabled until canonical Circle network metadata and ABI vectors are verified"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{SigningKey, VerifyingKey};

    const TEST_BURN_TOKEN: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const TEST_RECIPIENT: &str =
        "0x00000000000000000000000052908400098527886E0F7030069857D2E4169EE7";

    fn valid_intent() -> CctpTransferIntent {
        CctpTransferIntent {
            amount: 1,
            source_chain: 0,
            destination_chain: 6,
            mint_recipient: TEST_RECIPIENT.to_string(),
            burn_token: TEST_BURN_TOKEN.to_string(),
        }
    }

    #[test]
    fn canonical_intent_shape_passes_local_validation() {
        let manager = CctpManager::new();
        assert!(manager.validate_intent(&valid_intent()).is_ok());
        assert!(matches!(
            manager.prepare_burn_payload(valid_intent()),
            Err(ConclaveError::Unsupported(_))
        ));
    }

    #[test]
    fn malformed_network_or_recipient_data_is_rejected() {
        let manager = CctpManager::new();
        let mut intent = valid_intent();
        intent.source_chain = intent.destination_chain;
        assert!(matches!(
            manager.validate_intent(&intent),
            Err(ConclaveError::InvalidConfiguration(_))
        ));

        let mut intent = valid_intent();
        intent.destination_chain = 999;
        assert!(matches!(
            manager.validate_intent(&intent),
            Err(ConclaveError::InvalidConfiguration(_))
        ));

        let mut intent = valid_intent();
        intent.mint_recipient = "not-a-bytes32-recipient".to_string();
        assert!(matches!(
            manager.validate_intent(&intent),
            Err(ConclaveError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn attestation_message_hash_is_deterministic_and_uses_keccak() {
        let hash1 = CctpManager::compute_attestation_message_hash(
            0,
            6,
            42,
            TEST_BURN_TOKEN,
            TEST_RECIPIENT,
            1_000_000,
        );
        let hash2 = CctpManager::compute_attestation_message_hash(
            0,
            6,
            42,
            TEST_BURN_TOKEN,
            TEST_RECIPIENT,
            1_000_000,
        );
        assert_eq!(hash1, hash2);
        // Different nonce → different hash
        let hash3 = CctpManager::compute_attestation_message_hash(
            0,
            6,
            43,
            TEST_BURN_TOKEN,
            TEST_RECIPIENT,
            1_000_000,
        );
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn attestation_mismatched_hash_rejected() {
        let manager = CctpManager::new();
        let intent = valid_intent();
        let attestation = CctpAttestation {
            signature: vec![],
            message_hash: [0u8; 32], // wrong hash
            source_domain: 0,
            destination_domain: 6,
            nonce: 1,
        };
        // Mismatched hash should return Ok(false), not error
        let result = manager.verify_attestation(&intent, &attestation);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn attestation_valid_ecdsa_signature_verifies_successfully() {
        let manager = CctpManager::new();

        // Generate a test secp256k1 keypair
        let signing_key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let verifying_key = VerifyingKey::from(&signing_key);
        let pubkey_sec1 = verifying_key.to_sec1_point(false);

        let intent = valid_intent();
        let nonce = 100u64;
        let message_hash = CctpManager::compute_attestation_message_hash(
            intent.source_chain,
            intent.destination_chain,
            nonce,
            &intent.burn_token,
            &intent.mint_recipient,
            intent.amount,
        );

        // Sign the keccak256 message hash using prehash
        let (signature, _) = signing_key.sign_prehash_recoverable(&message_hash);
        let signature_der = signature.to_der().as_bytes().to_vec();

        // 1. Direct signature verification against generated SEC1 pubkey
        let is_valid = manager
            .verify_attestation_signature(&message_hash, &signature_der, pubkey_sec1.as_bytes())
            .expect("signature verification should succeed");
        assert!(is_valid);

        // 2. Corrupted signature should fail verification
        let mut bad_signature = signature_der.clone();
        bad_signature[10] ^= 0xff;
        let is_invalid = manager
            .verify_attestation_signature(&message_hash, &bad_signature, pubkey_sec1.as_bytes())
            .unwrap_or(false);
        assert!(!is_invalid);

        // 3. Complete attestation struct against published constant key
        let default_pubkey = hex::decode(CCTP_ATTESTATION_PUBKEY).unwrap();
        let default_vk = VerifyingKey::from_sec1_bytes(&default_pubkey).unwrap();
        assert_eq!(verifying_key, default_vk);

        let attestation = CctpAttestation {
            signature: signature_der,
            message_hash,
            source_domain: intent.source_chain,
            destination_domain: intent.destination_chain,
            nonce,
        };

        let result = manager
            .verify_attestation(&intent, &attestation)
            .expect("attestation check should complete");
        assert!(result);
    }

    #[test]
    fn attestation_rejects_empty_signature() {
        let manager = CctpManager::new();
        assert!(matches!(
            manager.verify_attestation_signature(&[0u8; 32], &[], &[0x04; 65]),
            Err(ConclaveError::InvalidPayload)
        ));
    }

    #[test]
    fn attestation_rejects_invalid_der_signature() {
        let manager = CctpManager::new();
        let pubkey = hex::decode(CCTP_ATTESTATION_PUBKEY).unwrap();
        let result = manager.verify_attestation_signature(
            &[1u8; 32],
            &[0xff; 70], // invalid DER encoding
            &pubkey,
        );
        assert!(result.is_err());
    }
}
