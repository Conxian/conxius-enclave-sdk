use crate::{
    enclave::{
        sign_value_bearing, EnclaveManager, OperationContext, SignerKeyBinding, SigningAlgorithm,
        TrustRequirement, ValueBearingPurpose, ValueBearingSignRequest, VALUE_BEARING_POLICY_ID,
    },
    ConclaveError, ConclaveResult,
};
use alloy::primitives::{eip191_hash_message, keccak256, Address as EthAddress};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId, Signature},
    Message, PublicKey,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc20Transfer {
    pub to: String,
    pub amount: u128,
    pub contract_address: String,
}

pub struct EthereumManager<'a> {
    enclave: &'a dyn EnclaveManager,
}

impl<'a> EthereumManager<'a> {
    pub fn new(enclave: &'a dyn EnclaveManager) -> Self {
        Self { enclave }
    }

    pub fn get_address(&self, derivation_path: &str) -> ConclaveResult<String> {
        let pubkey_hex = self.enclave.get_public_key(derivation_path)?;
        Self::address_from_public_key_hex(&pubkey_hex)
    }

    pub fn sign_transaction_hash(
        &self,
        sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        let public_key = hex::decode(self.enclave.get_public_key(derivation_path)?)
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let request = ValueBearingSignRequest::new(
            OperationContext::new(
                "conxian/ethereum/transaction",
                ValueBearingPurpose::Transaction,
                sighash.to_vec(),
            )?,
            SigningAlgorithm::EcdsaSecp256k1,
            TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID)?,
            sighash,
            SignerKeyBinding::new(key_id, derivation_path, public_key)?,
            None,
        )?;

        let response = sign_value_bearing(self.enclave, request)?;
        let sign_response = response.sign_response();
        if !Self::verify_signature(
            sighash,
            &sign_response.signature_hex,
            &sign_response.public_key_hex,
        )? {
            return Err(ConclaveError::CryptoError(
                "Enclave returned an ECDSA signature that does not verify".to_string(),
            ));
        }
        Ok(sign_response.signature_hex.clone())
    }

    /// Prepares an ERC-20 transfer calldata.
    pub fn prepare_erc20_transfer(&self, transfer: Erc20Transfer) -> ConclaveResult<Vec<u8>> {
        let recipient = Self::decode_evm_address(&transfer.to, "recipient")?;
        // The contract is not part of calldata, but accepting an invalid target
        // here would make the transfer intent ambiguous at the caller boundary.
        Self::decode_evm_address(&transfer.contract_address, "contract")?;

        // transfer(address,uint256) selector: 0xa9059cbb
        let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];

        let mut padded_addr = vec![0u8; 32];
        padded_addr[12..].copy_from_slice(&recipient);
        data.extend(padded_addr);

        // Pad amount to 32 bytes
        let amount_bytes = transfer.amount.to_be_bytes();
        let mut padded_amount = vec![0u8; 32];
        padded_amount[32 - amount_bytes.len()..].copy_from_slice(&amount_bytes);
        data.extend(padded_amount);

        Ok(data)
    }

    /// Hashes a message using the EIP-191 personal-sign envelope.
    pub fn hash_message(message: &str) -> [u8; 32] {
        *eip191_hash_message(message.as_bytes()).as_ref()
    }

    /// Verifies a secp256k1 ECDSA signature over an already-hashed payload.
    ///
    /// Both compact 64-byte signatures and 65-byte signatures carrying a
    /// recovery id are accepted. Malformed encodings return an error; a valid
    /// signature for a different payload or public key returns `Ok(false)`.
    pub fn verify_signature(
        message_hash: [u8; 32],
        signature_hex: &str,
        public_key_hex: &str,
    ) -> ConclaveResult<bool> {
        let public_key = Self::parse_public_key(public_key_hex)?;
        let signature_bytes =
            hex::decode(signature_hex).map_err(|_| ConclaveError::InvalidPayload)?;
        let message = Message::from_digest(message_hash);

        match signature_bytes.len() {
            64 => {
                let compact: [u8; 64] = signature_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| ConclaveError::InvalidPayload)?;
                let signature =
                    Signature::from_compact(&compact).map_err(|_| ConclaveError::InvalidPayload)?;
                Ok(secp256k1::ecdsa::verify(&signature, message, &public_key).is_ok())
            }
            65 => {
                let compact: [u8; 64] = signature_bytes[..64]
                    .try_into()
                    .map_err(|_| ConclaveError::InvalidPayload)?;
                let recovery_id = Self::parse_recovery_id(signature_bytes[64])?;
                let signature = RecoverableSignature::from_compact(&compact, recovery_id)
                    .map_err(|_| ConclaveError::InvalidPayload)?;
                let recovered_key = signature
                    .recover_ecdsa(message)
                    .map_err(|_| ConclaveError::InvalidPayload)?;
                Ok(recovered_key == public_key)
            }
            _ => Err(ConclaveError::InvalidPayload),
        }
    }

    /// Verifies a signature over an EIP-191 personal-sign message.
    pub fn verify_message_signature(
        message: &str,
        signature_hex: &str,
        public_key_hex: &str,
    ) -> ConclaveResult<bool> {
        Self::verify_signature(Self::hash_message(message), signature_hex, public_key_hex)
    }

    pub fn sign_message(
        &self,
        message: &str,
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        let message_hash = Self::hash_message(message);

        let public_key = hex::decode(self.enclave.get_public_key(derivation_path)?)
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let request = ValueBearingSignRequest::new(
            OperationContext::new(
                "conxian/ethereum/message",
                ValueBearingPurpose::Authorization,
                message_hash.to_vec(),
            )?,
            SigningAlgorithm::EcdsaSecp256k1,
            TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID)?,
            message_hash,
            SignerKeyBinding::new(key_id, derivation_path, public_key)?,
            None,
        )?;

        let response = sign_value_bearing(self.enclave, request)?;
        let sign_response = response.sign_response();
        if !Self::verify_signature(
            message_hash,
            &sign_response.signature_hex,
            &sign_response.public_key_hex,
        )? {
            return Err(ConclaveError::CryptoError(
                "Enclave returned an ECDSA signature that does not verify".to_string(),
            ));
        }
        Ok(sign_response.signature_hex.clone())
    }

    fn address_from_public_key_hex(public_key_hex: &str) -> ConclaveResult<String> {
        let public_key = Self::parse_public_key(public_key_hex)?;
        let uncompressed = public_key.serialize_uncompressed();
        let hash = keccak256(&uncompressed[1..]);
        Ok(EthAddress::from_slice(&hash.as_slice()[12..]).to_string())
    }

    fn parse_public_key(public_key_hex: &str) -> ConclaveResult<PublicKey> {
        let public_key_bytes =
            hex::decode(public_key_hex).map_err(|_| ConclaveError::InvalidPayload)?;
        match public_key_bytes.len() {
            33 => {
                PublicKey::from_slice(&public_key_bytes).map_err(|_| ConclaveError::InvalidPayload)
            }
            65 if public_key_bytes[0] == 0x04 => {
                PublicKey::from_slice(&public_key_bytes).map_err(|_| ConclaveError::InvalidPayload)
            }
            _ => Err(ConclaveError::InvalidPayload),
        }
    }

    fn decode_evm_address(value: &str, field: &str) -> ConclaveResult<[u8; 20]> {
        let value = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .unwrap_or(value);
        if value.len() != 40 {
            return Err(ConclaveError::InvalidPayload);
        }
        let bytes = hex::decode(value).map_err(|_| ConclaveError::InvalidPayload)?;
        bytes
            .try_into()
            .map_err(|_| ConclaveError::CryptoError(format!("Invalid {field} address encoding")))
    }

    fn parse_recovery_id(value: u8) -> ConclaveResult<RecoveryId> {
        let normalized = match value {
            0..=3 => value,
            27..=30 => value - 27,
            _ => return Err(ConclaveError::InvalidPayload),
        };
        RecoveryId::try_from(i32::from(normalized)).map_err(|_| ConclaveError::InvalidPayload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::{SignRequest, SignResponse};
    use std::sync::Mutex;

    struct TestEnclave {
        secret_key: secp256k1::SecretKey,
        public_key_hex: String,
        last_request: Mutex<Option<SignRequest>>,
    }

    impl TestEnclave {
        fn new(compressed: bool) -> Self {
            let mut secret_key_bytes = [0u8; 32];
            secret_key_bytes[31] = 1;
            let secret_key =
                secp256k1::SecretKey::from_secret_bytes(secret_key_bytes).expect("test secret key");
            let public_key = secp256k1::PublicKey::from_secret_key(&secret_key);
            let public_key_bytes = if compressed {
                public_key.serialize().to_vec()
            } else {
                public_key.serialize_uncompressed().to_vec()
            };
            Self {
                secret_key,
                public_key_hex: hex::encode(public_key_bytes),
                last_request: Mutex::new(None),
            }
        }
    }

    impl EnclaveManager for TestEnclave {
        fn initialize(&self) -> ConclaveResult<()> {
            Ok(())
        }

        fn generate_key(&self, _key_id: &str) -> ConclaveResult<String> {
            Err(ConclaveError::Unsupported(
                "test enclave does not generate keys".to_string(),
            ))
        }

        fn get_public_key(&self, _derivation_path: &str) -> ConclaveResult<String> {
            Ok(self.public_key_hex.clone())
        }

        fn sign(&self, request: SignRequest) -> ConclaveResult<SignResponse> {
            let message_hash: [u8; 32] = request
                .message_hash
                .as_slice()
                .try_into()
                .map_err(|_| ConclaveError::InvalidPayload)?;
            *self
                .last_request
                .lock()
                .map_err(|_| ConclaveError::EnclaveFailure("Mutex poison".to_string()))? =
                Some(request);
            let signature =
                secp256k1::ecdsa::sign(Message::from_digest(message_hash), &self.secret_key);
            Ok(SignResponse {
                signature_hex: hex::encode(signature.serialize_compact()),
                public_key_hex: self.public_key_hex.clone(),
                device_attestation: None,
            })
        }
    }

    #[test]
    fn test_ethereum_address_uses_canonical_keccak() {
        let enclave = TestEnclave::new(true);
        let manager = EthereumManager::new(&enclave);

        assert_eq!(
            manager.get_address("m/44'/60'/0'/0/0").unwrap(),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );

        let uncompressed_enclave = TestEnclave::new(false);
        let uncompressed_manager = EthereumManager::new(&uncompressed_enclave);
        assert_eq!(
            uncompressed_manager
                .get_address("m/44'/60'/0'/0/0")
                .unwrap(),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
    }

    #[test]
    fn test_eip191_hash_and_signature_verification() {
        let enclave = TestEnclave::new(true);
        let manager = EthereumManager::new(&enclave);
        let message_hash = EthereumManager::hash_message("Hello World");
        let signature =
            secp256k1::ecdsa::sign(Message::from_digest(message_hash), &enclave.secret_key);

        assert_eq!(
            hex::encode(message_hash),
            "a1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2"
        );
        assert!(EthereumManager::verify_message_signature(
            "Hello World",
            &hex::encode(signature.serialize_compact()),
            &enclave.public_key_hex,
        )
        .unwrap());
        assert!(manager
            .sign_message("Hello World", "m/44'/60'/0'/0/0", "test-key")
            .is_err());
    }

    #[test]
    fn test_ethereum_rejects_malformed_addresses_and_signatures() {
        let enclave = TestEnclave::new(true);
        let manager = EthereumManager::new(&enclave);

        assert!(manager
            .prepare_erc20_transfer(Erc20Transfer {
                to: "0x123".to_string(),
                amount: 1,
                contract_address: enclave.public_key_hex.clone(),
            })
            .is_err());
        assert!(manager
            .prepare_erc20_transfer(Erc20Transfer {
                to: "0x0000000000000000000000000000000000000001".to_string(),
                amount: 1,
                contract_address: "0x123".to_string(),
            })
            .is_err());
        assert!(manager.get_address("m/44'/60'/0'/0/0").is_ok());

        let message_hash = EthereumManager::hash_message("message");
        let signature =
            secp256k1::ecdsa::sign(Message::from_digest(message_hash), &enclave.secret_key);
        let signature_hex = hex::encode(signature.serialize_compact());
        let mut malformed_signature = hex::decode(&signature_hex).unwrap();
        malformed_signature[0] ^= 1;
        assert!(!EthereumManager::verify_message_signature(
            "message",
            &hex::encode(malformed_signature),
            &enclave.public_key_hex,
        )
        .unwrap());
        assert!(!EthereumManager::verify_message_signature(
            "different message",
            &signature_hex,
            &enclave.public_key_hex,
        )
        .unwrap());
        assert!(manager
            .sign_message("message", "m/44'/60'/0'/0/0", "test-key")
            .is_err());
        assert!(
            EthereumManager::verify_signature([0u8; 32], "00", &enclave.public_key_hex,).is_err()
        );
        assert!(manager.get_address("m/44'/60'/0'/0/0").is_ok());
    }
}
