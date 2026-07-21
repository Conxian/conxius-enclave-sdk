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

/// The chain binding and recovery parity encoded by an EIP-155 `v` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Eip155Recovery {
    pub chain_id: u64,
    pub y_parity: u8,
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

    /// Signs a caller-supplied, precomputed 32-byte transaction digest.
    ///
    /// This method does not serialize a transaction and does not apply
    /// EIP-155, EIP-1559, or EIP-712 rules. The caller is responsible for
    /// canonical transaction encoding and chain-id binding before supplying
    /// the digest.
    pub fn sign_transaction_hash(
        &self,
        transaction_digest: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        let public_key = hex::decode(self.enclave.get_public_key(derivation_path)?)
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let request = ValueBearingSignRequest::new(
            OperationContext::new(
                "conxian/ethereum/transaction",
                ValueBearingPurpose::Transaction,
                transaction_digest.to_vec(),
            )?,
            SigningAlgorithm::EcdsaSecp256k1,
            TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID)?,
            transaction_digest,
            SignerKeyBinding::new(key_id, derivation_path, public_key)?,
            None,
        )?;

        let response = sign_value_bearing(self.enclave, request)?;
        let sign_response = response.sign_response();
        if !Self::verify_signature(
            transaction_digest,
            &sign_response.signature_hex,
            &sign_response.public_key_hex,
        )? {
            return Err(ConclaveError::CryptoError(
                "Enclave returned an ECDSA signature that does not verify".to_string(),
            ));
        }
        Ok(sign_response.signature_hex.clone())
    }

    /// Validates an ERC-20 recipient and contract address and returns only
    /// `transfer(address,uint256)` calldata.
    ///
    /// The contract address is validated but is not encoded in the returned
    /// bytes. This method does not construct a transaction envelope, bind a
    /// chain ID, estimate gas, or broadcast anything.
    pub fn prepare_erc20_transfer(&self, transfer: Erc20Transfer) -> ConclaveResult<Vec<u8>> {
        let recipient = Self::decode_evm_address(&transfer.to, "recipient")?;
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

    /// Hashes UTF-8 message text using the EIP-191 personal-sign envelope.
    pub fn hash_message(message: &str) -> [u8; 32] {
        Self::hash_message_bytes(message.as_bytes())
    }

    /// Hashes arbitrary bytes using the EIP-191 personal-sign envelope.
    ///
    /// The message length is measured in bytes, so this method is safe for
    /// binary payloads as well as UTF-8 text.
    pub fn hash_message_bytes(message: &[u8]) -> [u8; 32] {
        *eip191_hash_message(message).as_ref()
    }

    /// Verifies a secp256k1 ECDSA signature over an already-hashed payload.
    ///
    /// A 64-byte input is the ordinary compact `r || s` encoding, not the
    /// EIP-2098 `r || yParityAndS` encoding. A 65-byte input is the Ethereum
    /// personal-sign form `r || s || v`, where `v` must be `0`, `1`, `27`, or
    /// `28`. All accepted signatures must use canonical low-S form.
    ///
    /// Malformed encodings return an error. A well-formed signature for a
    /// different payload or public key, a high-S signature, or a recoverable
    /// signature whose parity does not match the supplied key returns
    /// `Ok(false)`.
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
                let (_, signature) = Self::parse_compact_signature(&signature_bytes)?;
                if !Self::is_low_s(&signature) {
                    return Ok(false);
                }
                Ok(secp256k1::ecdsa::verify(&signature, message, &public_key).is_ok())
            }
            65 => {
                let recovery_id = Self::parse_recovery_id(signature_bytes[64])?;
                let (compact, signature) = Self::parse_compact_signature(&signature_bytes[..64])?;
                if !Self::is_low_s(&signature) {
                    return Ok(false);
                }
                Self::recover_and_match(message, &compact, recovery_id, &public_key)
            }
            _ => Err(ConclaveError::InvalidPayload),
        }
    }

    /// Verifies an EIP-2098 compact signature over an already-hashed payload.
    ///
    /// Unlike [`Self::verify_signature`], this method interprets the second
    /// 32-byte word as `yParityAndS`: the high bit carries y-parity and the
    /// remaining 255 bits carry the canonical low-S scalar.
    pub fn verify_eip2098_signature(
        message_hash: [u8; 32],
        signature_hex: &str,
        public_key_hex: &str,
    ) -> ConclaveResult<bool> {
        let public_key = Self::parse_public_key(public_key_hex)?;
        let signature_bytes =
            hex::decode(signature_hex).map_err(|_| ConclaveError::InvalidPayload)?;
        if signature_bytes.len() != 64 {
            return Err(ConclaveError::InvalidPayload);
        }

        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(&signature_bytes[..32]);
        compact[32..].copy_from_slice(&signature_bytes[32..]);
        let y_parity = compact[32] >> 7;
        compact[32] &= 0x7f;

        let (compact, signature) = Self::parse_compact_signature(&compact)?;
        if !Self::is_low_s(&signature) {
            return Ok(false);
        }
        let recovery_id = match y_parity {
            0 => RecoveryId::Zero,
            1 => RecoveryId::One,
            _ => return Err(ConclaveError::InvalidPayload),
        };
        Self::recover_and_match(
            Message::from_digest(message_hash),
            &compact,
            recovery_id,
            &public_key,
        )
    }

    /// Decodes and validates an EIP-155 transaction `v` value for a specific
    /// nonzero chain ID.
    ///
    /// This helper is intentionally separate from EIP-191 personal-message
    /// verification. It accepts only `v >= 35` and never normalizes legacy,
    /// personal-sign, or unbound parity values.
    pub fn decode_eip155_v(v: u64, expected_chain_id: u64) -> ConclaveResult<Eip155Recovery> {
        if expected_chain_id == 0 {
            return Err(ConclaveError::InvalidPayload);
        }
        if v < 35 {
            return Err(ConclaveError::InvalidPayload);
        }

        let adjusted = v.checked_sub(35).ok_or(ConclaveError::InvalidPayload)?;
        let y_parity = u8::try_from(adjusted % 2).map_err(|_| ConclaveError::InvalidPayload)?;
        let chain_id = adjusted
            .checked_div(2)
            .ok_or(ConclaveError::InvalidPayload)?;
        if chain_id == 0 || chain_id != expected_chain_id {
            return Err(ConclaveError::InvalidPayload);
        }

        let canonical_v = chain_id
            .checked_mul(2)
            .and_then(|value| value.checked_add(35))
            .and_then(|value| value.checked_add(u64::from(y_parity)))
            .ok_or(ConclaveError::InvalidPayload)?;
        if canonical_v != v {
            return Err(ConclaveError::InvalidPayload);
        }

        Ok(Eip155Recovery { chain_id, y_parity })
    }

    /// Verifies a signature over an EIP-191 personal-sign message.
    pub fn verify_message_signature(
        message: &str,
        signature_hex: &str,
        public_key_hex: &str,
    ) -> ConclaveResult<bool> {
        Self::verify_signature(Self::hash_message(message), signature_hex, public_key_hex)
    }

    /// Verifies a signature over arbitrary bytes using EIP-191 personal-sign
    /// hashing.
    pub fn verify_message_signature_bytes(
        message: &[u8],
        signature_hex: &str,
        public_key_hex: &str,
    ) -> ConclaveResult<bool> {
        Self::verify_signature(
            Self::hash_message_bytes(message),
            signature_hex,
            public_key_hex,
        )
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
        if !value.starts_with("0x") {
            return Err(ConclaveError::InvalidPayload);
        }
        let body = &value[2..];
        if body.len() != 40 {
            return Err(ConclaveError::InvalidPayload);
        }

        let all_lower = body
            .bytes()
            .all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_lowercase());
        let all_upper = body
            .bytes()
            .all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_uppercase());

        let address = if all_lower || all_upper {
            value.parse::<EthAddress>().map_err(|_| {
                ConclaveError::CryptoError(format!("Invalid {field} address encoding"))
            })?
        } else {
            EthAddress::parse_checksummed(value, None).map_err(|_| {
                ConclaveError::CryptoError(format!("Invalid {field} EIP-55 checksum"))
            })?
        };

        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(address.as_slice());
        Ok(bytes)
    }

    fn parse_compact_signature(signature_bytes: &[u8]) -> ConclaveResult<([u8; 64], Signature)> {
        let compact: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let signature =
            Signature::from_compact(&compact).map_err(|_| ConclaveError::InvalidPayload)?;
        Ok((compact, signature))
    }

    fn is_low_s(signature: &Signature) -> bool {
        let mut normalized = *signature;
        normalized.normalize_s();
        normalized == *signature
    }

    fn recover_and_match(
        message: Message,
        compact: &[u8; 64],
        recovery_id: RecoveryId,
        public_key: &PublicKey,
    ) -> ConclaveResult<bool> {
        let signature = RecoverableSignature::from_compact(compact, recovery_id)
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let recovered_key = signature
            .recover_ecdsa(message)
            .map_err(|_| ConclaveError::InvalidPayload)?;
        Ok(recovered_key == *public_key)
    }

    fn parse_recovery_id(value: u8) -> ConclaveResult<RecoveryId> {
        let normalized = match value {
            0 | 27 => 0,
            1 | 28 => 1,
            _ => return Err(ConclaveError::InvalidPayload),
        };
        RecoveryId::try_from(normalized).map_err(|_| ConclaveError::InvalidPayload)
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

    fn recoverable_signature(
        message_hash: [u8; 32],
        secret_key: &secp256k1::SecretKey,
    ) -> (u8, [u8; 64]) {
        let signature = RecoverableSignature::sign_ecdsa_recoverable(
            Message::from_digest(message_hash),
            secret_key,
        );
        let (recovery_id, compact) = signature.serialize_compact();
        (recovery_id.to_u8(), compact)
    }

    fn signature_with_v(compact: [u8; 64], v: u8) -> String {
        let mut signature = compact.to_vec();
        signature.push(v);
        hex::encode(signature)
    }

    fn eip2098_signature(compact: [u8; 64], y_parity: u8) -> String {
        let mut signature = compact;
        signature[32] |= y_parity << 7;
        hex::encode(signature)
    }

    fn high_s_signature(compact: [u8; 64]) -> [u8; 64] {
        let mut high_s = compact;
        let mut borrow = 0i16;
        for index in (0..32).rev() {
            let difference = i16::from(secp256k1::constants::CURVE_ORDER[index])
                - i16::from(compact[32 + index])
                - borrow;
            if difference < 0 {
                high_s[32 + index] = (difference + 256) as u8;
                borrow = 1;
            } else {
                high_s[32 + index] = difference as u8;
                borrow = 0;
            }
        }
        high_s
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
    fn test_keccak_and_eip191_binary_safe_vectors() {
        // Keccak-256 known answers: https://keccak.team/keccak.html
        assert_eq!(
            hex::encode(keccak256(b"").as_slice()),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex::encode(keccak256(b"abc").as_slice()),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );

        // EIP-191 personal-sign envelope: https://eips.ethereum.org/EIPS/eip-191
        assert_eq!(
            hex::encode(&EthereumManager::hash_message("")[..]),
            "5f35dce98ba4fba25530a026ed80b2cecdaa31091ba4958b99b52ea1d068adad"
        );
        assert_eq!(
            hex::encode(&EthereumManager::hash_message("☃")[..]),
            "c3c5c86a41ca7980a20b232ec3aca79d1ee2c239086478ebbc1c187f3f8eadaf"
        );
        assert_eq!(
            hex::encode(&EthereumManager::hash_message_bytes(&[0xff, 0x00, 0x80, 0x01])[..]),
            "6328fbedb0b7c6f5b494ca06cbf948656c5668df976b99b10682a9be65d6f266"
        );

        let enclave = TestEnclave::new(true);
        let binary_message = [0xff, 0x00, 0x80, 0x01];
        let binary_signature = secp256k1::ecdsa::sign(
            Message::from_digest(EthereumManager::hash_message_bytes(&binary_message)),
            &enclave.secret_key,
        );
        assert!(EthereumManager::verify_message_signature_bytes(
            &binary_message,
            &hex::encode(binary_signature.serialize_compact()),
            &enclave.public_key_hex,
        )
        .expect("binary EIP-191 signature"));
    }

    #[test]
    fn test_eip55_address_vectors_and_strict_input() {
        // Official EIP-55 test cases: https://eips.ethereum.org/EIPS/eip-55#test-cases
        let enclave = TestEnclave::new(true);
        let manager = EthereumManager::new(&enclave);
        let contract = "0x0000000000000000000000000000000000000123";
        let valid_addresses = [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ];

        for address in valid_addresses {
            assert!(manager
                .prepare_erc20_transfer(Erc20Transfer {
                    to: address.to_string(),
                    amount: 1,
                    contract_address: contract.to_string(),
                })
                .is_ok());
        }

        assert!(manager
            .prepare_erc20_transfer(Erc20Transfer {
                to: "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed".to_string(),
                amount: 1,
                contract_address: contract.to_string(),
            })
            .is_ok());
        assert!(manager
            .prepare_erc20_transfer(Erc20Transfer {
                to: "0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED".to_string(),
                amount: 1,
                contract_address: contract.to_string(),
            })
            .is_ok());

        let mut mutated = valid_addresses[0].as_bytes().to_vec();
        mutated[4] = b'a';
        assert!(matches!(
            manager.prepare_erc20_transfer(Erc20Transfer {
                to: String::from_utf8(mutated).expect("ASCII vector"),
                amount: 1,
                contract_address: contract.to_string(),
            }),
            Err(ConclaveError::CryptoError(message))
                if message.contains("EIP-55 checksum")
        ));

        assert!(matches!(
            manager.prepare_erc20_transfer(Erc20Transfer {
                to: valid_addresses[0].to_string(),
                amount: 1,
                contract_address: "0x5aaeb6053f3e94c9b9a09f33669435E7Ef1BeAed".to_string(),
            }),
            Err(ConclaveError::CryptoError(message))
                if message.contains("EIP-55 checksum")
        ));

        for malformed in [
            "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0X5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAedd",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeG",
        ] {
            assert!(manager
                .prepare_erc20_transfer(Erc20Transfer {
                    to: malformed.to_string(),
                    amount: 1,
                    contract_address: contract.to_string(),
                })
                .is_err());
        }
    }

    #[test]
    fn test_compact_and_recoverable_signature_canonicality() {
        let enclave = TestEnclave::new(true);
        let message_hash = EthereumManager::hash_message("canonical signature");
        let compact_signature =
            secp256k1::ecdsa::sign(Message::from_digest(message_hash), &enclave.secret_key)
                .serialize_compact();
        let compact_hex = hex::encode(compact_signature);

        assert!(EthereumManager::verify_signature(
            message_hash,
            &compact_hex,
            &enclave.public_key_hex,
        )
        .expect("valid compact signature"));

        let high_s = high_s_signature(compact_signature);
        assert_eq!(
            EthereumManager::verify_signature(
                message_hash,
                &hex::encode(high_s),
                &enclave.public_key_hex,
            ),
            Ok(false)
        );

        let (recovery_id, recoverable_compact) =
            recoverable_signature(message_hash, &enclave.secret_key);
        assert!(recovery_id <= 1, "test vector must use Ethereum parity");
        let personal_v = recovery_id + 27;
        assert!(EthereumManager::verify_signature(
            message_hash,
            &signature_with_v(recoverable_compact, personal_v),
            &enclave.public_key_hex,
        )
        .expect("valid recoverable signature"));
        assert!(EthereumManager::verify_eip2098_signature(
            message_hash,
            &eip2098_signature(recoverable_compact, recovery_id),
            &enclave.public_key_hex,
        )
        .expect("valid EIP-2098 signature"));

        let flipped_v = if personal_v == 27 { 28 } else { 27 };
        assert_eq!(
            EthereumManager::verify_signature(
                message_hash,
                &signature_with_v(recoverable_compact, flipped_v),
                &enclave.public_key_hex,
            ),
            Ok(false)
        );

        for invalid_v in [2, 3, 29, 30, 37, 38] {
            assert!(matches!(
                EthereumManager::verify_signature(
                    message_hash,
                    &signature_with_v(recoverable_compact, invalid_v),
                    &enclave.public_key_hex,
                ),
                Err(ConclaveError::InvalidPayload)
            ));
        }

        let other_key =
            secp256k1::SecretKey::from_secret_bytes([2u8; 32]).expect("test key is in range");
        let other_public_key =
            hex::encode(secp256k1::PublicKey::from_secret_key(&other_key).serialize());
        assert_eq!(
            EthereumManager::verify_signature(
                message_hash,
                &signature_with_v(recoverable_compact, personal_v),
                &other_public_key,
            ),
            Ok(false)
        );

        assert!(
            EthereumManager::verify_signature(message_hash, "00", "not-a-public-key",).is_err()
        );
    }

    #[test]
    fn test_eip2098_official_and_negative_vectors() {
        // Official EIP-2098 examples: https://eips.ethereum.org/EIPS/eip-2098#test-cases
        let secret_key = secp256k1::SecretKey::from_secret_bytes([
            0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78,
            0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
            0x78, 0x90, 0x12, 0x34,
        ])
        .expect("official test key is in range");
        let public_key = hex::encode(
            secp256k1::PublicKey::from_secret_key(&secret_key).serialize_uncompressed(),
        );

        let hello_signature = concat_hex(
            "68a020a209d3d56c46f38cc50a33f704f4a9a10a59377f8dd762ac66910e9b90",
            "7e865ad05c4035ab5792787d4a0297a43617ae897930a6fe4d822b8faea52064",
        );
        assert!(EthereumManager::verify_eip2098_signature(
            EthereumManager::hash_message("Hello World"),
            &hello_signature,
            &public_key,
        )
        .expect("official EIP-2098 vector"));

        let smaller_world_signature = concat_hex(
            "9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76",
            "939c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793",
        );
        assert!(EthereumManager::verify_eip2098_signature(
            EthereumManager::hash_message("It's a small(er) world"),
            &smaller_world_signature,
            &public_key,
        )
        .expect("official EIP-2098 vector"));
        assert_eq!(
            EthereumManager::verify_signature(
                EthereumManager::hash_message("It's a small(er) world"),
                &smaller_world_signature,
                &public_key,
            ),
            Ok(false)
        );

        let mut wrong_key = [2u8; 32];
        wrong_key[31] = 2;
        let wrong_public_key = hex::encode(
            secp256k1::PublicKey::from_secret_key(
                &secp256k1::SecretKey::from_secret_bytes(wrong_key).expect("test key is in range"),
            )
            .serialize(),
        );
        assert_eq!(
            EthereumManager::verify_eip2098_signature(
                EthereumManager::hash_message("Hello World"),
                &hello_signature,
                &wrong_public_key,
            ),
            Ok(false)
        );

        let mut malformed = [0u8; 64];
        malformed[..32].copy_from_slice(&[1u8; 32]);
        assert!(matches!(
            EthereumManager::verify_eip2098_signature(
                [0u8; 32],
                &hex::encode(malformed),
                &public_key,
            ),
            Err(ConclaveError::InvalidPayload)
        ));
        assert!(EthereumManager::verify_eip2098_signature([0u8; 32], "00", &public_key,).is_err());

        let high_s =
            hex::decode("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1")
                .expect("fixed high-S boundary");
        let mut high_s_signature = [0u8; 64];
        high_s_signature[..32].copy_from_slice(&[1u8; 32]);
        high_s_signature[32..].copy_from_slice(&high_s);
        high_s_signature[32] |= 0x80;
        assert_eq!(
            EthereumManager::verify_eip2098_signature(
                [0u8; 32],
                &hex::encode(high_s_signature),
                &public_key,
            ),
            Ok(false)
        );
    }

    #[test]
    fn test_eip155_chain_id_decoder_is_context_bound() {
        // Official EIP-155 example uses chain ID 1 and v=37/38:
        // https://eips.ethereum.org/EIPS/eip-155#example
        assert_eq!(
            EthereumManager::decode_eip155_v(37, 1),
            Ok(Eip155Recovery {
                chain_id: 1,
                y_parity: 0,
            })
        );
        assert_eq!(
            EthereumManager::decode_eip155_v(38, 1),
            Ok(Eip155Recovery {
                chain_id: 1,
                y_parity: 1,
            })
        );

        for invalid_v in [0, 1, 27, 28, 34, 35, 36] {
            assert!(EthereumManager::decode_eip155_v(invalid_v, 1).is_err());
        }
        assert!(EthereumManager::decode_eip155_v(37, 0).is_err());
        assert!(EthereumManager::decode_eip155_v(37, 2).is_err());

        let max_chain_id = (u64::MAX - 35) / 2;
        assert_eq!(
            EthereumManager::decode_eip155_v(u64::MAX, max_chain_id),
            Ok(Eip155Recovery {
                chain_id: max_chain_id,
                y_parity: 0,
            })
        );
        assert!(EthereumManager::decode_eip155_v(u64::MAX, max_chain_id - 1).is_err());
    }

    fn concat_hex(left: &str, right: &str) -> String {
        let mut value = String::with_capacity(left.len() + right.len());
        value.push_str(left);
        value.push_str(right);
        value
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
