use crate::{
    enclave::{sign_value_bearing, EnclaveManager, SignRequest, SigningAlgorithm},
    ConclaveError, ConclaveResult,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;

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
        let pubkey_bytes = hex::decode(pubkey_hex).map_err(|_| ConclaveError::InvalidPayload)?;

        // Simple Keccak-256 derived address (using Sha256 for simulation if Keccak not available)
        let mut hasher = sha2::Sha256::new();
        hasher.update(&pubkey_bytes[1..]);
        let hash = hasher.finalize();
        Ok(format!("0x{}", hex::encode(&hash[12..])))
    }

    pub fn sign_transaction_hash(
        &self,
        sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        let request = SignRequest {
            algorithm: SigningAlgorithm::EcdsaSecp256k1,
            message_hash: sighash.to_vec(),
            derivation_path: derivation_path.to_string(),
            key_id: key_id.to_string(),
            taproot_tweak: None,
        };

        let response = sign_value_bearing(self.enclave, request)?;
        Ok(response.signature_hex)
    }

    /// Prepares an ERC-20 transfer calldata.
    pub fn prepare_erc20_transfer(&self, transfer: Erc20Transfer) -> Vec<u8> {
        // transfer(address,uint256) selector: 0xa9059cbb
        let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];

        // Pad address to 32 bytes
        let addr_bytes = hex::decode(transfer.to.trim_start_matches("0x")).unwrap_or_default();
        let mut padded_addr = vec![0u8; 32];
        padded_addr[32 - addr_bytes.len()..].copy_from_slice(&addr_bytes);
        data.extend(padded_addr);

        // Pad amount to 32 bytes
        let amount_bytes = transfer.amount.to_be_bytes();
        let mut padded_amount = vec![0u8; 32];
        padded_amount[32 - amount_bytes.len()..].copy_from_slice(&amount_bytes);
        data.extend(padded_amount);

        data
    }

    pub fn sign_message(
        &self,
        message: &str,
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut hasher = sha2::Sha256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(message.as_bytes());
        let message_hash = hasher.finalize().to_vec();

        let request = SignRequest {
            algorithm: SigningAlgorithm::EcdsaSecp256k1,
            message_hash,
            derivation_path: derivation_path.to_string(),
            key_id: key_id.to_string(),
            taproot_tweak: None,
        };

        let response = sign_value_bearing(self.enclave, request)?;
        Ok(response.signature_hex)
    }
}
