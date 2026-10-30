use crate::protocol::asset::{AssetIdentifier, AssetRegistry};
use crate::{ConclaveError, ConclaveResult};
use alloy_primitives::{Address, U256};
use serde_json::Value;
use std::sync::Arc;

// ERC-20 function selectors (keccak256 of the canonical signatures, first 4 bytes).
const ERC20_BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
const ERC20_NAME: [u8; 4] = [0x06, 0xfd, 0xde, 0x03];
const ERC20_SYMBOL: [u8; 4] = [0x95, 0xd8, 0x9b, 0x41];
const ERC20_DECIMALS: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];

async fn eth_call(rpc_url: &str, to: &Address, calldata: &[u8]) -> ConclaveResult<Vec<u8>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [
            { "to": to.to_string(), "data": format!("0x{}", hex::encode(calldata)) },
            "latest"
        ],
        "id": 1,
    });

    let client = reqwest::Client::new();
    let resp: Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| ConclaveError::NetworkError(format!("eth_call request failed: {e}")))?
        .json()
        .await
        .map_err(|e| ConclaveError::NetworkError(format!("eth_call response parse failed: {e}")))?;

    if let Some(err) = resp.get("error") {
        return Err(ConclaveError::NetworkError(format!(
            "eth_call RPC error: {err}"
        )));
    }

    let result = resp
        .get("result")
        .and_then(Value::as_str)
        .ok_or_else(|| ConclaveError::NetworkError("eth_call missing result".to_string()))?;

    let bare = result.strip_prefix("0x").unwrap_or(result);
    hex::decode(bare)
        .map_err(|_| ConclaveError::NetworkError("eth_call invalid hex result".to_string()))
}

fn decode_uint256(bytes: &[u8]) -> ConclaveResult<U256> {
    if bytes.len() < 32 {
        return Err(ConclaveError::InvalidPayload);
    }
    Ok(U256::from_be_slice(&bytes[..32]))
}

fn decode_uint8(bytes: &[u8]) -> ConclaveResult<u8> {
    if bytes.len() < 32 {
        return Err(ConclaveError::InvalidPayload);
    }
    Ok(bytes[31])
}

fn decode_abi_string(bytes: &[u8]) -> ConclaveResult<String> {
    if bytes.len() < 64 {
        return Err(ConclaveError::InvalidPayload);
    }
    let offset = usize::from_be_bytes(
        bytes[..32]
            .try_into()
            .map_err(|_| ConclaveError::InvalidPayload)?,
    );
    let len_start = offset
        .checked_add(32)
        .ok_or(ConclaveError::InvalidPayload)?;
    if len_start > bytes.len() {
        return Err(ConclaveError::InvalidPayload);
    }
    let length = usize::from_be_bytes(
        bytes[offset..len_start]
            .try_into()
            .map_err(|_| ConclaveError::InvalidPayload)?,
    );
    let data_end = len_start
        .checked_add(length)
        .ok_or(ConclaveError::InvalidPayload)?;
    if data_end > bytes.len() {
        return Err(ConclaveError::InvalidPayload);
    }
    String::from_utf8(bytes[len_start..data_end].to_vec())
        .map_err(|_| ConclaveError::InvalidPayload)
}

pub struct StablecoinOrchestrator {
    asset_registry: Arc<AssetRegistry>,
}

impl StablecoinOrchestrator {
    pub fn new(asset_registry: Arc<AssetRegistry>) -> Self {
        Self { asset_registry }
    }

    pub async fn get_stablecoin_balance(
        &self,
        user_address: &str,
        asset_id: &AssetIdentifier,
        rpc_url: &str,
    ) -> ConclaveResult<U256> {
        let metadata = self.asset_registry.validate_asset(asset_id)?;
        let contract_addr_str = metadata
            .contract_address
            .ok_or(ConclaveError::InvalidPayload)?;
        let user_addr: Address = user_address
            .parse()
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let contract_addr: Address = contract_addr_str
            .parse()
            .map_err(|_| ConclaveError::InvalidPayload)?;

        let mut calldata = Vec::with_capacity(36);
        calldata.extend_from_slice(&ERC20_BALANCE_OF);
        let mut arg = [0u8; 32];
        arg[12..].copy_from_slice(user_addr.as_slice());
        calldata.extend_from_slice(&arg);

        let result = eth_call(rpc_url, &contract_addr, &calldata).await?;
        decode_uint256(&result)
    }

    pub async fn get_token_metadata(
        &self,
        contract_address: &str,
        rpc_url: &str,
    ) -> ConclaveResult<(String, String, u8)> {
        let address: Address = contract_address
            .parse()
            .map_err(|_| ConclaveError::InvalidPayload)?;

        let name = decode_abi_string(&eth_call(rpc_url, &address, &ERC20_NAME).await?)?;
        let symbol = decode_abi_string(&eth_call(rpc_url, &address, &ERC20_SYMBOL).await?)?;
        let decimals = decode_uint8(&eth_call(rpc_url, &address, &ERC20_DECIMALS).await?)?;

        Ok((name, symbol, decimals))
    }
}
