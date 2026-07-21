use crate::protocol::asset::{AssetIdentifier, AssetRegistry};
use crate::{ConclaveError, ConclaveResult};
use alloy::primitives::{Address, U256};
use alloy::providers::ProviderBuilder;
use alloy::sol;
use std::sync::Arc;

sol! {
    #[sol(rpc)]
    interface IERC20 {
        function balanceOf(address account) external view returns (uint256);
        function symbol() external view returns (string);
        function name() external view returns (string);
        function decimals() external view returns (uint8);
    }
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

        let rpc_url_parsed = rpc_url.parse().map_err(|_| ConclaveError::InvalidPayload)?;

        let provider = ProviderBuilder::new().connect_http(rpc_url_parsed);

        let contract = IERC20::new(contract_addr, &provider);

        let balance = contract
            .balanceOf(user_addr)
            .call()
            .await
            .map_err(|_| ConclaveError::InvalidPayload)?;

        // Based on compiler error, balance is already U256 (or IERC20::balanceOfReturn which behaves as U256 if it has no _0?)
        // Actually, let's try using the Return struct explicitly if possible, or just the value.
        // If the compiler said "no field _0 on type Uint", then it's a Uint.
        Ok(balance)
    }

    pub async fn get_token_metadata(
        &self,
        contract_address: &str,
        rpc_url: &str,
    ) -> ConclaveResult<(String, String, u8)> {
        let rpc_url_parsed = rpc_url.parse().map_err(|_| ConclaveError::InvalidPayload)?;

        let provider = ProviderBuilder::new().connect_http(rpc_url_parsed);

        let address: Address = contract_address
            .parse()
            .map_err(|_| ConclaveError::InvalidPayload)?;

        let contract = IERC20::new(address, &provider);

        let name = contract
            .name()
            .call()
            .await
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let symbol = contract
            .symbol()
            .call()
            .await
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let decimals = contract
            .decimals()
            .call()
            .await
            .map_err(|_| ConclaveError::InvalidPayload)?;

        Ok((name, symbol, decimals))
    }
}
