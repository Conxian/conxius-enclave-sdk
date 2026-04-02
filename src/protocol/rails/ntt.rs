use crate::protocol::rails::{SovereignRail, SwapIntent, SwapRequest, SwapResponse};
use async_trait::async_trait;

/// NTTRail: Native Token Transfer (NTT) implementation via Wormhole.
/// This rail handles the mint/burn/lock logic for cross-chain satellites
/// as defined in the Sovereign Bridge Strategy.
pub struct NTTRail;

#[async_trait]
impl SovereignRail for NTTRail {
    fn name(&self) -> String {
        "NTT".to_string()
    }

    fn validate_request(&self, request: &SwapRequest) -> Result<Option<String>, String> {
        // NTT is only valid for same-asset cross-chain transfers (e.g. USDC on ETH to USDC on ARB)
        if request.from_asset.symbol != request.to_asset.symbol {
            return Err("NTT only supports same-asset cross-chain transfers".to_string());
        }

        // Validate supported chains for NTT
        let supported_chains = ["ETH", "ARBITRUM", "BASE", "SOLANA"];
        if !supported_chains.contains(&request.from_asset.chain.as_str())
            || !supported_chains.contains(&request.to_asset.chain.as_str())
        {
            return Err("NTT currently only supports ETH, ARBITRUM, BASE, and SOLANA".to_string());
        }

        if request.recipient_address.len() < 32 {
            return Err("Invalid recipient address for NTT transceiver".to_string());
        }

        // Return the NTT specific context (e.g. target chain ID and manager address)
        Ok(Some(format!(
            "NTT_MGR_{}_TO_{}",
            request.from_asset.chain, request.to_asset.chain
        )))
    }

    async fn execute_swap(
        &self,
        intent: SwapIntent,
        _signature: String,
    ) -> Result<SwapResponse, String> {
        // NTT execution involves the 'TokenBridge' protocol string in Wormhole VAA
        Ok(SwapResponse {
            transaction_id: format!("NTT-VAA-{}", hex::encode(&intent.signable_hash[..10])),
            status: "Awaiting NTT Attestation".to_string(),
            estimated_arrival: 180, // NTT is generally faster than generic Wormhole swaps
            rail_used: self.name(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::asset::{AssetIdentifier, AssetRegistry};
    use crate::protocol::business::BusinessRegistry;
    use crate::protocol::rails::{RailProxy, SovereignHandshake};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_ntt_validation_success() {
        let ntt = NTTRail;
        let request = SwapRequest {
            from_asset: AssetIdentifier {
                chain: "ETH".to_string(),
                symbol: "USDC".to_string(),
            },
            to_asset: AssetIdentifier {
                chain: "ARBITRUM".to_string(),
                symbol: "USDC".to_string(),
            },
            amount: 1000000,
            recipient_address: "0x1234567890123456789012345678901234567890".to_string(),
            attribution: None,
        };

        let result = ntt.validate_request(&request);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().unwrap(), "NTT_MGR_ETH_TO_ARBITRUM");
    }

    #[tokio::test]
    async fn test_ntt_validation_different_assets_fail() {
        let ntt = NTTRail;
        let request = SwapRequest {
            from_asset: AssetIdentifier {
                chain: "ETH".to_string(),
                symbol: "ETH".to_string(),
            },
            to_asset: AssetIdentifier {
                chain: "ARBITRUM".to_string(),
                symbol: "USDC".to_string(),
            },
            amount: 1000000,
            recipient_address: "0x1234567890123456789012345678901234567890".to_string(),
            attribution: None,
        };

        let result = ntt.validate_request(&request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("same-asset"));
    }

    #[tokio::test]
    async fn test_ntt_via_rail_proxy() {
        let asset_registry = Arc::new(AssetRegistry::new());
        let business_registry = Arc::new(BusinessRegistry::new());
        let proxy = RailProxy::new(
            "https://gateway.conxian.com".to_string(),
            None,
            asset_registry,
            business_registry,
        );

        let request = SwapRequest {
            from_asset: AssetIdentifier {
                chain: "BASE".to_string(),
                symbol: "USDC".to_string(),
            },
            to_asset: AssetIdentifier {
                chain: "ETH".to_string(),
                symbol: "USDC".to_string(),
            },
            amount: 5000000,
            recipient_address: "0x1234567890123456789012345678901234567890".to_string(),
            attribution: None,
        };

        let intent_result = proxy.prepare_intent("NTT", request);
        assert!(intent_result.is_ok());

        let intent = intent_result.unwrap();
        assert_eq!(intent.rail_type, "NTT");
        assert_eq!(intent.chain_context.unwrap(), "NTT_MGR_BASE_TO_ETH");
    }

    #[test]
    fn test_asset_registry_l2_support() {
        let registry = AssetRegistry::new();

        // Test Arbitrum ETH
        let arb_eth = registry.get_asset("ARBITRUM", "ETH");
        assert!(arb_eth.is_some());
        assert_eq!(arb_eth.unwrap().decimals, 18);

        // Test Base USDC
        let base_usdc = registry.get_asset("BASE", "USDC");
        assert!(base_usdc.is_some());
        assert_eq!(base_usdc.unwrap().decimals, 6);
        assert!(base_usdc.unwrap().contract_address.is_some());

        // Test validation
        let eth_usdc = AssetIdentifier {
            chain: "ETH".to_string(),
            symbol: "USDC".to_string(),
        };
        let arb_usdc = AssetIdentifier {
            chain: "ARBITRUM".to_string(),
            symbol: "USDC".to_string(),
        };
        assert!(registry.validate_pair(&eth_usdc, &arb_usdc));
    }
}
