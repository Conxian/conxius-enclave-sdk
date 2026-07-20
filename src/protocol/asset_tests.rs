#[cfg(test)]
mod tests {
    use crate::config::Network;
    use crate::protocol::asset::{
        validate_evm_address, AssetIdentifier, AssetMetadata, AssetRegistry, Chain,
    };
    use crate::ConclaveError;

    #[test]
    fn test_rsk_bob_registration() {
        let registry = AssetRegistry::new();

        let rsk_btc = AssetIdentifier {
            chain: Chain::ROOTSTOCK,
            symbol: "RBTC".to_string(),
        };
        let bob_btc = AssetIdentifier {
            chain: Chain::BOB,
            symbol: "BTC".to_string(),
        };

        assert!(registry.get_asset(&rsk_btc).is_some());
        assert!(registry.get_asset(&bob_btc).is_some());

        assert_eq!(registry.get_asset(&rsk_btc).unwrap().name, "Smart Bitcoin");
        assert_eq!(registry.get_asset(&bob_btc).unwrap().name, "BOB Bitcoin");
    }

    #[test]
    fn test_expanded_bitcoin_network_registration() {
        let registry = AssetRegistry::new();

        let mezo_btc = AssetIdentifier {
            chain: Chain::MEZO,
            symbol: "BTC".to_string(),
        };
        let babylon_btc = AssetIdentifier {
            chain: Chain::BABYLON,
            symbol: "BTC".to_string(),
        };
        let botanix_btc = AssetIdentifier {
            chain: Chain::BOTANIX,
            symbol: "BTC".to_string(),
        };
        let citrea_btc = AssetIdentifier {
            chain: Chain::CITREA,
            symbol: "BTC".to_string(),
        };

        assert_eq!(registry.get_asset(&mezo_btc).unwrap().name, "Mezo Bitcoin");
        assert_eq!(
            registry.get_asset(&babylon_btc).unwrap().name,
            "Babylon Staked Bitcoin"
        );
        assert_eq!(
            registry.get_asset(&botanix_btc).unwrap().name,
            "Botanix Bitcoin"
        );
        assert_eq!(
            registry.get_asset(&citrea_btc).unwrap().name,
            "Citrea Bitcoin"
        );
        assert!(matches!(
            registry.validate_asset(&citrea_btc),
            Err(ConclaveError::Unsupported(_))
        ));
    }

    #[test]
    fn canonical_mainnet_contract_asset_is_active() {
        let registry = AssetRegistry::new();
        let usdc = AssetIdentifier {
            chain: Chain::ETHEREUM,
            symbol: "USDC".to_string(),
        };

        let metadata = registry.validate_asset(&usdc).unwrap();
        assert_eq!(metadata.decimals, 6);
        assert_eq!(
            metadata.contract_address.as_deref(),
            Some("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
        );
    }

    #[test]
    fn canonical_eurc_is_active() {
        let registry = AssetRegistry::new();
        let eurc = AssetIdentifier {
            chain: Chain::ETHEREUM,
            symbol: "EURC".to_string(),
        };

        assert!(registry.validate_asset(&eurc).is_ok());
    }

    #[test]
    fn canonical_tron_usdt_passes_base58check_validation() {
        let registry = AssetRegistry::new();
        let usdt = AssetIdentifier {
            chain: Chain::TRON,
            symbol: "USDT".to_string(),
        };

        assert!(registry.validate_asset(&usdt).is_ok());
    }

    #[test]
    fn every_builtin_active_asset_has_canonical_metadata() {
        let registry = AssetRegistry::new();

        for (id, metadata) in registry.list_assets() {
            if metadata.active {
                assert!(
                    registry.validate_asset(&id).is_ok(),
                    "active asset must validate: {}:{}",
                    id.chain,
                    id.symbol
                );
            }
        }
    }

    #[test]
    fn unregistered_asset_cannot_enter_value_bearing_paths() {
        let registry = AssetRegistry::new();
        let unknown = AssetIdentifier {
            chain: Chain::ETHEREUM,
            symbol: "NOT_REGISTERED".to_string(),
        };

        assert!(matches!(
            registry.validate_asset(&unknown),
            Err(ConclaveError::InvalidConfiguration(message))
                if message.contains("not registered")
        ));
    }

    #[test]
    fn canonical_usdc_address_checksum_is_valid() {
        let address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        assert_eq!(
            validate_evm_address(address).unwrap().to_checksum(None),
            address
        );
    }

    #[test]
    fn wrong_network_is_rejected_before_asset_use() {
        let registry = AssetRegistry::new();
        let usdc = AssetIdentifier {
            chain: Chain::ETHEREUM,
            symbol: "USDC".to_string(),
        };

        assert!(matches!(
            registry.validate_asset_on_network(&usdc, Network::Testnet),
            Err(ConclaveError::Unsupported(_))
        ));
    }

    #[test]
    fn malformed_checksum_cannot_be_registered_as_active() {
        let registry = AssetRegistry::new();
        let id = AssetIdentifier {
            chain: Chain::ETHEREUM,
            symbol: "USDC".to_string(),
        };
        let metadata = AssetMetadata {
            name: "USD Coin".to_string(),
            decimals: 6,
            contract_address: Some("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eb49".to_string()),
            active: true,
        };

        assert!(matches!(
            registry.register_asset(id, metadata),
            Err(ConclaveError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn wrong_canonical_address_cannot_be_registered_as_active() {
        let registry = AssetRegistry::new();
        let id = AssetIdentifier {
            chain: Chain::ETHEREUM,
            symbol: "USDC".to_string(),
        };
        let metadata = AssetMetadata {
            name: "USD Coin".to_string(),
            decimals: 6,
            contract_address: Some("0x0000000000000000000000000000000000000001".to_string()),
            active: true,
        };

        assert!(matches!(
            registry.register_asset(id, metadata),
            Err(ConclaveError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn placeholder_address_cannot_be_registered_as_active() {
        let registry = AssetRegistry::new();
        let id = AssetIdentifier {
            chain: Chain::ETHEREUM,
            symbol: "USDC".to_string(),
        };
        let metadata = AssetMetadata {
            name: "USD Coin".to_string(),
            decimals: 6,
            contract_address: Some("0x123".to_string()),
            active: true,
        };

        assert!(matches!(
            registry.register_asset(id, metadata),
            Err(ConclaveError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn missing_contract_address_is_quarantined() {
        let registry = AssetRegistry::new();
        let id = AssetIdentifier {
            chain: Chain::ETHEREUM,
            symbol: "UNVERIFIED".to_string(),
        };
        let metadata = AssetMetadata {
            name: "Unverified Token".to_string(),
            decimals: 18,
            contract_address: None,
            active: true,
        };

        assert!(matches!(
            registry.register_asset(id, metadata),
            Err(ConclaveError::InvalidConfiguration(_))
        ));
    }
}
