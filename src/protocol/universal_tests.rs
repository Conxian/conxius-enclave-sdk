#[cfg(test)]
mod tests {
    use crate::enclave::cloud::CloudEnclave;
    use crate::protocol::asset::{AssetIdentifier, AssetRegistry, Chain};
    use crate::protocol::ethereum::EthereumManager;
    use crate::protocol::solana::SolanaManager;
    use std::sync::Arc;

    #[test]
    fn test_ethereum_address_derivation() {
        let enclave = Arc::new(CloudEnclave::new("test".to_string()).unwrap());
        let eth_mgr = EthereumManager::new(enclave);
        let address = eth_mgr.get_address("m/44'/60'/0'/0/0").unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_solana_address_retrieval() {
        let enclave = Arc::new(CloudEnclave::new("test".to_string()).unwrap());
        let sol_mgr = SolanaManager::new(enclave);
        let address = sol_mgr.get_address("m/44'/501'/0'/0'").unwrap();
        // For simulation, it returns hex pubkey
        assert!(!address.is_empty());
    }

    #[test]
    fn test_universal_asset_registry() {
        let registry = AssetRegistry::new();
        let eth = AssetIdentifier {
            chain: Chain::ETHEREUM,
            symbol: "ETH".to_string(),
        };
        let sol = AssetIdentifier {
            chain: Chain::SOLANA,
            symbol: "SOL".to_string(),
        };
        let pol = AssetIdentifier {
            chain: Chain::POLYGON,
            symbol: "POL".to_string(),
        };
        let bsc = AssetIdentifier {
            chain: Chain::BSC,
            symbol: "BNB".to_string(),
        };

        assert!(registry.get_asset(&eth).is_some());
        assert!(registry.get_asset(&sol).is_some());
        assert!(registry.get_asset(&pol).is_some());
        assert!(registry.get_asset(&bsc).is_some());
    }
}
