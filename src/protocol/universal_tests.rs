#[cfg(test)]
mod tests {
    use crate::enclave::cloud::CloudEnclave;
    use crate::protocol::asset::{AssetIdentifier, AssetRegistry, Chain};
    use crate::protocol::chain_abstraction::{ChainAbstractionService, ChainSignatureRequest};
    use crate::protocol::ethereum::EthereumManager;
    use crate::protocol::solana::SolanaManager;
    use std::sync::Arc;

    #[test]
    fn test_ethereum_address_derivation() {
        let enclave = CloudEnclave::new("test".to_string()).unwrap();
        let eth_mgr = EthereumManager::new(&enclave);
        let address = eth_mgr.get_address("m/44'/60'/0'/0/0").unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_solana_address_retrieval() {
        let enclave = CloudEnclave::new("test".to_string()).unwrap();
        let sol_mgr = SolanaManager::new(&enclave);
        let address = sol_mgr.get_address("m/44'/501'/0'/0'").unwrap();
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
        let atm = AssetIdentifier {
            chain: Chain::COSMOS,
            symbol: "ATOM".to_string(),
        };

        assert!(registry.get_asset(&eth).is_some());
        assert!(registry.get_asset(&sol).is_some());
        assert!(registry.get_asset(&pol).is_some());
        assert!(registry.get_asset(&bsc).is_some());
        assert!(registry.get_asset(&atm).is_some());
    }

    #[test]
    fn test_chain_abstraction_signature() {
        let enclave = Arc::new(CloudEnclave::new("test".to_string()).unwrap());
        let assets = Arc::new(AssetRegistry::new());
        let service = ChainAbstractionService::new(enclave, assets);

        let request = ChainSignatureRequest {
            target_chain: Chain::SOLANA,
            payload: vec![1, 2, 3],
            derivation_path: "m/44'/501'/0'/0'".to_string(),
        };

        let response = service.sign_for_chain(request).unwrap();
        assert!(!response.signature_hex.is_empty());
        assert!(!response.target_address.is_empty());
    }

    #[test]
    fn test_ethereum_erc20_preparation() {
        let enclave = CloudEnclave::new("test".to_string()).unwrap();
        let eth_mgr = EthereumManager::new(&enclave);
        let transfer = crate::protocol::ethereum::Erc20Transfer {
            to: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            amount: 1000000,
            contract_address: "0x0000000000000000000000000000000000000123".to_string(),
        };

        let data = eth_mgr.prepare_erc20_transfer(transfer).unwrap();
        assert_eq!(data.len(), 4 + 32 + 32);
        assert_eq!(&data[0..4], &[0xa9, 0x05, 0x9c, 0xbb]);
    }
}
