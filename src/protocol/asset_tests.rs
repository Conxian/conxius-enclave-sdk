#[cfg(test)]
mod tests {
    use crate::protocol::asset::{AssetIdentifier, AssetRegistry, Chain};

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
        let cosmos_atom = AssetIdentifier {
            chain: Chain::COSMOS,
            symbol: "ATOM".to_string(),
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
        assert_eq!(
            registry.get_asset(&cosmos_atom).unwrap().name,
            "Cosmos Hub"
        );
    }
}
