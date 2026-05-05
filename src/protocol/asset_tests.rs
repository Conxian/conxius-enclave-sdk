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
}
