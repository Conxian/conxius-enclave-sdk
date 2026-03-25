use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AssetIdentifier {
    pub chain: String,
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub identifier: AssetIdentifier,
    pub name: String,
    pub decimals: u8,
    pub contract_address: Option<String>,
    pub active: bool,
}

#[derive(Clone)]
pub struct AssetRegistry {
    assets: HashMap<AssetIdentifier, Asset>,
}

impl AssetRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            assets: HashMap::new(),
        };
        registry.initialize_defaults();
        registry
    }

    fn initialize_defaults(&mut self) {
        self.register_asset(Asset {
            identifier: AssetIdentifier { chain: "BTC".to_string(), symbol: "BTC".to_string() },
            name: "Bitcoin".to_string(),
            decimals: 8,
            contract_address: None,
            active: true,
        });

        self.register_asset(Asset {
            identifier: AssetIdentifier { chain: "ETH".to_string(), symbol: "ETH".to_string() },
            name: "Ethereum".to_string(),
            decimals: 18,
            contract_address: None,
            active: true,
        });

        self.register_asset(Asset {
            identifier: AssetIdentifier { chain: "STACKS".to_string(), symbol: "STX".to_string() },
            name: "Stacks".to_string(),
            decimals: 6,
            contract_address: None,
            active: true,
        });

        self.register_asset(Asset {
            identifier: AssetIdentifier { chain: "ETH".to_string(), symbol: "USDT".to_string() },
            name: "Tether USD".to_string(),
            decimals: 6,
            contract_address: Some("0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string()),
            active: true,
        });

        self.register_asset(Asset {
            identifier: AssetIdentifier { chain: "LIQUID".to_string(), symbol: "LBTC".to_string() },
            name: "Liquid Bitcoin".to_string(),
            decimals: 8,
            contract_address: None,
            active: true,
        });

        self.register_asset(Asset {
            identifier: AssetIdentifier { chain: "LIGHTNING".to_string(), symbol: "BTC".to_string() },
            name: "Lightning Bitcoin".to_string(),
            decimals: 8,
            contract_address: None,
            active: true,
        });
    }

    pub fn register_asset(&mut self, asset: Asset) {
        self.assets.insert(asset.identifier.clone(), asset);
    }

    pub fn get_asset(&self, chain: &str, symbol: &str) -> Option<&Asset> {
        let id = AssetIdentifier { chain: chain.to_string(), symbol: symbol.to_string() };
        self.assets.get(&id)
    }

    pub fn validate_pair(&self, from: &AssetIdentifier, to: &AssetIdentifier) -> bool {
        self.assets.contains_key(from) && self.assets.contains_key(to) && from != to
    }
}
