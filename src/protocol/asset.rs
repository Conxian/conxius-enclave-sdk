use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Copy)]
pub enum Chain {
    BITCOIN,
    ETHEREUM,
    STACKS,
    LIQUID,
    SOLANA,
    ARBITRUM,
    BASE,
    LIGHTNING,
}

impl Chain {
    pub fn as_str(&self) -> &'static str {
        match self {
            Chain::BITCOIN => "BITCOIN",
            Chain::ETHEREUM => "ETHEREUM",
            Chain::STACKS => "STACKS",
            Chain::LIQUID => "LIQUID",
            Chain::SOLANA => "SOLANA",
            Chain::ARBITRUM => "ARBITRUM",
            Chain::BASE => "BASE",
            Chain::LIGHTNING => "LIGHTNING",
        }
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AssetIdentifier {
    pub chain: Chain,
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetMetadata {
    pub name: String,
    pub decimals: u8,
    pub contract_address: Option<String>,
    pub active: bool,
}

pub struct AssetRegistry {
    assets: RwLock<HashMap<AssetIdentifier, AssetMetadata>>,
}

impl Default for AssetRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AssetRegistry {
    pub fn new() -> Self {
        let mut registry = HashMap::new();

        // Seed with core assets
        registry.insert(
            AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            AssetMetadata {
                name: "Bitcoin".to_string(),
                decimals: 8,
                contract_address: None,
                active: true,
            },
        );

        registry.insert(
            AssetIdentifier {
                chain: Chain::ETHEREUM,
                symbol: "ETH".to_string(),
            },
            AssetMetadata {
                name: "Ethereum".to_string(),
                decimals: 18,
                contract_address: None,
                active: true,
            },
        );

        registry.insert(
            AssetIdentifier {
                chain: Chain::STACKS,
                symbol: "STX".to_string(),
            },
            AssetMetadata {
                name: "Stacks".to_string(),
                decimals: 6,
                contract_address: None,
                active: true,
            },
        );

        registry.insert(
            AssetIdentifier {
                chain: Chain::ETHEREUM,
                symbol: "USDT".to_string(),
            },
            AssetMetadata {
                name: "Tether USD".to_string(),
                decimals: 6,
                contract_address: Some("0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string()),
                active: true,
            },
        );

        registry.insert(
            AssetIdentifier {
                chain: Chain::SOLANA,
                symbol: "SOL".to_string(),
            },
            AssetMetadata {
                name: "Solana".to_string(),
                decimals: 9,
                contract_address: None,
                active: true,
            },
        );

        registry.insert(
            AssetIdentifier {
                chain: Chain::SOLANA,
                symbol: "USDC".to_string(),
            },
            AssetMetadata {
                name: "USD Coin".to_string(),
                decimals: 6,
                contract_address: Some("EPjFWdd5Aufqztqjn2nWBGmeEj8Tu9xQVyzfnm9165tr".to_string()),
                active: true,
            },
        );

        registry.insert(
            AssetIdentifier {
                chain: Chain::LIQUID,
                symbol: "L-BTC".to_string(),
            },
            AssetMetadata {
                name: "Liquid Bitcoin".to_string(),
                decimals: 8,
                contract_address: None,
                active: true,
            },
        );

        registry.insert(
            AssetIdentifier {
                chain: Chain::LIGHTNING,
                symbol: "BTC".to_string(),
            },
            AssetMetadata {
                name: "Lightning Bitcoin".to_string(),
                decimals: 8,
                contract_address: None,
                active: true,
            },
        );

        Self {
            assets: RwLock::new(registry),
        }
    }

    pub fn register_asset(&self, id: AssetIdentifier, metadata: AssetMetadata) {
        if let Ok(mut lock) = self.assets.write() {
            lock.insert(id, metadata);
        }
    }

    pub fn get_asset(&self, id: &AssetIdentifier) -> Option<AssetMetadata> {
        self.assets.read().ok()?.get(id).cloned()
    }

    pub fn validate_pair(&self, from: &AssetIdentifier, to: &AssetIdentifier) -> bool {
        let lock = match self.assets.read() {
            Ok(l) => l,
            Err(_) => return false,
        };
        lock.contains_key(from) && lock.contains_key(to)
    }

    pub fn list_assets(&self) -> Vec<(AssetIdentifier, AssetMetadata)> {
        self.assets
            .read()
            .ok()
            .map(|lock| lock.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    }
}
