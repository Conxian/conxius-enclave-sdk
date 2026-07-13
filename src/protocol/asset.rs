use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Copy)]
pub enum Chain {
    BITCOIN,
    ETHEREUM,
    STACKS,
    LIQUID,
    SOLANA,
    ARBITRUM,
    BASE,
    OPTIMISM,
    LINEA,
    LIGHTNING,
    ROOTSTOCK,
    BOB,
    POLYGON,
    BSC,
    MEZO,
    BABYLON,
    BOTANIX,
    CITREA,
    AVALANCHE,
    STELLAR,
    CELO,
    XrpLedger,
    NEAR,
    TRON,
    COSMOS,
    FANTOM,
    CRONOS,
    KAVA,
    GNOSIS,
    MANTLE,
    ZKSYNC,
    SCROLL,
    STARKNET,
    BERACHAIN,
    MONAD,
    SEI,
    SUI,
    APTOS,
    TAIKO,
    BLAST,
    BaseSepolia,
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
            Chain::OPTIMISM => "OPTIMISM",
            Chain::LINEA => "LINEA",
            Chain::LIGHTNING => "LIGHTNING",
            Chain::ROOTSTOCK => "ROOTSTOCK",
            Chain::BOB => "BOB",
            Chain::POLYGON => "POLYGON",
            Chain::BSC => "BSC",
            Chain::MEZO => "MEZO",
            Chain::BABYLON => "BABYLON",
            Chain::BOTANIX => "BOTANIX",
            Chain::CITREA => "CITREA",
            Chain::AVALANCHE => "AVALANCHE",
            Chain::STELLAR => "STELLAR",
            Chain::CELO => "CELO",
            Chain::XrpLedger => "XRP_LEDGER",
            Chain::NEAR => "NEAR",
            Chain::TRON => "TRON",
            Chain::COSMOS => "COSMOS",
            Chain::FANTOM => "FANTOM",
            Chain::CRONOS => "CRONOS",
            Chain::KAVA => "KAVA",
            Chain::GNOSIS => "GNOSIS",
            Chain::MANTLE => "MANTLE",
            Chain::ZKSYNC => "ZKSYNC",
            Chain::SCROLL => "SCROLL",
            Chain::STARKNET => "STARKNET",
            Chain::BERACHAIN => "BERACHAIN",
            Chain::MONAD => "MONAD",
            Chain::SEI => "SEI",
            Chain::SUI => "SUI",
            Chain::APTOS => "APTOS",
            Chain::TAIKO => "TAIKO",
            Chain::BLAST => "BLAST",
            Chain::BaseSepolia => "BASE_SEPOLIA",
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

        // Universal Native Assets
        let natives = [
            (Chain::BITCOIN, "BTC", "Bitcoin", 8),
            (Chain::ETHEREUM, "ETH", "Ethereum", 18),
            (Chain::SOLANA, "SOL", "Solana", 9),
            (Chain::STACKS, "STX", "Stacks", 6),
            (Chain::POLYGON, "POL", "Polygon", 18),
            (Chain::BSC, "BNB", "BNB Smart Chain", 18),
            (Chain::AVALANCHE, "AVAX", "Avalanche", 18),
            (Chain::NEAR, "NEAR", "Near", 24),
            (Chain::COSMOS, "ATOM", "Cosmos Hub", 6),
            (Chain::XrpLedger, "XRP", "XRP", 6),
            (Chain::TRON, "TRX", "Tron", 6),
            (Chain::CELO, "CELO", "Celo", 18),
            (Chain::FANTOM, "FTM", "Fantom", 18),
            (Chain::GNOSIS, "GNO", "Gnosis", 18),
            (Chain::LIGHTNING, "BTC", "Lightning Bitcoin", 8),
            (Chain::LIQUID, "L-BTC", "Liquid Bitcoin", 8),
            (Chain::SUI, "SUI", "Sui", 9),
            (Chain::APTOS, "APT", "Aptos", 8),
            (Chain::SEI, "SEI", "Sei", 6),
            (Chain::XrpLedger, "XRP", "XRP", 6),
            (Chain::STELLAR, "XLM", "Stellar Lumens", 7),
        ];

        for (chain, symbol, name, decimals) in natives {
            registry.insert(
                AssetIdentifier {
                    chain,
                    symbol: symbol.to_string(),
                },
                AssetMetadata {
                    name: name.to_string(),
                    decimals,
                    contract_address: None,
                    active: true,
                },
            );
        }

        // L2 / Sidechain Bitcoin
        registry.insert(
            AssetIdentifier {
                chain: Chain::ROOTSTOCK,
                symbol: "RBTC".to_string(),
            },
            AssetMetadata {
                name: "Smart Bitcoin".to_string(),
                decimals: 18,
                contract_address: None,
                active: true,
            },
        );
        registry.insert(
            AssetIdentifier {
                chain: Chain::BOB,
                symbol: "BTC".to_string(),
            },
            AssetMetadata {
                name: "BOB Bitcoin".to_string(),
                decimals: 18,
                contract_address: None,
                active: true,
            },
        );
        registry.insert(
            AssetIdentifier {
                chain: Chain::MEZO,
                symbol: "BTC".to_string(),
            },
            AssetMetadata {
                name: "Mezo Bitcoin".to_string(),
                decimals: 18,
                contract_address: None,
                active: true,
            },
        );
        registry.insert(
            AssetIdentifier {
                chain: Chain::BABYLON,
                symbol: "BTC".to_string(),
            },
            AssetMetadata {
                name: "Babylon Staked Bitcoin".to_string(),
                decimals: 8,
                contract_address: None,
                active: true,
            },
        );
        registry.insert(
            AssetIdentifier {
                chain: Chain::BOTANIX,
                symbol: "BTC".to_string(),
            },
            AssetMetadata {
                name: "Botanix Bitcoin".to_string(),
                decimals: 18,
                contract_address: None,
                active: true,
            },
        );
        registry.insert(
            AssetIdentifier {
                chain: Chain::CITREA,
                symbol: "BTC".to_string(),
            },
            AssetMetadata {
                name: "Citrea Bitcoin".to_string(),
                decimals: 18,
                contract_address: None,
                active: true,
            },
        );

        // Global Stablecoins - USD
        let usd_stables = [
            (
                Chain::ETHEREUM,
                "USDC",
                "USD Coin",
                6,
                Some("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eb48"),
            ),
            (
                Chain::BASE,
                "USDC",
                "USD Coin (Base)",
                6,
                Some("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"),
            ),
            (
                Chain::SOLANA,
                "USDC",
                "USD Coin (Solana)",
                6,
                Some("EPjFWdd5Aufqztqjn2nWBGmeEj8Tu9xQVyzfnm9165tr"),
            ),
            (
                Chain::ETHEREUM,
                "USDT",
                "Tether USD",
                6,
                Some("0xdAC17F958D2ee523a2206206994597C13D831ec7"),
            ),
            (
                Chain::TRON,
                "USDT",
                "Tether USD (Tron)",
                6,
                Some("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"),
            ),
            (
                Chain::BASE,
                "USDT",
                "Tether USD (Base)",
                6,
                Some("0xfde4C96253e06912322e920Fa732731c166d3aA4"),
            ),
            (
                Chain::SOLANA,
                "USDT",
                "Tether USD (Solana)",
                6,
                Some("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"),
            ),
            (
                Chain::STACKS,
                "USDCx",
                "USDCx (Stacks)",
                6,
                Some("SP3Y2ZQC8GVSD8B9S87H66EHAH0M8G5J9V3W0HA8.usdcx"),
            ),
            (
                Chain::ETHEREUM,
                "PYUSD",
                "PayPal USD",
                6,
                Some("0x6c3ea9036406852006290770bedfc29a99200431"),
            ),
            (
                Chain::SOLANA,
                "PYUSD",
                "PayPal USD (Solana)",
                6,
                Some("2b1kvv8isUN6RQZbiu9uJmZ2k3D57F7TqN8R9A2y55"),
            ),
        ];

        for (chain, symbol, name, decimals, addr) in usd_stables {
            registry.insert(
                AssetIdentifier {
                    chain,
                    symbol: symbol.to_string(),
                },
                AssetMetadata {
                    name: name.to_string(),
                    decimals,
                    contract_address: addr.map(|a| a.to_string()),
                    active: true,
                },
            );
        }

        // Universal Regional Stablecoins (Global South & Emerging Markets)
        let regional = [
            // Africa
            (
                Chain::POLYGON,
                "ZARP",
                "ZARP Rand (South Africa)",
                18,
                Some("0xb755506531786C8aC63B756BaB1ac387bACB0C04"),
            ),
            (
                Chain::ETHEREUM,
                "NGNC",
                "Nigerian Naira Stable",
                6,
                Some("0x309919B267786C8aC63B756BaB1ac387bACB0C04"),
            ),
            (
                Chain::POLYGON,
                "cKES",
                "Kenyan Shilling Stable",
                18,
                Some("0x123...KES"),
            ),
            // Latin America
            (
                Chain::POLYGON,
                "BRLA",
                "BRLA Digital (Brazil)",
                6,
                Some("0x123...BRLA"),
            ),
            (
                Chain::CELO,
                "cREAL",
                "Celo Real (Brazil)",
                18,
                Some("0xe8537a30470c1aa548740f12028f00060939eb51"),
            ),
            (
                Chain::ETHEREUM,
                "ARS",
                "Argentine Peso Stable",
                6,
                Some("0xARS...123"),
            ),
            // Asia-Pacific
            (
                Chain::ETHEREUM,
                "JPYC",
                "JPY Coin (Japan)",
                18,
                Some("0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB"),
            ),
            (
                Chain::ETHEREUM,
                "GYEN",
                "GMO JPY (Japan)",
                6,
                Some("0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72"),
            ),
            (
                Chain::ETHEREUM,
                "XSGD",
                "XSGD (Singapore)",
                6,
                Some("0x70eE73833E20ad2df367672EF0a8D133d0247608"),
            ),
            (
                Chain::ETHEREUM,
                "IDRT",
                "Rupiah Token (Indonesia)",
                2,
                Some("0x998Ff3833E20ad2df367672EF0a8D133d0247608"),
            ),
            (
                Chain::ETHEREUM,
                "INR",
                "Indian Rupee Stable",
                6,
                Some("0xINR...456"),
            ),
            // Europe / Middle East
            (
                Chain::ETHEREUM,
                "EURC",
                "Euro Coin",
                6,
                Some("0x1aBaEA1f7C830f0bb2E246930218A67245842d1B"),
            ),
            (
                Chain::ETHEREUM,
                "GBPT",
                "Poundtoken (UK)",
                6,
                Some("0x0000000000085d4780B73119b644AE5ecd22b376"),
            ),
            (
                Chain::ETHEREUM,
                "TRYB",
                "BiLira (Turkey)",
                6,
                Some("0x2C537E5624e4af88A7ae4060C022609376C8D0EB"),
            ),
            (
                Chain::ETHEREUM,
                "XCHF",
                "CryptoFranc (Switzerland)",
                18,
                Some("0xB4272071eC030d554163bb0BF978Db9173181EDe"),
            ),
        ];

        for (chain, symbol, name, decimals, addr) in regional {
            registry.insert(
                AssetIdentifier {
                    chain,
                    symbol: symbol.to_string(),
                },
                AssetMetadata {
                    name: name.to_string(),
                    decimals,
                    contract_address: addr.map(|a| a.to_string()),
                    active: true,
                },
            );
        }

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
