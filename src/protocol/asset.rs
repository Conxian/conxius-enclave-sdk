use crate::config::Network;
use crate::{ConclaveError, ConclaveResult};
use alloy::primitives::Address;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetMetadata {
    pub name: String,
    pub decimals: u8,
    pub contract_address: Option<String>,
    pub active: bool,
}

/// Returns whether a chain uses EVM address encoding for contract assets.
pub fn is_evm_chain(chain: Chain) -> bool {
    matches!(
        chain,
        Chain::ETHEREUM
            | Chain::ARBITRUM
            | Chain::BASE
            | Chain::OPTIMISM
            | Chain::LINEA
            | Chain::ROOTSTOCK
            | Chain::BOB
            | Chain::POLYGON
            | Chain::BSC
            | Chain::MEZO
            | Chain::BOTANIX
            | Chain::CITREA
            | Chain::AVALANCHE
            | Chain::CELO
            | Chain::FANTOM
            | Chain::CRONOS
            | Chain::KAVA
            | Chain::GNOSIS
            | Chain::MANTLE
            | Chain::ZKSYNC
            | Chain::SCROLL
            | Chain::BERACHAIN
            | Chain::MONAD
            | Chain::TAIKO
            | Chain::BLAST
            | Chain::BaseSepolia
    )
}

/// Parses an EVM address and rejects malformed or incorrectly checksummed mixed-case input.
pub fn validate_evm_address(address: &str) -> ConclaveResult<Address> {
    if !address.starts_with("0x") || address.len() != 42 {
        return Err(ConclaveError::InvalidConfiguration(
            "EVM address must be a 20-byte 0x-prefixed value".to_string(),
        ));
    }

    let parsed = address.parse::<Address>().map_err(|_| {
        ConclaveError::InvalidConfiguration(
            "EVM address contains invalid hexadecimal data".to_string(),
        )
    })?;

    let body = &address[2..];
    let has_uppercase = body.chars().any(|character| character.is_ascii_uppercase());
    let has_lowercase = body.chars().any(|character| character.is_ascii_lowercase());
    if has_uppercase && has_lowercase && Address::parse_checksummed(address, None).is_err() {
        return Err(ConclaveError::InvalidConfiguration(
            "mixed-case EVM address has an invalid EIP-55 checksum".to_string(),
        ));
    }

    Ok(parsed)
}

fn is_native_asset(id: &AssetIdentifier) -> bool {
    matches!(
        (id.chain, id.symbol.as_str()),
        (Chain::BITCOIN, "BTC")
            | (Chain::ETHEREUM, "ETH")
            | (Chain::SOLANA, "SOL")
            | (Chain::STACKS, "STX")
            | (Chain::POLYGON, "POL")
            | (Chain::BSC, "BNB")
            | (Chain::AVALANCHE, "AVAX")
            | (Chain::NEAR, "NEAR")
            | (Chain::COSMOS, "ATOM")
            | (Chain::XrpLedger, "XRP")
            | (Chain::TRON, "TRX")
            | (Chain::CELO, "CELO")
            | (Chain::FANTOM, "FTM")
            | (Chain::GNOSIS, "GNO")
            | (Chain::LIGHTNING, "BTC")
            | (Chain::LIQUID, "L-BTC")
            | (Chain::ROOTSTOCK, "RBTC")
            | (Chain::SUI, "SUI")
            | (Chain::APTOS, "APT")
            | (Chain::SEI, "SEI")
            | (Chain::STELLAR, "XLM")
    )
}

fn canonical_native_metadata(id: &AssetIdentifier) -> Option<(&'static str, u8)> {
    match (id.chain, id.symbol.as_str()) {
        (Chain::BITCOIN, "BTC") => Some(("Bitcoin", 8)),
        (Chain::ETHEREUM, "ETH") => Some(("Ethereum", 18)),
        (Chain::SOLANA, "SOL") => Some(("Solana", 9)),
        (Chain::STACKS, "STX") => Some(("Stacks", 6)),
        (Chain::POLYGON, "POL") => Some(("Polygon", 18)),
        (Chain::BSC, "BNB") => Some(("BNB Smart Chain", 18)),
        (Chain::AVALANCHE, "AVAX") => Some(("Avalanche", 18)),
        (Chain::NEAR, "NEAR") => Some(("Near", 24)),
        (Chain::COSMOS, "ATOM") => Some(("Cosmos Hub", 6)),
        (Chain::XrpLedger, "XRP") => Some(("XRP", 6)),
        (Chain::TRON, "TRX") => Some(("Tron", 6)),
        (Chain::CELO, "CELO") => Some(("Celo", 18)),
        (Chain::FANTOM, "FTM") => Some(("Fantom", 18)),
        (Chain::GNOSIS, "GNO") => Some(("Gnosis", 18)),
        (Chain::LIGHTNING, "BTC") => Some(("Lightning Bitcoin", 8)),
        (Chain::LIQUID, "L-BTC") => Some(("Liquid Bitcoin", 8)),
        (Chain::ROOTSTOCK, "RBTC") => Some(("Smart Bitcoin", 18)),
        (Chain::SUI, "SUI") => Some(("Sui", 9)),
        (Chain::APTOS, "APT") => Some(("Aptos", 8)),
        (Chain::SEI, "SEI") => Some(("Sei", 6)),
        (Chain::STELLAR, "XLM") => Some(("Stellar Lumens", 7)),
        _ => None,
    }
}

/// This allowlist is deliberately small: entries remain inactive until their address,
/// chain, symbol, decimals, and source metadata all match a reviewed canonical record.
fn canonical_contract_metadata(id: &AssetIdentifier) -> Option<(&'static str, &'static str, u8)> {
    match (id.chain, id.symbol.as_str()) {
        (Chain::ETHEREUM, "USDC") => {
            Some(("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "USD Coin", 6))
        }
        (Chain::BASE, "USDC") => Some((
            "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "USD Coin (Base)",
            6,
        )),
        (Chain::SOLANA, "USDC") => Some((
            "EPjFWdd5Aufqztqjn2nWBGmeEj8Tu9xQVyzfnm9165tr",
            "USD Coin (Solana)",
            6,
        )),
        (Chain::ETHEREUM, "USDT") => Some((
            "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            "Tether USD",
            6,
        )),
        (Chain::BASE, "USDT") => Some((
            "0xfde4C96253e06912322e920Fa732731c166d3aA4",
            "Tether USD (Base)",
            6,
        )),
        (Chain::SOLANA, "USDT") => Some((
            "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
            "Tether USD (Solana)",
            6,
        )),
        (Chain::TRON, "USDT") => {
            Some(("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "Tether USD (Tron)", 6))
        }
        (Chain::ETHEREUM, "EURC") => {
            Some(("0x1abAEa1F7C830F0BB2e246930218A67245842d1b", "Euro Coin", 6))
        }
        _ => None,
    }
}

fn validate_contract_address(chain: Chain, address: &str) -> ConclaveResult<()> {
    if is_evm_chain(chain) {
        validate_evm_address(address)?;
        return Ok(());
    }

    match chain {
        Chain::SOLANA => {
            let decoded = bs58::decode(address).into_vec().map_err(|_| {
                ConclaveError::InvalidConfiguration(
                    "Solana address is not valid base58".to_string(),
                )
            })?;
            if decoded.len() != 32 {
                return Err(ConclaveError::InvalidConfiguration(
                    "Solana address must decode to 32 bytes".to_string(),
                ));
            }
        }
        Chain::TRON => {
            let decoded = bs58::decode(address).into_vec().map_err(|_| {
                ConclaveError::InvalidConfiguration("Tron address is not valid base58".to_string())
            })?;
            if decoded.len() != 25 || decoded.first() != Some(&0x41) {
                return Err(ConclaveError::InvalidConfiguration(
                    "Tron address must be a mainnet base58 account".to_string(),
                ));
            }
            let payload = &decoded[..21];
            let first_hash = Sha256::digest(payload);
            let second_hash = Sha256::digest(first_hash);
            if decoded[21..25] != second_hash[..4] {
                return Err(ConclaveError::InvalidConfiguration(
                    "Tron address has an invalid Base58Check checksum".to_string(),
                ));
            }
        }
        _ => {
            return Err(ConclaveError::Unsupported(format!(
                "contract address validation is not implemented for {}",
                chain
            )))
        }
    }

    Ok(())
}

fn canonical_metadata_matches(
    id: &AssetIdentifier,
    metadata: &AssetMetadata,
) -> ConclaveResult<()> {
    if metadata.name.trim().is_empty() || metadata.decimals > 36 {
        return Err(ConclaveError::InvalidConfiguration(format!(
            "invalid metadata for {}:{}",
            id.chain, id.symbol
        )));
    }

    if is_native_asset(id) {
        let (canonical_name, canonical_decimals) =
            canonical_native_metadata(id).ok_or_else(|| {
                ConclaveError::Unsupported(format!(
                    "native asset {}:{} has no canonical metadata",
                    id.chain, id.symbol
                ))
            })?;
        if metadata.contract_address.is_some()
            || metadata.name != canonical_name
            || metadata.decimals != canonical_decimals
        {
            return Err(ConclaveError::InvalidConfiguration(format!(
                "native asset {}:{} has non-canonical metadata",
                id.chain, id.symbol
            )));
        }
        return Ok(());
    }

    let address = metadata.contract_address.as_deref().ok_or_else(|| {
        ConclaveError::InvalidConfiguration(format!(
            "active contract asset {}:{} is missing an address",
            id.chain, id.symbol
        ))
    })?;
    validate_contract_address(id.chain, address)?;

    let (canonical_address, canonical_name, canonical_decimals) = canonical_contract_metadata(id)
        .ok_or_else(|| {
        ConclaveError::Unsupported(format!(
            "no reviewed canonical metadata is enabled for {}:{}",
            id.chain, id.symbol
        ))
    })?;
    if metadata.name != canonical_name || metadata.decimals != canonical_decimals {
        return Err(ConclaveError::InvalidConfiguration(format!(
            "asset metadata does not match the canonical {}:{} record",
            id.chain, id.symbol
        )));
    }
    if is_evm_chain(id.chain) {
        let parsed_address = validate_evm_address(address)?;
        let canonical_parsed = validate_evm_address(canonical_address)?;
        if parsed_address != canonical_parsed {
            return Err(ConclaveError::InvalidConfiguration(format!(
                "asset address does not match the canonical {}:{} record",
                id.chain, id.symbol
            )));
        }
    } else if address != canonical_address {
        return Err(ConclaveError::InvalidConfiguration(format!(
            "asset address does not match the canonical {}:{} record",
            id.chain, id.symbol
        )));
    }

    Ok(())
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
                active: false,
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
                active: false,
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
                active: false,
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
                active: false,
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
                active: false,
            },
        );

        // Global Stablecoins - USD
        let usd_stables = [
            (
                Chain::ETHEREUM,
                "USDC",
                "USD Coin",
                6,
                Some("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
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
            let id = AssetIdentifier {
                chain,
                symbol: symbol.to_string(),
            };
            let metadata = AssetMetadata {
                name: name.to_string(),
                decimals,
                contract_address: addr.map(|a| a.to_string()),
                active: canonical_metadata_matches(
                    &id,
                    &AssetMetadata {
                        name: name.to_string(),
                        decimals,
                        contract_address: addr.map(|a| a.to_string()),
                        active: true,
                    },
                )
                .is_ok(),
            };
            registry.insert(id, metadata);
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
            (Chain::POLYGON, "cKES", "Kenyan Shilling Stable", 18, None),
            // Latin America
            (Chain::POLYGON, "BRLA", "BRLA Digital (Brazil)", 6, None),
            (
                Chain::CELO,
                "cREAL",
                "Celo Real (Brazil)",
                18,
                Some("0xe8537a30470c1aa548740f12028f00060939eb51"),
            ),
            (Chain::ETHEREUM, "ARS", "Argentine Peso Stable", 6, None),
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
            (Chain::ETHEREUM, "INR", "Indian Rupee Stable", 6, None),
            // Europe / Middle East
            (
                Chain::ETHEREUM,
                "EURC",
                "Euro Coin",
                6,
                Some("0x1abAEa1F7C830F0BB2e246930218A67245842d1b"),
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
            let id = AssetIdentifier {
                chain,
                symbol: symbol.to_string(),
            };
            let metadata = AssetMetadata {
                name: name.to_string(),
                decimals,
                contract_address: addr.map(|a| a.to_string()),
                active: canonical_metadata_matches(
                    &id,
                    &AssetMetadata {
                        name: name.to_string(),
                        decimals,
                        contract_address: addr.map(|a| a.to_string()),
                        active: true,
                    },
                )
                .is_ok(),
            };
            registry.insert(id, metadata);
        }

        Self {
            assets: RwLock::new(registry),
        }
    }

    pub fn register_asset(
        &self,
        id: AssetIdentifier,
        metadata: AssetMetadata,
    ) -> ConclaveResult<()> {
        if metadata.active {
            canonical_metadata_matches(&id, &metadata)?;
        }

        let mut lock = self.assets.write().map_err(|_| {
            ConclaveError::InvalidConfiguration("asset registry lock is poisoned".to_string())
        })?;
        lock.insert(id, metadata);
        Ok(())
    }

    pub fn get_asset(&self, id: &AssetIdentifier) -> Option<AssetMetadata> {
        self.assets.read().ok()?.get(id).cloned()
    }

    pub fn validate_asset(&self, id: &AssetIdentifier) -> ConclaveResult<AssetMetadata> {
        let metadata = self.get_asset(id).ok_or_else(|| {
            ConclaveError::InvalidConfiguration(format!(
                "asset {}:{} is not registered",
                id.chain, id.symbol
            ))
        })?;

        if !metadata.active {
            return Err(ConclaveError::Unsupported(format!(
                "asset {}:{} is quarantined because canonical network metadata is incomplete",
                id.chain, id.symbol
            )));
        }

        canonical_metadata_matches(id, &metadata)?;
        Ok(metadata)
    }

    pub fn validate_asset_on_network(
        &self,
        id: &AssetIdentifier,
        network: Network,
    ) -> ConclaveResult<AssetMetadata> {
        match network {
            Network::Mainnet => self.validate_asset(id),
            Network::Testnet | Network::Devnet => Err(ConclaveError::Unsupported(format!(
                "asset {}:{} has no reviewed metadata for {:?}",
                id.chain, id.symbol, network
            ))),
        }
    }

    pub fn validate_pair(&self, from: &AssetIdentifier, to: &AssetIdentifier) -> bool {
        self.validate_asset(from).is_ok() && self.validate_asset(to).is_ok()
    }

    pub fn validate_pair_on_network(
        &self,
        from: &AssetIdentifier,
        to: &AssetIdentifier,
        network: Network,
    ) -> ConclaveResult<()> {
        self.validate_asset_on_network(from, network)?;
        self.validate_asset_on_network(to, network)?;
        Ok(())
    }

    pub fn list_assets(&self) -> Vec<(AssetIdentifier, AssetMetadata)> {
        self.assets
            .read()
            .ok()
            .map(|lock| lock.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    }
}
