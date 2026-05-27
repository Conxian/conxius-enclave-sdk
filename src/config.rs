use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReleaseTrack {
    Lts,
    BleedingEdge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkConfig {
    pub network: Network,
    pub track: ReleaseTrack,
    pub gateway_url: String,
    pub api_key: Option<String>,
}

impl SdkConfig {
    pub fn new(network: Network, track: ReleaseTrack, gateway_url: String) -> Self {
        Self {
            network,
            track,
            gateway_url,
            api_key: None,
        }
    }

    pub fn with_api_key(mut self, key: String) -> Self {
        self.api_key = Some(key);
        self
    }
}
