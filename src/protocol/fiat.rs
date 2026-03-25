use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use crate::protocol::asset::AssetIdentifier;
use crate::protocol::business::BusinessAttribution;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiatOnRampRequest {
    pub fiat_currency: String,
    pub crypto_asset: AssetIdentifier,
    pub amount: f64,
    pub wallet_address: String,
    pub provider: String,
    pub attribution: Option<BusinessAttribution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiatSessionIntent {
    pub request: FiatOnRampRequest,
    pub signable_hash: Vec<u8>,
    pub gateway_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiatSessionResponse {
    pub session_id: String,
    pub redirect_url: String,
    pub provider: String,
}

pub struct FiatRouterService {
    pub gateway_endpoint: String,
}

impl FiatRouterService {
    pub fn new(gateway_endpoint: String) -> Self {
        Self { gateway_endpoint }
    }

    /// Prepares a stateless on-ramp session intent for signing.
    pub fn prepare_session(&self, request: FiatOnRampRequest) -> FiatSessionIntent {
        let mut hasher = Sha256::new();
        hasher.update(format!("FIAT_ONRAMP:{:?}:{}", request, self.gateway_endpoint).as_bytes());
        let signable_hash = hasher.finalize().to_vec();

        FiatSessionIntent {
            request,
            signable_hash,
            gateway_url: self.gateway_endpoint.clone(),
        }
    }

    /// In a real implementation, this would call the Gateway API.
    /// For the SDK, we provide the structure to handle the response.
    pub async fn create_session(
        &self,
        _intent: FiatSessionIntent,
        _signature: String,
    ) -> Result<FiatSessionResponse, String> {
        // Mock response for the SDK
        Ok(FiatSessionResponse {
            session_id: "sess_12345".to_string(),
            redirect_url: "https://ramp.network/buy?address=...".to_string(),
            provider: "Ramp".to_string(),
        })
    }
}
