use crate::protocol::asset::AssetIdentifier;
use crate::protocol::business::BusinessAttribution;
use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

#[derive(Debug, Serialize, Deserialize)]
struct BroadcastFiatRequest {
    pub intent: FiatSessionIntent,
    pub signature: String,
}

pub struct FiatRouterService {
    pub http_client: reqwest::Client,
    pub gateway_endpoint: String,
}

impl FiatRouterService {
    pub fn new(gateway_endpoint: String, http_client: reqwest::Client) -> Self {
        Self {
            gateway_endpoint,
            http_client,
        }
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

    /// Broadcasts the signed fiat session intent to the Conxian Gateway.
    pub async fn create_session(
        &self,
        intent: FiatSessionIntent,
        signature: String,
    ) -> ConclaveResult<FiatSessionResponse> {
        let url = format!("{}/v1/fiat/session", self.gateway_endpoint);

        let payload = BroadcastFiatRequest { intent, signature };

        let response = self
            .http_client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| ConclaveError::EnclaveFailure(format!("Gateway request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(ConclaveError::EnclaveFailure(format!(
                "Gateway returned error: {}",
                response.status()
            )));
        }

        let session_resp = response
            .json::<FiatSessionResponse>()
            .await
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid gateway response: {}", e)))?;

        Ok(session_resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::asset::{AssetIdentifier, Chain};

    #[test]
    fn test_prepare_fiat_session() {
        let client = reqwest::Client::new();
        let service = FiatRouterService::new("https://api.conxian.io".to_string(), client);

        let request = FiatOnRampRequest {
            fiat_currency: "USD".to_string(),
            crypto_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            amount: 100.0,
            wallet_address: "bc1q...".to_string(),
            provider: "stripe".to_string(),
            attribution: None,
        };

        let intent = service.prepare_session(request);
        assert!(!intent.signable_hash.is_empty());
        assert_eq!(intent.gateway_url, "https://api.conxian.io");
    }
}
