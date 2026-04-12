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

    /// Broadcasts the signed fiat session intent to the Conxian Gateway.
    pub async fn create_session(
        &self,
        intent: FiatSessionIntent,
        signature: String,
    ) -> ConclaveResult<FiatSessionResponse> {
        let url = format!("{}/v1/fiat/session", self.gateway_endpoint);
        let client = reqwest::Client::new();

        let payload = BroadcastFiatRequest { intent, signature };

        let response =
            client.post(&url).json(&payload).send().await.map_err(|e| {
                ConclaveError::EnclaveFailure(format!("Gateway request failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(ConclaveError::EnclaveFailure(format!(
                "Gateway returned error: {}",
                response.status()
            )));
        }

        let session_resp = response.json::<FiatSessionResponse>().await.map_err(|e| {
            ConclaveError::CryptoError(format!("Invalid gateway response: {}", e))
        })?;

        Ok(session_resp)
    }
}
