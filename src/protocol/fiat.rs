use crate::protocol::asset::AssetIdentifier;
use crate::protocol::business::BusinessAttribution;
use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FiatProviderType {
    /// Traditional centralized providers (Stripe, Circle, MoonPay)
    Legacy,
    /// Sovereign P2P or hardware-attested providers (Bisq, Sovereign Ramp)
    Sovereign,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiatOnRampRequest {
    pub fiat_currency: String,
    pub crypto_asset: AssetIdentifier,
    pub amount: f64,
    pub wallet_address: String,
    pub provider: String,
    pub provider_type: FiatProviderType,
    pub attribution: Option<BusinessAttribution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiatSessionIntent {
    pub request: FiatOnRampRequest,
    pub signable_hash: Vec<u8>,
    pub gateway_url: String,
    pub enforce_sovereignty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiatSessionResponse {
    pub session_id: String,
    pub redirect_url: String,
    pub provider: String,
    pub is_sovereign: bool,
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
    /// If provider_type is Sovereign, the intent will require hardware attestation at the gateway.
    pub fn prepare_session(&self, request: FiatOnRampRequest) -> FiatSessionIntent {
        let mut hasher = Sha256::new();
        hasher.update(format!("FIAT_SOVEREIGN_v1:{:?}:{}", request, self.gateway_endpoint).as_bytes());
        let signable_hash = hasher.finalize().to_vec();

        let enforce_sovereignty = request.provider_type == FiatProviderType::Sovereign;

        FiatSessionIntent {
            request,
            signable_hash,
            gateway_url: self.gateway_endpoint.clone(),
            enforce_sovereignty,
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
    fn test_prepare_fiat_session_sovereign() {
        let client = reqwest::Client::new();
        let service =
            FiatRouterService::new("https://gateway.conxian-labs.com".to_string(), client);

        let request = FiatOnRampRequest {
            fiat_currency: "USD".to_string(),
            crypto_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            amount: 100.0,
            wallet_address: "bc1q...".to_string(),
            provider: "bisq".to_string(),
            provider_type: FiatProviderType::Sovereign,
            attribution: None,
        };

        let intent = service.prepare_session(request);
        assert!(intent.enforce_sovereignty);
        assert!(!intent.signable_hash.is_empty());
    }
}
