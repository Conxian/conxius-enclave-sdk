use crate::protocol::business::BusinessAttribution;
use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpRequest {
    pub phone_number: String, // E.164 format
    pub channel: String,      // SMS or WhatsApp
    pub attribution: Option<BusinessAttribution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpVerificationRequest {
    pub phone_number: String,
    pub otp_code: String,
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2pSessionIntent {
    pub request: OtpRequest,
    pub signable_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2pResponse {
    pub session_id: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BroadcastOtpRequest {
    pub intent: A2pSessionIntent,
    pub signature: String,
}

pub struct A2pRouterService {
    pub http_client: reqwest::Client,
    pub gateway_endpoint: String,
}

impl A2pRouterService {
    pub fn new(gateway_endpoint: String, http_client: reqwest::Client) -> Self {
        Self {
            gateway_endpoint,
            http_client,
        }
    }

    /// Prepares a stateless OTP request intent for signing.
    pub fn prepare_otp(&self, request: OtpRequest) -> A2pSessionIntent {
        let mut hasher = Sha256::new();
        hasher.update(format!("A2P_OTP:{:?}:{}", request, self.gateway_endpoint).as_bytes());
        let signable_hash = hasher.finalize().to_vec();

        A2pSessionIntent {
            request,
            signable_hash,
        }
    }

    /// Initiates phone verification by broadcasting the signed intent to the gateway.
    pub async fn initiate_verification(
        &self,
        intent: A2pSessionIntent,
        signature: String,
    ) -> ConclaveResult<A2pResponse> {
        let url = format!("{}/v1/a2p/otp/initiate", self.gateway_endpoint);

        let payload = BroadcastOtpRequest { intent, signature };

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

        let a2p_resp = response
            .json::<A2pResponse>()
            .await
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid gateway response: {}", e)))?;

        Ok(a2p_resp)
    }

    /// Verifies the OTP code against the gateway.
    pub async fn verify_otp(
        &self,
        verification: OtpVerificationRequest,
        signature: String,
    ) -> ConclaveResult<bool> {
        let url = format!("{}/v1/a2p/otp/verify", self.gateway_endpoint);

        #[derive(Debug, Serialize, Deserialize)]
        struct VerifyPayload {
            pub verification: OtpVerificationRequest,
            pub signature: String,
        }

        let payload = VerifyPayload {
            verification,
            signature,
        };

        let response = self
            .http_client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| ConclaveError::EnclaveFailure(format!("Gateway request failed: {}", e)))?;

        if !response.status().is_success() {
            return Ok(false);
        }

        let result: bool = response
            .json()
            .await
            .map_err(|e| ConclaveError::CryptoError(format!("Invalid gateway response: {}", e)))?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prepare_otp_intent() {
        let client = reqwest::Client::new();
        let service = A2pRouterService::new("https://api.conxian.io".to_string(), client);

        let request = OtpRequest {
            phone_number: "+1234567890".to_string(),
            channel: "SMS".to_string(),
            attribution: None,
        };

        let intent = service.prepare_otp(request);
        assert!(!intent.signable_hash.is_empty());
    }
}
