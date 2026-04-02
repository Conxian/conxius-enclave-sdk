use crate::protocol::business::BusinessAttribution;
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

pub struct A2pRouterService {
    pub gateway_endpoint: String,
}

impl A2pRouterService {
    pub fn new(gateway_endpoint: String) -> Self {
        Self { gateway_endpoint }
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

    /// Verifies the OTP code against the gateway.
    pub async fn verify_otp(
        &self,
        _verification: OtpVerificationRequest,
        _signature: String,
    ) -> Result<bool, String> {
        // Mock verification for the SDK
        Ok(true)
    }
}
