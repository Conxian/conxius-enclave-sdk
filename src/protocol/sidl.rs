use crate::protocol::business::BusinessAttribution;
use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};

/// Conxian SIDL (Sovereign Identity and Deployment Layer) Governance and Cart services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidlVote {
    pub proposal_id: String,
    pub vote_option: String,
    pub attribution: BusinessAttribution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidlCartMandate {
    pub cart_id: String,
    pub items: Vec<String>,
    pub total_amount: u64,
    pub attribution: BusinessAttribution,
}

pub struct SidlService {
    pub gateway_url: String,
    pub http_client: reqwest::Client,
}

impl SidlService {
    pub fn new(gateway_url: String, http_client: reqwest::Client) -> Self {
        Self {
            gateway_url,
            http_client,
        }
    }

    pub async fn broadcast_vote(&self, vote: SidlVote, signature: String) -> ConclaveResult<bool> {
        let url = format!("{}/v1/sidl/vote", self.gateway_url);

        #[derive(Serialize)]
        struct VotePayload {
            vote: SidlVote,
            signature: String,
        }

        let resp = self
            .http_client
            .post(&url)
            .json(&VotePayload { vote, signature })
            .send()
            .await
            .map_err(|e| ConclaveError::NetworkError(e.to_string()))?;

        Ok(resp.status().is_success())
    }

    pub async fn broadcast_cart_mandate(
        &self,
        mandate: SidlCartMandate,
        signature: String,
    ) -> ConclaveResult<bool> {
        let url = format!("{}/v1/sidl/cart/mandate", self.gateway_url);

        #[derive(Serialize)]
        struct MandatePayload {
            mandate: SidlCartMandate,
            signature: String,
        }

        let resp = self
            .http_client
            .post(&url)
            .json(&MandatePayload { mandate, signature })
            .send()
            .await
            .map_err(|e| ConclaveError::NetworkError(e.to_string()))?;

        Ok(resp.status().is_success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_sidl_service_new() {
        let client = reqwest::Client::new();
        let service = SidlService::new("https://api.conxian.io".to_string(), client);
        assert_eq!(service.gateway_url, "https://api.conxian.io");
    }

    #[test]
    fn test_sidl_vote_serialization() {
        let vote = SidlVote {
            proposal_id: "prop_1".to_string(),
            vote_option: "YES".to_string(),
            attribution: BusinessAttribution {
                business_id: "b1".to_string(),
                user_id: "u1".to_string(),
                timestamp: 100,
                expiration: 200,
                nonce: [0u8; 16],
                signature: "sig".to_string(),
                metadata: HashMap::new(),
            },
        };
        let json = serde_json::to_string(&vote).unwrap();
        assert!(json.contains("prop_1"));
        assert!(json.contains("YES"));
    }
}
