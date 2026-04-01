use reqwest::Client;
use serde::Serialize;
use tokio;

#[derive(Serialize)]
struct TelemetryPayload {
    pub api_key: String,
    pub signature_hash: String,
}

pub struct TelemetryClient {
    nexus_url: String,
    api_key: String,
    http_client: Client,
}

impl TelemetryClient {
    pub fn new(nexus_url: String, api_key: String) -> Self {
        Self {
            nexus_url,
            api_key,
            http_client: Client::new(),
        }
    }

    /// Non-blocking ping to conxian-nexus billing endpoint.
    /// This runs in the background and does not slow down hardware signing.
    pub fn track_signature(&self, signature_hash: String) {
        let url = format!("{}/v1/billing/telemetry/track-signature", self.nexus_url);
        let api_key = self.api_key.clone();
        let client = self.http_client.clone();

        // Spawn as a detached tokio task so it never blocks the critical signing path
        tokio::spawn(async move {
            let payload = TelemetryPayload {
                api_key,
                signature_hash,
            };

            match client.post(&url).json(&payload).send().await {
                Ok(res) => {
                    if !res.status().is_success() {
                        // In production, we'd log this locally or queue for retry
                        // We intentionally ignore errors here to prevent SDK crashing
                        // from backend downtime (preserving user sovereignty).
                        let _ = res.text().await;
                    }
                }
                Err(_) => {
                    // Network failure, ignore to maintain 300ms SLA
                }
            }
        });
    }
}
