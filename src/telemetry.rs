use reqwest::Client;
use serde::Serialize;

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

        let future = async move {
            let payload = TelemetryPayload {
                api_key,
                signature_hash,
            };

            if let Ok(res) = client.post(&url).json(&payload).send().await {
                if !res.status().is_success() {
                    let _ = res.text().await;
                }
            }
        };

        #[cfg(not(target_arch = "wasm32"))]
        {
            tokio::spawn(future);
        }
        #[cfg(target_arch = "wasm32")]
        {
            wasm_bindgen_futures::spawn_local(future);
        }
    }
}
