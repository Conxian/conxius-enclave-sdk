use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client, Url,
};
use serde::Serialize;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use thiserror::Error;

#[cfg(not(target_arch = "wasm32"))]
use tokio::runtime::Handle;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::spawn_local;

const TELEMETRY_PATH: &str = "v1/billing/telemetry/track-signature";
const API_KEY_HEADER: &str = "x-api-key";

/// A bounded policy for best-effort telemetry delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryPolicy {
    request_timeout: Duration,
    max_retries: u8,
    retry_backoff: Duration,
}

impl TelemetryPolicy {
    /// Maximum request timeout accepted by the SDK.
    pub const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
    /// Maximum number of retries accepted by the SDK.
    pub const MAX_RETRIES: u8 = 3;
    /// Maximum initial retry backoff accepted by the SDK.
    pub const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(1);

    /// Build a bounded delivery policy.
    pub fn new(
        request_timeout: Duration,
        max_retries: u8,
        retry_backoff: Duration,
    ) -> Result<Self, TelemetryConfigError> {
        if request_timeout.is_zero() || request_timeout > Self::MAX_REQUEST_TIMEOUT {
            return Err(TelemetryConfigError::InvalidTimeout);
        }
        if max_retries > Self::MAX_RETRIES {
            return Err(TelemetryConfigError::InvalidRetryCount);
        }
        if retry_backoff > Self::MAX_RETRY_BACKOFF {
            return Err(TelemetryConfigError::InvalidRetryBackoff);
        }

        Ok(Self {
            request_timeout,
            max_retries,
            retry_backoff,
        })
    }

    pub fn request_timeout(self) -> Duration {
        self.request_timeout
    }

    pub fn max_retries(self) -> u8 {
        self.max_retries
    }

    pub fn retry_backoff(self) -> Duration {
        self.retry_backoff
    }
}

impl Default for TelemetryPolicy {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(5),
            max_retries: 2,
            retry_backoff: Duration::from_millis(50),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TelemetryConfigError {
    #[error("Telemetry endpoint is invalid")]
    InvalidEndpoint,
    #[error("Telemetry endpoint must use HTTPS")]
    InsecureEndpoint,
    #[error("Telemetry endpoint may not include credentials")]
    EndpointCredentials,
    #[error("Telemetry endpoint may not include a query or fragment")]
    EndpointQueryOrFragment,
    #[error("Telemetry API key is invalid")]
    InvalidApiKey,
    #[error("Telemetry request timeout is invalid or unbounded")]
    InvalidTimeout,
    #[error("Telemetry retry count is invalid or unbounded")]
    InvalidRetryCount,
    #[error("Telemetry retry backoff is invalid or unbounded")]
    InvalidRetryBackoff,
    #[error("Telemetry HTTP client could not be initialized")]
    HttpClientInitialization,
}

impl TelemetryConfigError {
    fn failure_kind(self) -> TelemetryFailureKind {
        TelemetryFailureKind::Configuration
    }
}

/// Events are deliberately coarse and contain no request-derived identifiers.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryEvent {
    SignedIntent,
}

#[derive(Debug, Serialize)]
struct TelemetryPayload {
    schema_version: u8,
    event: TelemetryEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryDeliveryStatus {
    /// Telemetry was explicitly disabled or rejected during configuration.
    Disabled,
    /// No delivery has been scheduled yet.
    Idle,
    /// A best-effort delivery is in flight.
    Pending,
    /// The most recently scheduled event was delivered successfully.
    Delivered,
    /// The most recently scheduled event failed or could not be scheduled.
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryFailureKind {
    Configuration,
    NoRuntime,
    Serialization,
    Timeout,
    Network,
    HttpStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryFailure {
    pub kind: TelemetryFailureKind,
    pub status_code: Option<u16>,
    pub retries_exhausted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryDispatch {
    Disabled,
    Scheduled,
    Rejected(TelemetryFailureKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportError {
    Timeout,
    Network,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransportResponse {
    status: u16,
}

#[derive(Debug, Clone)]
struct TransportRequest {
    url: Url,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[cfg(not(target_arch = "wasm32"))]
type TransportFuture =
    Pin<Box<dyn Future<Output = Result<TransportResponse, TransportError>> + Send + 'static>>;

#[cfg(target_arch = "wasm32")]
type TransportFuture =
    Pin<Box<dyn Future<Output = Result<TransportResponse, TransportError>> + 'static>>;

#[cfg(not(target_arch = "wasm32"))]
trait TelemetryTransport: Send + Sync {
    fn send(&self, request: TransportRequest) -> TransportFuture;
}

#[cfg(target_arch = "wasm32")]
trait TelemetryTransport {
    fn send(&self, request: TransportRequest) -> TransportFuture;
}

struct ReqwestTransport {
    client: Client,
}

impl TelemetryTransport for ReqwestTransport {
    fn send(&self, request: TransportRequest) -> TransportFuture {
        let client = self.client.clone();
        Box::pin(async move {
            client
                .post(request.url)
                .headers(request.headers)
                .body(request.body)
                .send()
                .await
                .map(|response| TransportResponse {
                    status: response.status().as_u16(),
                })
                .map_err(|error| {
                    if error.is_timeout() {
                        TransportError::Timeout
                    } else {
                        TransportError::Network
                    }
                })
        })
    }
}

#[derive(Debug)]
struct DeliveryState {
    status: TelemetryDeliveryStatus,
    last_failure: Option<TelemetryFailure>,
    failure_count: u64,
}

impl DeliveryState {
    fn enabled() -> Self {
        Self {
            status: TelemetryDeliveryStatus::Idle,
            last_failure: None,
            failure_count: 0,
        }
    }

    fn disabled() -> Self {
        Self {
            status: TelemetryDeliveryStatus::Disabled,
            last_failure: None,
            failure_count: 0,
        }
    }
}

pub struct TelemetryClient {
    endpoint: Option<Url>,
    auth_headers: HeaderMap,
    transport: Arc<dyn TelemetryTransport>,
    policy: TelemetryPolicy,
    enabled: bool,
    state: Arc<Mutex<DeliveryState>>,
}

impl TelemetryClient {
    /// Construct an enabled client, or a disabled client if configuration is invalid.
    ///
    /// Prefer [`TelemetryClient::try_new`] when configuration errors must be handled
    /// explicitly. The compatibility constructor fails closed and never panics.
    pub fn new(nexus_url: String, api_key: String) -> Self {
        match Self::try_new(nexus_url, api_key) {
            Ok(client) => client,
            Err(error) => {
                let client = Self::disabled();
                record_failure(
                    &client.state,
                    TelemetryFailure {
                        kind: error.failure_kind(),
                        status_code: None,
                        retries_exhausted: false,
                    },
                );
                client
            }
        }
    }

    /// Construct an enabled client that requires an HTTPS endpoint.
    pub fn try_new(nexus_url: String, api_key: String) -> Result<Self, TelemetryConfigError> {
        Self::try_new_with_policy(nexus_url, api_key, TelemetryPolicy::default())
    }

    /// Construct an enabled client with a bounded delivery policy.
    pub fn try_new_with_policy(
        nexus_url: String,
        api_key: String,
        policy: TelemetryPolicy,
    ) -> Result<Self, TelemetryConfigError> {
        let endpoint = parse_endpoint(&nexus_url, false)?;
        let auth_headers = build_auth_headers(&api_key)?;
        let client = build_http_client(policy)?;

        Ok(Self::from_parts(
            Some(endpoint),
            auth_headers,
            Arc::new(ReqwestTransport { client }),
            policy,
            true,
        ))
    }

    /// Construct an explicitly disabled client.
    pub fn disabled() -> Self {
        Self::from_parts(
            None,
            HeaderMap::new(),
            Arc::new(ReqwestTransport {
                client: Client::new(),
            }),
            TelemetryPolicy::default(),
            false,
        )
    }

    /// Schedule a coarse event without placing security-critical work on the
    /// telemetry delivery path.
    pub fn track_event(&self, event: TelemetryEvent) -> TelemetryDispatch {
        if !self.enabled {
            return TelemetryDispatch::Disabled;
        }

        let payload = match serde_json::to_vec(&TelemetryPayload {
            schema_version: 1,
            event,
        }) {
            Ok(payload) => payload,
            Err(_) => {
                let failure = TelemetryFailure {
                    kind: TelemetryFailureKind::Serialization,
                    status_code: None,
                    retries_exhausted: false,
                };
                record_failure(&self.state, failure);
                return TelemetryDispatch::Rejected(failure.kind);
            }
        };

        let endpoint = match self.endpoint.as_ref() {
            Some(endpoint) => endpoint,
            None => {
                let failure = TelemetryFailure {
                    kind: TelemetryFailureKind::Configuration,
                    status_code: None,
                    retries_exhausted: false,
                };
                record_failure(&self.state, failure);
                return TelemetryDispatch::Rejected(failure.kind);
            }
        };

        let request = TransportRequest {
            url: telemetry_url(endpoint),
            headers: self.auth_headers.clone(),
            body: payload,
        };

        #[cfg(not(target_arch = "wasm32"))]
        let runtime = match Handle::try_current() {
            Ok(runtime) => runtime,
            Err(_) => {
                let failure = TelemetryFailure {
                    kind: TelemetryFailureKind::NoRuntime,
                    status_code: None,
                    retries_exhausted: false,
                };
                record_failure(&self.state, failure);
                return TelemetryDispatch::Rejected(failure.kind);
            }
        };

        mark_pending(&self.state);
        let transport = Arc::clone(&self.transport);
        let policy = self.policy;
        let state = Arc::clone(&self.state);
        let delivery = deliver_event(transport, policy, state, request);

        #[cfg(not(target_arch = "wasm32"))]
        {
            runtime.spawn(delivery);
        }

        #[cfg(target_arch = "wasm32")]
        {
            spawn_local(delivery);
        }

        TelemetryDispatch::Scheduled
    }

    /// Compatibility shim for callers of the original API.
    ///
    /// The supplied identifier is intentionally discarded and is never serialized.
    #[deprecated(note = "use track_event; signature-derived identifiers are not transmitted")]
    pub fn track_signature(&self, _signature_hash: String) {
        let _ = self.track_event(TelemetryEvent::SignedIntent);
    }

    pub fn delivery_status(&self) -> TelemetryDeliveryStatus {
        match self.state.lock() {
            Ok(state) => state.status,
            Err(poisoned) => poisoned.into_inner().status,
        }
    }

    pub fn last_failure(&self) -> Option<TelemetryFailure> {
        match self.state.lock() {
            Ok(state) => state.last_failure,
            Err(poisoned) => poisoned.into_inner().last_failure,
        }
    }

    pub fn failure_count(&self) -> u64 {
        match self.state.lock() {
            Ok(state) => state.failure_count,
            Err(poisoned) => poisoned.into_inner().failure_count,
        }
    }

    #[cfg(test)]
    fn with_test_transport(
        endpoint: &str,
        api_key: &str,
        policy: TelemetryPolicy,
        transport: Arc<TestTransport>,
    ) -> Result<Self, TelemetryConfigError> {
        let endpoint = parse_endpoint(endpoint, true)?;
        let auth_headers = build_auth_headers(api_key)?;
        Ok(Self::from_parts(
            Some(endpoint),
            auth_headers,
            transport,
            policy,
            true,
        ))
    }

    fn from_parts(
        endpoint: Option<Url>,
        auth_headers: HeaderMap,
        transport: Arc<dyn TelemetryTransport>,
        policy: TelemetryPolicy,
        enabled: bool,
    ) -> Self {
        Self {
            endpoint,
            auth_headers,
            transport,
            policy,
            enabled,
            state: Arc::new(Mutex::new(if enabled {
                DeliveryState::enabled()
            } else {
                DeliveryState::disabled()
            })),
        }
    }
}

fn parse_endpoint(value: &str, allow_insecure: bool) -> Result<Url, TelemetryConfigError> {
    let endpoint = Url::parse(value).map_err(|_| TelemetryConfigError::InvalidEndpoint)?;
    if endpoint.host_str().is_none() {
        return Err(TelemetryConfigError::InvalidEndpoint);
    }
    if endpoint.username() != "" || endpoint.password().is_some() {
        return Err(TelemetryConfigError::EndpointCredentials);
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        return Err(TelemetryConfigError::EndpointQueryOrFragment);
    }

    let is_https = endpoint.scheme().eq_ignore_ascii_case("https");
    let is_http = endpoint.scheme().eq_ignore_ascii_case("http");
    if !is_https {
        if !allow_insecure && is_http {
            return Err(TelemetryConfigError::InsecureEndpoint);
        }
        if !(allow_insecure && is_http) {
            return Err(TelemetryConfigError::InvalidEndpoint);
        }
    }

    Ok(endpoint)
}

fn build_http_client(policy: TelemetryPolicy) -> Result<Client, TelemetryConfigError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        Client::builder()
            .timeout(policy.request_timeout())
            .build()
            .map_err(|_| TelemetryConfigError::HttpClientInitialization)
    }

    #[cfg(target_arch = "wasm32")]
    {
        let _ = policy;
        Client::builder()
            .build()
            .map_err(|_| TelemetryConfigError::HttpClientInitialization)
    }
}

fn build_auth_headers(api_key: &str) -> Result<HeaderMap, TelemetryConfigError> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if api_key.is_empty() {
        return Ok(headers);
    }

    let mut value =
        HeaderValue::from_str(api_key).map_err(|_| TelemetryConfigError::InvalidApiKey)?;
    value.set_sensitive(true);
    headers.insert(API_KEY_HEADER, value);
    Ok(headers)
}

fn telemetry_url(endpoint: &Url) -> Url {
    let mut url = endpoint.clone();
    let base_path = endpoint.path().trim_end_matches('/');
    let path = if base_path.is_empty() {
        format!("/{TELEMETRY_PATH}")
    } else {
        format!("{base_path}/{TELEMETRY_PATH}")
    };
    url.set_path(&path);
    url
}

async fn deliver_event(
    transport: Arc<dyn TelemetryTransport>,
    policy: TelemetryPolicy,
    state: Arc<Mutex<DeliveryState>>,
    request: TransportRequest,
) {
    for retry_index in 0..=policy.max_retries() {
        let result =
            match tokio::time::timeout(policy.request_timeout(), transport.send(request.clone()))
                .await
            {
                Ok(result) => result,
                Err(_) => Err(TransportError::Timeout),
            };

        match result {
            Ok(response) if (200..300).contains(&response.status) => {
                record_delivered(&state);
                return;
            }
            Ok(response) => {
                let retryable = is_retryable_status(response.status);
                if retryable && retry_index < policy.max_retries() {
                    wait_before_retry(policy, retry_index).await;
                    continue;
                }

                record_failure(
                    &state,
                    TelemetryFailure {
                        kind: TelemetryFailureKind::HttpStatus,
                        status_code: Some(response.status),
                        retries_exhausted: retryable && policy.max_retries() > 0,
                    },
                );
                return;
            }
            Err(error) => {
                let kind = match error {
                    TransportError::Timeout => TelemetryFailureKind::Timeout,
                    TransportError::Network => TelemetryFailureKind::Network,
                };
                if retry_index < policy.max_retries() {
                    wait_before_retry(policy, retry_index).await;
                    continue;
                }

                record_failure(
                    &state,
                    TelemetryFailure {
                        kind,
                        status_code: None,
                        retries_exhausted: policy.max_retries() > 0,
                    },
                );
                return;
            }
        }
    }
}

async fn wait_before_retry(policy: TelemetryPolicy, retry_index: u8) {
    let multiplier = 1_u32 << u32::from(retry_index);
    let delay = policy
        .retry_backoff()
        .checked_mul(multiplier)
        .unwrap_or(TelemetryPolicy::MAX_RETRY_BACKOFF);
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
}

fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
}

fn mark_pending(state: &Arc<Mutex<DeliveryState>>) {
    let mut state = match state.lock() {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    };
    state.status = TelemetryDeliveryStatus::Pending;
}

fn record_delivered(state: &Arc<Mutex<DeliveryState>>) {
    let mut state = match state.lock() {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    };
    state.status = TelemetryDeliveryStatus::Delivered;
}

fn record_failure(state: &Arc<Mutex<DeliveryState>>, failure: TelemetryFailure) {
    let mut state = match state.lock() {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    };
    state.status = TelemetryDeliveryStatus::Failed;
    state.last_failure = Some(failure);
    state.failure_count = state.failure_count.saturating_add(1);
}

#[cfg(test)]
#[derive(Clone, Default)]
struct TestTransport {
    requests: Arc<Mutex<Vec<TransportRequest>>>,
    responses: Arc<Mutex<std::collections::VecDeque<Result<TransportResponse, TransportError>>>>,
}

#[cfg(test)]
impl TestTransport {
    fn with_responses<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<TransportResponse, TransportError>>,
    {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(responses.into_iter().collect())),
        }
    }

    fn requests(&self) -> Vec<TransportRequest> {
        match self.requests.lock() {
            Ok(requests) => requests.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

#[cfg(test)]
impl TelemetryTransport for TestTransport {
    fn send(&self, request: TransportRequest) -> TransportFuture {
        let response = match self.responses.lock() {
            Ok(mut responses) => responses.pop_front(),
            Err(poisoned) => poisoned.into_inner().pop_front(),
        }
        .unwrap_or(Ok(TransportResponse { status: 204 }));

        match self.requests.lock() {
            Ok(mut requests) => requests.push(request),
            Err(poisoned) => poisoned.into_inner().push(request),
        }

        Box::pin(async move { response })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy(max_retries: u8) -> TelemetryPolicy {
        TelemetryPolicy::new(Duration::from_millis(100), max_retries, Duration::ZERO)
            .expect("test policy should be bounded")
    }

    fn success() -> Result<TransportResponse, TransportError> {
        Ok(TransportResponse { status: 204 })
    }

    async fn wait_for_delivery(client: &TelemetryClient) {
        for _ in 0..20 {
            if client.delivery_status() != TelemetryDeliveryStatus::Pending {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    #[test]
    fn payload_serialization_excludes_credentials_and_identifiers() {
        let serialized = serde_json::to_string(&TelemetryPayload {
            schema_version: 1,
            event: TelemetryEvent::SignedIntent,
        })
        .expect("static telemetry payload should serialize");

        assert!(serialized.contains("schema_version"));
        assert!(serialized.contains("signed_intent"));
        assert!(!serialized.contains("api_key"));
        assert!(!serialized.contains("signature_hash"));
        assert!(!serialized.contains("private_key"));
        assert!(!serialized.contains("attestation"));
    }

    #[tokio::test]
    async fn transport_keeps_credentials_in_headers_only() {
        let transport = Arc::new(TestTransport::with_responses([success()]));
        let client = TelemetryClient::with_test_transport(
            "http://telemetry.invalid",
            "test-api-key",
            test_policy(0),
            Arc::clone(&transport),
        )
        .expect("test transport should accept an HTTP test endpoint");

        assert_eq!(
            client.track_event(TelemetryEvent::SignedIntent),
            TelemetryDispatch::Scheduled
        );
        wait_for_delivery(&client).await;

        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        let body = String::from_utf8_lossy(&request.body);
        assert!(!body.contains("test-api-key"));
        assert!(!body.contains("signature_hash"));
        assert!(request
            .headers
            .get(API_KEY_HEADER)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == "test-api-key"));
        assert!(request.url.as_str().ends_with(TELEMETRY_PATH));
        assert_eq!(client.delivery_status(), TelemetryDeliveryStatus::Delivered);
    }

    #[test]
    fn production_endpoints_require_https_and_reject_ambiguous_urls() {
        assert!(matches!(
            TelemetryClient::try_new("http://telemetry.invalid".to_string(), "key".to_string()),
            Err(TelemetryConfigError::InsecureEndpoint)
        ));
        assert!(matches!(
            TelemetryClient::try_new("not-an-endpoint".to_string(), "key".to_string()),
            Err(TelemetryConfigError::InvalidEndpoint)
        ));
        assert!(matches!(
            TelemetryClient::try_new(
                "https://user:password@telemetry.invalid".to_string(),
                "key".to_string()
            ),
            Err(TelemetryConfigError::EndpointCredentials)
        ));
        assert!(matches!(
            TelemetryClient::try_new(
                "https://telemetry.invalid?token=redacted".to_string(),
                "key".to_string()
            ),
            Err(TelemetryConfigError::EndpointQueryOrFragment)
        ));
    }

    #[test]
    fn delivery_policy_rejects_unbounded_values() {
        assert!(matches!(
            TelemetryPolicy::new(Duration::ZERO, 0, Duration::ZERO),
            Err(TelemetryConfigError::InvalidTimeout)
        ));
        assert!(matches!(
            TelemetryPolicy::new(
                TelemetryPolicy::MAX_REQUEST_TIMEOUT,
                TelemetryPolicy::MAX_RETRIES + 1,
                Duration::ZERO
            ),
            Err(TelemetryConfigError::InvalidRetryCount)
        ));
        assert!(matches!(
            TelemetryPolicy::new(
                Duration::from_secs(1),
                0,
                TelemetryPolicy::MAX_RETRY_BACKOFF + Duration::from_nanos(1)
            ),
            Err(TelemetryConfigError::InvalidRetryBackoff)
        ));
    }

    #[test]
    fn invalid_compatibility_configuration_fails_closed_without_panic() {
        let client =
            TelemetryClient::new("http://telemetry.invalid".to_string(), "key".to_string());

        assert_eq!(
            client.track_event(TelemetryEvent::SignedIntent),
            TelemetryDispatch::Disabled
        );
        assert_eq!(client.delivery_status(), TelemetryDeliveryStatus::Failed);
        assert_eq!(client.failure_count(), 1);
        assert_eq!(
            client.last_failure().map(|failure| failure.kind),
            Some(TelemetryFailureKind::Configuration)
        );
    }

    #[test]
    fn disabled_mode_is_explicit_and_side_effect_free() {
        let client = TelemetryClient::disabled();

        assert_eq!(
            client.track_event(TelemetryEvent::SignedIntent),
            TelemetryDispatch::Disabled
        );
        assert_eq!(client.delivery_status(), TelemetryDeliveryStatus::Disabled);
        assert_eq!(client.failure_count(), 0);
    }

    #[tokio::test]
    async fn timeout_retries_are_bounded_and_observable() {
        let transport = Arc::new(TestTransport::with_responses([
            Err(TransportError::Timeout),
            Err(TransportError::Timeout),
            Err(TransportError::Timeout),
        ]));
        let client = TelemetryClient::with_test_transport(
            "http://telemetry.invalid",
            "",
            test_policy(2),
            Arc::clone(&transport),
        )
        .expect("test transport should be constructible");

        assert_eq!(
            client.track_event(TelemetryEvent::SignedIntent),
            TelemetryDispatch::Scheduled
        );
        wait_for_delivery(&client).await;

        assert_eq!(transport.requests().len(), 3);
        assert_eq!(client.delivery_status(), TelemetryDeliveryStatus::Failed);
        assert_eq!(client.failure_count(), 1);
        assert_eq!(
            client.last_failure(),
            Some(TelemetryFailure {
                kind: TelemetryFailureKind::Timeout,
                status_code: None,
                retries_exhausted: true,
            })
        );
    }

    #[tokio::test]
    async fn retryable_http_failure_can_recover_without_blocking() {
        let transport = Arc::new(TestTransport::with_responses([
            Ok(TransportResponse { status: 503 }),
            success(),
        ]));
        let client = TelemetryClient::with_test_transport(
            "http://telemetry.invalid",
            "",
            test_policy(1),
            Arc::clone(&transport),
        )
        .expect("test transport should be constructible");

        assert_eq!(
            client.track_event(TelemetryEvent::SignedIntent),
            TelemetryDispatch::Scheduled
        );
        wait_for_delivery(&client).await;

        assert_eq!(transport.requests().len(), 2);
        assert_eq!(client.delivery_status(), TelemetryDeliveryStatus::Delivered);
        assert_eq!(client.failure_count(), 0);
    }

    #[test]
    fn scheduling_without_a_runtime_is_observable_and_does_not_panic() {
        let transport = Arc::new(TestTransport::with_responses([success()]));
        let client = TelemetryClient::with_test_transport(
            "http://telemetry.invalid",
            "",
            test_policy(0),
            transport,
        )
        .expect("test transport should be constructible");

        assert_eq!(
            client.track_event(TelemetryEvent::SignedIntent),
            TelemetryDispatch::Rejected(TelemetryFailureKind::NoRuntime)
        );
        assert_eq!(client.delivery_status(), TelemetryDeliveryStatus::Failed);
        assert_eq!(
            client.last_failure().map(|failure| failure.kind),
            Some(TelemetryFailureKind::NoRuntime)
        );
    }
}
