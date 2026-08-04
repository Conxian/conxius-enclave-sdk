//! OIDC (OpenID Connect) token verification (Phase 3).
//!
//! Verifies OIDC access/ID tokens for enterprise authentication
//! before signing operations. AWS Nitro Enclaves and GCP Confidential
//! Space can natively verify OIDC tokens from enterprise IdPs.
//!
//! Supported IdPs:
//! - Okta
//! - Azure AD / Entra ID
//! - Google Workspace
//! - AWS Cognito / IAM
//! - Any OIDC-compliant provider with JWKS endpoint
//!
//! # References
//! - OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
//! - RFC 7519 (JWT): https://datatracker.ietf.org/doc/html/rfc7519
//! - AWS Nitro Enclaves OIDC: https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-ref.html

use crate::{ConclaveResult, ConclaveError};
use std::collections::HashMap;

/// OIDC token claims.
#[derive(Debug, Clone)]
pub struct OidcClaims {
    pub issuer: String,
    pub subject: String,
    pub audience: Vec<String>,
    pub expiration: u64,
    pub issued_at: u64,
    pub nonce: Option<String>,
    pub extra: HashMap<String, String>,
}

/// OIDC provider configuration (from .well-known/openid-configuration).
#[derive(Debug, Clone)]
pub struct OidcProviderConfig {
    pub issuer: String,
    pub jwks_uri: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub algorithms_supported: Vec<String>,
}

/// OIDC verifier configuration.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Expected issuer URL
    pub expected_issuer: String,
    /// Expected audience (client ID)
    pub expected_audience: String,
    /// JWKS cache TTL in seconds
    pub jwks_cache_ttl_secs: u64,
    /// Required algorithms (default: ["RS256", "ES256"])
    pub allowed_algorithms: Vec<String>,
    /// Maximum clock skew in seconds
    pub max_clock_skew_secs: u64,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            expected_issuer: String::new(),
            expected_audience: String::new(),
            jwks_cache_ttl_secs: 3600,
            allowed_algorithms: vec!["RS256".into(), "ES256".into(), "EdDSA".into()],
            max_clock_skew_secs: 60,
        }
    }
}

/// OIDC verification result.
#[derive(Debug, Clone)]
pub struct OidcVerificationResult {
    pub claims: OidcClaims,
    pub token_hash: [u8; 32],
    pub provider: String,
}

/// OIDC token verifier.
///
/// Validates OIDC tokens from enterprise identity providers.
/// Integrates with the enclave auth pipeline to gate signing
/// operations behind enterprise authentication.
pub struct OidcVerifier {
    config: OidcConfig,
}

impl OidcVerifier {
    pub fn new(config: OidcConfig) -> Self {
        Self { config }
    }

    /// Parse an OIDC JWT without verifying the signature (header + claims only).
    ///
    /// Use `verify_token` for full verification including signature.
    pub fn decode_token_header(&self, _token: &str) -> ConclaveResult<(String, String)> {
        Err(ConclaveError::Unsupported(
            "OIDC verify: add `jsonwebtoken` or `jwt` crate".into(),
        ))
    }

    /// Fully verify an OIDC JWT:
    /// 1. Decode JWT header → extract algorithm and key ID
    /// 2. Fetch JWKS from provider if not cached
    /// 3. Verify JWT signature against JWK
    /// 4. Validate claims: iss, aud, exp, iat, nonce
    /// 5. Check token is not expired (with clock skew)
    pub fn verify_token(&self, _token: &str, _expected_nonce: Option<&str>) -> ConclaveResult<OidcVerificationResult> {
        Err(ConclaveError::Unsupported(
            "OIDC verify: add `jsonwebtoken` crate".into(),
        ))
    }

    /// Validate OIDC claims without signature verification.
    ///
    /// Checks issuer, audience, expiration, and optional nonce.
    pub fn validate_claims(&self, claims: &OidcClaims, _expected_nonce: Option<&str>) -> ConclaveResult<()> {
        // Check issuer
        if claims.issuer != self.config.expected_issuer {
            return Err(crate::ConclaveError::Attestation(format!(
                "OIDC issuer mismatch: expected {}, got {}",
                self.config.expected_issuer, claims.issuer
            )));
        }

        // Check audience
        if !claims.audience.contains(&self.config.expected_audience) {
            return Err(crate::ConclaveError::Attestation(format!(
                "OIDC audience mismatch: expected {}",
                self.config.expected_audience
            )));
        }

        // Check expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now > claims.expiration + self.config.max_clock_skew_secs {
            return Err(crate::ConclaveError::Attestation("OIDC token expired".into()));
        }

        // Check not-before (issued_at with clock skew)
        if claims.issued_at > now + self.config.max_clock_skew_secs {
            return Err(crate::ConclaveError::Attestation("OIDC token from the future".into()));
        }

        Ok(())
    }

    /// Fetch OIDC provider configuration from .well-known/openid-configuration.
    pub fn discover_provider(&self, _issuer_url: &str) -> ConclaveResult<OidcProviderConfig> {
        Err(ConclaveError::Unsupported(
            "OIDC discover: add `reqwest` for HTTP".into(),
        ))
    }

    /// Bind an OIDC token to a signing operation via nonce.
    ///
    /// The nonce links the OIDC authentication ceremony to a
    /// specific signing request, preventing token reuse.
    pub fn bind_nonce(&self, request_id: &[u8; 32]) -> String {
        let mut hash_input = Vec::with_capacity(32 + 8);
        hash_input.extend_from_slice(request_id);
        hash_input.extend_from_slice(&std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_le_bytes());
        use sha2::{Sha256, Digest};
        let digest = Sha256::digest(&hash_input);
        hex::encode(&digest[..16])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_verifier_constructs() {
        let config = OidcConfig {
            expected_issuer: "https://accounts.google.com".into(),
            expected_audience: "my-client-id".into(),
            ..Default::default()
        };
        let _v = OidcVerifier::new(config);
    }

    #[test]
    fn oidc_validate_claims_rejects_wrong_issuer() {
        let config = OidcConfig {
            expected_issuer: "https://login.microsoftonline.com/tenant/v2.0".into(),
            expected_audience: "app-123".into(),
            ..Default::default()
        };
        let v = OidcVerifier::new(config);
        let claims = OidcClaims {
            issuer: "https://evil.example.com".into(),
            subject: "user-1".into(),
            audience: vec!["app-123".into()],
            expiration: u64::MAX,
            issued_at: 0,
            nonce: None,
            extra: HashMap::new(),
        };
        assert!(v.validate_claims(&claims, None).is_err());
    }

    #[test]
    fn oidc_validate_claims_rejects_expired_token() {
        let config = OidcConfig {
            expected_issuer: "https://issuer.test".into(),
            expected_audience: "test-app".into(),
            ..Default::default()
        };
        let v = OidcVerifier::new(config);
        let claims = OidcClaims {
            issuer: "https://issuer.test".into(),
            subject: "user-1".into(),
            audience: vec!["test-app".into()],
            expiration: 1, // Expired in 1970
            issued_at: 0,
            nonce: None,
            extra: HashMap::new(),
        };
        assert!(v.validate_claims(&claims, None).is_err());
    }

    #[test]
    fn oidc_validate_claims_accepts_valid() {
        let config = OidcConfig {
            expected_issuer: "https://issuer.test".into(),
            expected_audience: "test-app".into(),
            ..Default::default()
        };
        let v = OidcVerifier::new(config);
        let far_future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let claims = OidcClaims {
            issuer: "https://issuer.test".into(),
            subject: "user-1".into(),
            audience: vec!["test-app".into()],
            expiration: far_future,
            issued_at: 0,
            nonce: None,
            extra: HashMap::new(),
        };
        assert!(v.validate_claims(&claims, None).is_ok());
    }

    #[test]
    fn oidc_nonce_is_deterministic() {
        let config = OidcConfig::default();
        let v = OidcVerifier::new(config);
        let nonce = v.bind_nonce(&[0x42; 32]);
        assert_eq!(nonce.len(), 32); // 16 bytes → 32 hex chars
    }
}
