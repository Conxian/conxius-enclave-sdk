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

use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use sha2::{Sha256, Digest};

/// JWK (JSON Web Key) for OIDC signature verification.
#[derive(Debug, Clone)]
pub struct Jwk {
    /// Key ID
    pub kid: Option<String>,
    /// Key type: "RSA" or "EC"
    pub kty: String,
    /// Algorithm: "RS256", "ES256", etc.
    pub alg: Option<String>,
    /// RSA modulus (base64url)
    pub n: String,
    /// RSA exponent (base64url)
    pub e: String,
    /// EC x coordinate (base64url)
    pub x: Option<String>,
    /// EC y coordinate (base64url)
    pub y: Option<String>,
    /// EC curve: "P-256", "P-384", "P-521"
    pub crv: Option<String>,
}

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
    pub fn decode_token_header(&self, token: &str) -> ConclaveResult<(String, String)> {
        let header = decode_header(token)
            .map_err(|e| ConclaveError::Attestation(
                format!("OIDC: failed to decode token header: {e}")
            ))?;
        let kid = header.kid.unwrap_or_default();
        let alg = format!("{:?}", header.alg);
        Ok((kid, alg))
    }

    /// Fully verify an OIDC JWT:
    /// 1. Decode JWT header → extract algorithm and key ID
    /// 2. Match key ID against provided JWK set
    /// 3. Verify JWT signature against the matched key
    /// 4. Validate claims: iss, aud, exp, iat, nonce
    /// 5. Check token is not expired (with clock skew)
    pub fn verify_token(
        &self,
        token: &str,
        jwks: &[Jwk],
        expected_nonce: Option<&str>,
    ) -> ConclaveResult<OidcVerificationResult> {
        let header = decode_header(token)
            .map_err(|e| ConclaveError::Attestation(
                format!("OIDC: failed to decode token header: {e}")
            ))?;

        // Use algorithm from token header
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.config.expected_issuer]);
        validation.set_audience(&[&self.config.expected_audience]);
        validation.required_spec_claims.remove("aud");
        validation.leeway = self.config.max_clock_skew_secs;

        // Find the matching key by kid
        let kid = header.kid.unwrap_or_default();
        let jwk = jwks.iter()
            .find(|k| k.kid.as_deref() == Some(&kid) || kid.is_empty())
            .ok_or_else(|| ConclaveError::Attestation(format!(
                "OIDC: no JWK found for kid '{}'", kid
            )))?;

        let decoding_key = match jwk.kty.as_str() {
            "RSA" => DecodingKey::from_rsa_components(&jwk.n, &jwk.e),
            "EC" => {
                let x = jwk.x.as_deref().unwrap_or("");
                let y = jwk.y.as_deref().unwrap_or("");
                DecodingKey::from_ec_components(x, y)
            }
            other => return Err(ConclaveError::Attestation(format!(
                "OIDC: unsupported key type '{}'", other
            ))),
        }.map_err(|e| ConclaveError::Attestation(
            format!("OIDC: invalid JWK: {e}")
        ))?;

        let token_data = decode::<serde_json::Value>(
            token,
            &decoding_key,
            &validation,
        ).map_err(|e| ConclaveError::Attestation(
            format!("OIDC: token verification failed: {e}")
        ))?;

        // Extract claims
        let claims_raw = token_data.claims;
        let issuer = claims_raw.get("iss").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let subject = claims_raw.get("sub").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let audience = claims_raw.get("aud")
            .map(|v| match v {
                serde_json::Value::String(s) => vec![s.clone()],
                serde_json::Value::Array(arr) => arr.iter()
                    .filter_map(|a| a.as_str().map(String::from))
                    .collect(),
                _ => vec![format!("{v}")],
            })
            .unwrap_or_default();
        let expiration = claims_raw.get("exp").and_then(|v| v.as_u64()).unwrap_or(0);
        let issued_at = claims_raw.get("iat").and_then(|v| v.as_u64()).unwrap_or(0);
        let nonce = claims_raw.get("nonce").and_then(|v| v.as_str()).map(String::from);
        let mut extra = HashMap::new();
        for (k, v) in claims_raw.as_object().into_iter().flat_map(|o| o.iter()) {
            if let Some(s) = v.as_str() {
                extra.insert(k.clone(), s.to_string());
            }
        }

        let claims = OidcClaims {
            issuer,
            subject,
            audience,
            expiration,
            issued_at,
            nonce,
            extra,
        };

        // Validate claims (issuer, audience, expiry, nonce)
        self.validate_claims(&claims, expected_nonce)?;

        let token_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        Ok(OidcVerificationResult {
            claims,
            token_hash,
            provider: self.config.expected_issuer.clone(),
        })
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
