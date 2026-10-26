//! WebAuthn/FIDO2 attestation verifier (Phase 3).
//!
//! Verifies FIDO2/WebAuthn attestation statements from:
//! - Apple Secure Enclave (via TouchID/FaceID)
//! - Android KeyStore (via BiometricPrompt)
//! - Windows Hello (TPM 2.0)
//! - External FIDO2 keys (YubiKey, Solo, etc.)
//!
//! Attestation statement formats supported:
//! - `packed` (FIDO2 standard, ECDSA/EdDSA)
//! - `tpm` (TPM 2.0 attestation)
//! - `android-safetynet` / `android-key` (Android KeyStore attestation)
//! - `apple` (Apple Anonymous Attestation)
//! - `none` (no attestation — self-assertion only)
//!
//! # References
//! - WebAuthn Level 3: https://www.w3.org/TR/webauthn-3/
//! - FIDO2 Attestation: https://fidoalliance.org/specs/
//! - webauthn-rs crate: https://docs.rs/webauthn-rs/

use crate::{ConclaveError, ConclaveResult};
use ciborium::value::Value;
use sha2::{Digest, Sha256};
use std::io::Cursor;

/// WebAuthn client data (parsed from clientDataJSON).
#[derive(Debug, Clone, serde::Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    #[allow(dead_code)]
    cross_origin: bool,
}

/// WebAuthn attestation statement format.
#[derive(Debug, Clone, PartialEq)]
pub enum AttestationFormat {
    Packed,
    Tpm,
    AndroidKey,
    AndroidSafetyNet,
    Apple,
    None_,
}

#[derive(Debug)]
struct ParsedAuthenticatorData {
    credential_id: Option<Vec<u8>>,
    credential_public_key: Option<Vec<u8>>,
    aaguid: Option<[u8; 16]>,
    sign_count: u32,
    user_verified: bool,
}

fn attestation_error(message: impl Into<String>) -> ConclaveError {
    ConclaveError::Attestation(format!("WebAuthn: {}", message.into()))
}

fn map_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| match candidate {
            Value::Text(candidate) if candidate == key => Some(value),
            _ => None,
        })
}

fn decode_cbor_prefix(bytes: &[u8], label: &str) -> ConclaveResult<(Value, usize)> {
    if bytes.is_empty() {
        return Err(attestation_error(format!("{label} is empty")));
    }
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader(&mut cursor)
        .map_err(|error| attestation_error(format!("invalid {label} CBOR: {error}")))?;
    let consumed = usize::try_from(cursor.position())
        .map_err(|_| attestation_error(format!("{label} length overflow")))?;
    if consumed == 0 || consumed > bytes.len() {
        return Err(attestation_error(format!("invalid {label} length")));
    }
    Ok((value, consumed))
}

fn parse_authenticator_data(
    bytes: &[u8],
    rp_id: &str,
    registration: bool,
) -> ConclaveResult<ParsedAuthenticatorData> {
    if bytes.len() < 37 {
        return Err(attestation_error("authenticatorData is truncated"));
    }

    let expected_rp_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if bytes[..32] != expected_rp_hash {
        return Err(attestation_error("RP ID hash mismatch"));
    }

    let flags = bytes[32];
    if flags & 0x01 == 0 {
        return Err(attestation_error("user-presence flag is missing"));
    }
    let has_attested_data = flags & 0x40 != 0;
    if registration != has_attested_data {
        return Err(attestation_error(if registration {
            "registration is missing attested credential data"
        } else {
            "authentication unexpectedly contains attested credential data"
        }));
    }

    let sign_count = u32::from_be_bytes(bytes[33..37].try_into().expect("fixed bounds"));
    let mut offset = 37;
    let mut credential_id = None;
    let mut credential_public_key = None;
    let mut aaguid = None;

    if registration {
        if bytes.len() < offset + 18 {
            return Err(attestation_error("attested credential data is truncated"));
        }
        let mut parsed_aaguid = [0u8; 16];
        parsed_aaguid.copy_from_slice(&bytes[offset..offset + 16]);
        aaguid = Some(parsed_aaguid);
        offset += 16;

        let credential_id_len =
            u16::from_be_bytes(bytes[offset..offset + 2].try_into().expect("fixed bounds"))
                as usize;
        offset += 2;
        let credential_id_end = offset
            .checked_add(credential_id_len)
            .ok_or_else(|| attestation_error("credential ID length overflow"))?;
        if credential_id_len == 0 || credential_id_end > bytes.len() {
            return Err(attestation_error("credential ID is empty or truncated"));
        }
        credential_id = Some(bytes[offset..credential_id_end].to_vec());
        offset = credential_id_end;

        let (public_key, consumed) = decode_cbor_prefix(&bytes[offset..], "credential public key")?;
        if !matches!(public_key, Value::Map(_)) {
            return Err(attestation_error(
                "credential public key must be a CBOR map",
            ));
        }
        credential_public_key = Some(bytes[offset..offset + consumed].to_vec());
        offset += consumed;
    }

    if flags & 0x80 != 0 {
        let (_, consumed) = decode_cbor_prefix(&bytes[offset..], "authenticator extensions")?;
        offset += consumed;
    }
    if offset != bytes.len() {
        return Err(attestation_error(
            "authenticatorData has unexpected trailing bytes",
        ));
    }

    Ok(ParsedAuthenticatorData {
        credential_id,
        credential_public_key,
        aaguid,
        sign_count,
        user_verified: flags & 0x04 != 0,
    })
}

fn parse_attestation_object(
    bytes: &[u8],
    rp_id: &str,
) -> ConclaveResult<(AttestationFormat, ParsedAuthenticatorData)> {
    let (value, consumed) = decode_cbor_prefix(bytes, "attestationObject")?;
    if consumed != bytes.len() {
        return Err(attestation_error("attestationObject has trailing bytes"));
    }
    let Value::Map(entries) = value else {
        return Err(attestation_error("attestationObject must be a CBOR map"));
    };

    let format = match map_value(&entries, "fmt") {
        Some(Value::Text(format)) => match format.as_str() {
            "packed" => AttestationFormat::Packed,
            "tpm" => AttestationFormat::Tpm,
            "android-key" => AttestationFormat::AndroidKey,
            "android-safetynet" => AttestationFormat::AndroidSafetyNet,
            "apple" => AttestationFormat::Apple,
            "none" => AttestationFormat::None_,
            _ => {
                return Err(attestation_error(format!(
                    "unsupported attestation format '{format}'"
                )))
            }
        },
        _ => return Err(attestation_error("attestationObject fmt must be text")),
    };
    let auth_data = match map_value(&entries, "authData") {
        Some(Value::Bytes(bytes)) => bytes,
        _ => {
            return Err(attestation_error(
                "attestationObject authData must be bytes",
            ))
        }
    };
    if !matches!(map_value(&entries, "attStmt"), Some(Value::Map(_))) {
        return Err(attestation_error(
            "attestationObject attStmt must be a CBOR map",
        ));
    }

    Ok((format, parse_authenticator_data(auth_data, rp_id, true)?))
}

/// WebAuthn credential with attestation evidence.
#[derive(Debug, Clone)]
pub struct WebauthnCredential {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub attestation_format: AttestationFormat,
    pub aaguid: [u8; 16],
    pub sign_count: u32,
    pub user_verified: bool,
    pub attestation_trusted: bool,
}

/// WebAuthn verifier configuration.
#[derive(Debug, Clone)]
pub struct WebauthnConfig {
    /// Relying Party ID (domain name)
    pub rp_id: String,
    /// Relying Party name (display)
    pub rp_name: String,
    /// Allowed credential IDs (empty = all)
    pub allowed_credentials: Vec<Vec<u8>>,
    /// Require attestation verification (vs. self-assertion)
    pub require_attestation: bool,
    /// Trusted attestation CA certificates (PEM)
    pub trusted_attestation_cas: Vec<Vec<u8>>,
}

/// WebAuthn/FIDO2 attestation verifier.
///
/// Verifies WebAuthn registration and authentication ceremonies,
/// with optional attestation statement verification for hardware
/// provenance.
pub struct WebauthnVerifier {
    #[allow(dead_code)]
    config: WebauthnConfig,
}

impl WebauthnVerifier {
    pub fn new(config: WebauthnConfig) -> Self {
        Self { config }
    }

    /// Validate client data JSON against expected challenge and origin.
    fn validate_client_data(
        &self,
        client_data_json: &[u8],
        challenge_b64: &str,
        origin: &str,
        expected_type: &str,
    ) -> ConclaveResult<ClientData> {
        let cd: ClientData = serde_json::from_slice(client_data_json).map_err(|e| {
            ConclaveError::Attestation(format!("WebAuthn: invalid clientDataJSON: {e}"))
        })?;

        if cd.typ != expected_type {
            return Err(ConclaveError::Attestation(format!(
                "WebAuthn: expected type '{expected_type}', got '{}'",
                cd.typ
            )));
        }

        if cd.challenge != challenge_b64 {
            return Err(ConclaveError::Attestation(
                "WebAuthn: challenge mismatch".into(),
            ));
        }

        if cd.origin != origin {
            return Err(ConclaveError::Attestation(format!(
                "WebAuthn: origin mismatch: expected '{origin}', got '{}'",
                cd.origin
            )));
        }

        Ok(cd)
    }

    /// Verify a WebAuthn registration response (attestation).
    #[cfg(feature = "webauthn")]
    pub fn verify_registration(
        &self,
        _attestation_object: &[u8],
        client_data_json: &[u8],
        challenge: &[u8],
        origin: &str,
    ) -> ConclaveResult<WebauthnCredential> {
        let challenge_b64 = base64_url(challenge);
        let _cd =
            self.validate_client_data(client_data_json, &challenge_b64, origin, "webauthn.create")?;
        if self.config.require_attestation && self.config.trusted_attestation_cas.is_empty() {
            return Err(attestation_error(
                "attestation is required but no trust anchors are configured",
            ));
        }
        let (format, parsed) = parse_attestation_object(_attestation_object, &self.config.rp_id)?;
        if self.config.require_attestation && format == AttestationFormat::None_ {
            return Err(attestation_error(
                "attestation is required but the credential uses fmt=none",
            ));
        }
        let _structural_credential = WebauthnCredential {
            credential_id: parsed
                .credential_id
                .expect("registration parser sets credential ID"),
            public_key: parsed
                .credential_public_key
                .expect("registration parser sets credential public key"),
            attestation_format: format,
            aaguid: parsed.aaguid.expect("registration parser sets AAGUID"),
            sign_count: parsed.sign_count,
            user_verified: parsed.user_verified,
            attestation_trusted: false,
        };

        Err(ConclaveError::Unsupported(
            "WebAuthn attestation: structural validation passed; cryptographic webauthn-rs verification pending".into(),
        ))
    }

    #[cfg(not(feature = "webauthn"))]
    pub fn verify_registration(
        &self,
        _attestation_object: &[u8],
        client_data_json: &[u8],
        challenge: &[u8],
        origin: &str,
    ) -> ConclaveResult<WebauthnCredential> {
        let challenge_b64 = base64_url(challenge);
        let _cd =
            self.validate_client_data(client_data_json, &challenge_b64, origin, "webauthn.create")?;
        if self.config.require_attestation && self.config.trusted_attestation_cas.is_empty() {
            return Err(attestation_error(
                "attestation is required but no trust anchors are configured",
            ));
        }
        let (format, _) = parse_attestation_object(_attestation_object, &self.config.rp_id)?;
        if self.config.require_attestation && format == AttestationFormat::None_ {
            return Err(attestation_error(
                "attestation is required but the credential uses fmt=none",
            ));
        }
        Err(ConclaveError::Unsupported(
            "WebAuthn structural validation passed; enable `webauthn` for cryptographic verification".into(),
        ))
    }

    /// Verify a WebAuthn authentication response (assertion).
    #[cfg(feature = "webauthn")]
    pub fn verify_authentication(
        &self,
        _credential: &WebauthnCredential,
        authenticator_data: &[u8],
        client_data_json: &[u8],
        _signature: &[u8],
        challenge: &[u8],
        origin: &str,
    ) -> ConclaveResult<bool> {
        let challenge_b64 = base64_url(challenge);
        let _cd =
            self.validate_client_data(client_data_json, &challenge_b64, origin, "webauthn.get")?;

        let _parsed = parse_authenticator_data(authenticator_data, &self.config.rp_id, false)?;
        let client_data_hash: [u8; 32] = Sha256::digest(client_data_json).into();
        let mut signed_data = Vec::with_capacity(authenticator_data.len() + 32);
        signed_data.extend_from_slice(authenticator_data);
        signed_data.extend_from_slice(&client_data_hash);

        Err(ConclaveError::Unsupported(
            "WebAuthn assertion: full webauthn-rs signature verification pending".into(),
        ))
    }

    #[cfg(not(feature = "webauthn"))]
    pub fn verify_authentication(
        &self,
        _credential: &WebauthnCredential,
        _authenticator_data: &[u8],
        client_data_json: &[u8],
        _signature: &[u8],
        challenge: &[u8],
        origin: &str,
    ) -> ConclaveResult<bool> {
        let challenge_b64 = base64_url(challenge);
        let _cd =
            self.validate_client_data(client_data_json, &challenge_b64, origin, "webauthn.get")?;
        let _parsed = parse_authenticator_data(_authenticator_data, &self.config.rp_id, false)?;
        Err(ConclaveError::Unsupported(
            "WebAuthn structural validation passed; enable `webauthn` for cryptographic verification".into(),
        ))
    }

    /// Generate a WebAuthn registration challenge.
    pub fn generate_challenge(&self) -> ConclaveResult<(Vec<u8>, String)> {
        let mut challenge = vec![0u8; 32];
        getrandom::fill(&mut challenge).map_err(|error| {
            ConclaveError::Attestation(format!("WebAuthn: challenge RNG failed: {error}"))
        })?;
        let b64 = base64_url(&challenge);
        Ok((challenge, b64))
    }

    /// Check if a credential is hardware-attested (vs. self-asserted).
    pub fn is_hardware_attested(&self, credential: &WebauthnCredential) -> bool {
        credential.attestation_trusted
            && credential.attestation_format != AttestationFormat::None_
            && credential.user_verified
    }

    /// Map attestation format to hardware tier.
    pub fn hardware_tier(&self, credential: &WebauthnCredential) -> &'static str {
        match credential.attestation_format {
            AttestationFormat::Apple | AttestationFormat::AndroidKey => "StrongBox",
            AttestationFormat::Tpm => "TEE",
            AttestationFormat::Packed => {
                if credential.attestation_trusted {
                    "TEE"
                } else {
                    "Software"
                }
            }
            AttestationFormat::None_ | AttestationFormat::AndroidSafetyNet => "Software",
        }
    }
}

fn base64_url(data: &[u8]) -> String {
    // Base64url without padding
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[(n & 0x3F) as usize] as char);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webauthn_verifier_constructs() {
        let config = WebauthnConfig {
            rp_id: "example.com".into(),
            rp_name: "Example".into(),
            allowed_credentials: vec![],
            require_attestation: true,
            trusted_attestation_cas: vec![],
        };
        let _v = WebauthnVerifier::new(config);
    }

    #[test]
    fn webauthn_generate_challenge() {
        let config = WebauthnConfig {
            rp_id: "test.local".into(),
            rp_name: "Test".into(),
            allowed_credentials: vec![],
            require_attestation: false,
            trusted_attestation_cas: vec![],
        };
        let v = WebauthnVerifier::new(config);
        let (challenge, b64) = v.generate_challenge().unwrap();
        assert_eq!(challenge.len(), 32);
        assert!(!b64.is_empty());
    }

    #[test]
    fn webauthn_hardware_tier_classification() {
        let apple_cred = WebauthnCredential {
            credential_id: vec![1],
            public_key: vec![],
            attestation_format: AttestationFormat::Apple,
            aaguid: [0; 16],
            sign_count: 0,
            user_verified: true,
            attestation_trusted: true,
        };
        let config = WebauthnConfig {
            rp_id: "test".into(),
            rp_name: "test".into(),
            allowed_credentials: vec![],
            require_attestation: false,
            trusted_attestation_cas: vec![],
        };
        let v = WebauthnVerifier::new(config);
        assert_eq!(v.hardware_tier(&apple_cred), "StrongBox");
    }

    #[test]
    fn attestation_formats_distinct() {
        assert_ne!(AttestationFormat::Apple, AttestationFormat::Tpm);
        assert_ne!(AttestationFormat::Packed, AttestationFormat::None_);
    }

    #[test]
    fn client_data_validation_rejects_wrong_type() {
        let config = WebauthnConfig {
            rp_id: "test.local".into(),
            rp_name: "Test".into(),
            allowed_credentials: vec![],
            require_attestation: false,
            trusted_attestation_cas: vec![],
        };
        let v = WebauthnVerifier::new(config);
        let cd = r#"{"type":"webauthn.get","challenge":"AAAA","origin":"https://test.local"}"#;
        let result = v.validate_client_data(
            cd.as_bytes(),
            "AAAA",
            "https://test.local",
            "webauthn.create",
        );
        assert!(result.is_err());
    }

    #[test]
    fn client_data_validation_accepts_valid() {
        let config = WebauthnConfig {
            rp_id: "test.local".into(),
            rp_name: "Test".into(),
            allowed_credentials: vec![],
            require_attestation: false,
            trusted_attestation_cas: vec![],
        };
        let v = WebauthnVerifier::new(config);
        let cd = r#"{"type":"webauthn.create","challenge":"AAAA","origin":"https://test.local"}"#;
        let result = v.validate_client_data(
            cd.as_bytes(),
            "AAAA",
            "https://test.local",
            "webauthn.create",
        );
        assert!(result.is_ok());
    }
    fn test_config(require_attestation: bool) -> WebauthnConfig {
        WebauthnConfig {
            rp_id: "test.local".into(),
            rp_name: "Test".into(),
            allowed_credentials: vec![],
            require_attestation,
            trusted_attestation_cas: if require_attestation {
                vec![b"test-anchor".to_vec()]
            } else {
                vec![]
            },
        }
    }

    fn registration_auth_data(rp_id: &str, flags: u8, truncate: bool) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        data.push(flags);
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&2u16.to_be_bytes());
        data.extend_from_slice(&[0x01, 0x02]);
        let key = Value::Map(vec![(Value::Integer(1.into()), Value::Integer(2.into()))]);
        ciborium::ser::into_writer(&key, &mut data).unwrap();
        if truncate {
            data.pop();
        }
        data
    }

    fn attestation_object(fmt: Value, auth_data: Value, att_stmt: Value) -> Vec<u8> {
        let value = Value::Map(vec![
            (Value::Text("fmt".into()), fmt),
            (Value::Text("authData".into()), auth_data),
            (Value::Text("attStmt".into()), att_stmt),
        ]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded).unwrap();
        encoded
    }

    #[test]
    fn registration_rejects_malformed_cbor_and_typed_fields() {
        let verifier = WebauthnVerifier::new(test_config(false));
        assert!(parse_attestation_object(&[0xff], &verifier.config.rp_id).is_err());
        let auth = registration_auth_data("test.local", 0x41, false);
        let wrong_fmt = attestation_object(
            Value::Integer(1.into()),
            Value::Bytes(auth.clone()),
            Value::Map(vec![]),
        );
        assert!(parse_attestation_object(&wrong_fmt, &verifier.config.rp_id).is_err());
        let wrong_stmt = attestation_object(
            Value::Text("packed".into()),
            Value::Bytes(auth),
            Value::Bytes(vec![]),
        );
        assert!(parse_attestation_object(&wrong_stmt, &verifier.config.rp_id).is_err());
    }

    #[test]
    fn registration_rejects_wrong_rp_hash_and_truncated_credential_data() {
        let wrong_rp = attestation_object(
            Value::Text("packed".into()),
            Value::Bytes(registration_auth_data("other.local", 0x41, false)),
            Value::Map(vec![]),
        );
        assert!(parse_attestation_object(&wrong_rp, "test.local").is_err());

        let truncated = attestation_object(
            Value::Text("packed".into()),
            Value::Bytes(registration_auth_data("test.local", 0x41, true)),
            Value::Map(vec![]),
        );
        assert!(parse_attestation_object(&truncated, "test.local").is_err());
    }

    #[test]
    fn registration_requires_attested_flag_and_supported_format() {
        let no_at = attestation_object(
            Value::Text("packed".into()),
            Value::Bytes(registration_auth_data("test.local", 0x01, false)),
            Value::Map(vec![]),
        );
        assert!(parse_attestation_object(&no_at, "test.local").is_err());

        let unsupported = attestation_object(
            Value::Text("custom".into()),
            Value::Bytes(registration_auth_data("test.local", 0x41, false)),
            Value::Map(vec![]),
        );
        assert!(parse_attestation_object(&unsupported, "test.local").is_err());
    }

    #[test]
    fn required_attestation_rejects_missing_trust_configuration() {
        let verifier = WebauthnVerifier::new(WebauthnConfig {
            trusted_attestation_cas: vec![],
            ..test_config(true)
        });
        let challenge = b"challenge";
        let client_data = format!(
            r#"{{"type":"webauthn.create","challenge":"{}","origin":"https://test.local"}}"#,
            base64_url(challenge)
        );
        let object = attestation_object(
            Value::Text("packed".into()),
            Value::Bytes(registration_auth_data("test.local", 0x45, false)),
            Value::Map(vec![]),
        );
        let result = verifier.verify_registration(
            &object,
            client_data.as_bytes(),
            challenge,
            "https://test.local",
        );
        assert!(
            matches!(result, Err(ConclaveError::Attestation(message)) if message.contains("trust anchors"))
        );
    }

    #[test]
    fn structurally_valid_registration_remains_unsupported() {
        let verifier = WebauthnVerifier::new(test_config(false));
        let challenge = b"challenge";
        let client_data = format!(
            r#"{{"type":"webauthn.create","challenge":"{}","origin":"https://test.local"}}"#,
            base64_url(challenge)
        );
        let object = attestation_object(
            Value::Text("packed".into()),
            Value::Bytes(registration_auth_data("test.local", 0x45, false)),
            Value::Map(vec![]),
        );
        assert!(matches!(
            verifier.verify_registration(
                &object,
                client_data.as_bytes(),
                challenge,
                "https://test.local"
            ),
            Err(ConclaveError::Unsupported(_))
        ));
    }

    #[test]
    fn authentication_rejects_truncated_wrong_rp_and_attested_flag() {
        assert!(parse_authenticator_data(&[0u8; 36], "test.local", false).is_err());
        let mut wrong_rp = vec![0u8; 37];
        wrong_rp[32] = 0x01;
        assert!(parse_authenticator_data(&wrong_rp, "test.local", false).is_err());
        let mut with_at = Vec::new();
        with_at.extend_from_slice(&Sha256::digest(b"test.local"));
        with_at.push(0x41);
        with_at.extend_from_slice(&0u32.to_be_bytes());
        assert!(parse_authenticator_data(&with_at, "test.local", false).is_err());
    }

    #[test]
    fn generated_challenges_are_not_deterministic() {
        let verifier = WebauthnVerifier::new(test_config(false));
        let (first, _) = verifier.generate_challenge().unwrap();
        let (second, _) = verifier.generate_challenge().unwrap();
        assert_ne!(first, second);
    }
}
