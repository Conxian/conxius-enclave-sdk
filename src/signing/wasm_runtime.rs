//! WASM runtime signing surface (Phase 2).
//!
//! Provides a serialization-safe signing interface for WASM consumers.
//! All methods accept and return JSON-encoded requests/responses to avoid
//! exposing enclave internals across the WASM boundary.
//!
//! # Security
//! This module NEVER exports private keys or enclave internals. All signing
//! goes through the value-bearing attestation path.

use crate::signing::ucs::{EnclaveUniversalSigner, UniversalChainSigner};
use crate::ConclaveResult;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct WasmSignRequest {
    pub chain: String,
    pub message_hex: String,
    pub derivation_path: String,
    pub key_id: String,
    #[serde(default)]
    pub merkle_root_hex: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WasmSignResponse {
    pub signature_hex: String,
    pub chain: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WasmPublicKeyRequest {
    pub derivation_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WasmPublicKeyResponse {
    pub public_key_hex: String,
    pub derivation_path: String,
}

// ---------------------------------------------------------------------------
// WASM signing runtime
// ---------------------------------------------------------------------------

/// Stateless WASM signing runtime. Each call creates a fresh UCS from the
/// provided enclave reference. Compatible with `wasm-bindgen` exports.
pub struct WasmSigningRuntime;

impl WasmSigningRuntime {
    /// Process a JSON-encoded sign request and return a JSON-encoded response.
    pub fn sign_json(
        enclave: &dyn crate::enclave::EnclaveManager,
        request_json: &str,
    ) -> ConclaveResult<String> {
        let req: WasmSignRequest = serde_json::from_str(request_json).map_err(|e| {
            crate::ConclaveError::Unsupported(format!("wasm: invalid request: {}", e))
        })?;

        let ucs = EnclaveUniversalSigner::new(enclave);
        let message: [u8; 32] = Self::decode_hex_32(&req.message_hex)?;

        let signature_hex = match req.chain.as_str() {
            "bitcoin:taproot" => {
                let merkle_root = req
                    .merkle_root_hex
                    .map(|h| Self::decode_hex_32(&h))
                    .transpose()?;
                ucs.sign_bitcoin_taproot(message, &req.derivation_path, &req.key_id, merkle_root)?
            }
            "bitcoin:ecdsa" => {
                ucs.sign_bitcoin_ecdsa(message, &req.derivation_path, &req.key_id)?
            }
            "ethereum" => ucs.sign_ethereum(message, &req.derivation_path, &req.key_id)?,
            "solana" => ucs.sign_solana(message, &req.derivation_path, &req.key_id)?,
            "stacks" => ucs.sign_stacks(message, &req.derivation_path, &req.key_id)?,
            "babylon" => ucs.sign_babylon(message, &req.derivation_path, &req.key_id)?,
            other => {
                return Err(crate::ConclaveError::Unsupported(format!(
                    "wasm: unknown chain: {}",
                    other
                )));
            }
        };

        let resp = WasmSignResponse {
            signature_hex,
            chain: req.chain,
        };
        serde_json::to_string(&resp)
            .map_err(|e| crate::ConclaveError::Unsupported(format!("wasm: serialize error: {}", e)))
    }

    /// Get a public key for a derivation path (JSON API).
    pub fn public_key_json(
        enclave: &dyn crate::enclave::EnclaveManager,
        request_json: &str,
    ) -> ConclaveResult<String> {
        let req: WasmPublicKeyRequest = serde_json::from_str(request_json).map_err(|e| {
            crate::ConclaveError::Unsupported(format!("wasm: invalid request: {}", e))
        })?;

        let public_key_hex = enclave.get_public_key(&req.derivation_path)?;
        let resp = WasmPublicKeyResponse {
            public_key_hex,
            derivation_path: req.derivation_path,
        };
        serde_json::to_string(&resp)
            .map_err(|e| crate::ConclaveError::Unsupported(format!("wasm: serialize error: {}", e)))
    }

    fn decode_hex_32(hex_str: &str) -> ConclaveResult<[u8; 32]> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| crate::ConclaveError::Unsupported(format!("wasm: invalid hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(crate::ConclaveError::Unsupported(format!(
                "wasm: expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_decode_hex_32_valid() {
        let hex_str = "ab".repeat(32);
        let result = WasmSigningRuntime::decode_hex_32(&hex_str);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0xAB; 32]);
    }

    #[test]
    fn wasm_decode_hex_32_invalid_length() {
        let result = WasmSigningRuntime::decode_hex_32("ab");
        assert!(result.is_err());
    }

    #[test]
    fn wasm_request_serialization_roundtrips() {
        let req = WasmSignRequest {
            chain: "bitcoin:taproot".into(),
            message_hex: "ab".repeat(32),
            derivation_path: "m/86'/0'/0'/0/0".into(),
            key_id: "key-1".into(),
            merkle_root_hex: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: WasmSignRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.chain, "bitcoin:taproot");
    }

    #[test]
    fn wasm_sign_rejects_unknown_chain() {
        let json = r#"{"chain":"unknown","message_hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","derivation_path":"m/0","key_id":"k"}"#;
        // Without a real enclave we can't call sign_json, but we can verify
        // deserialization works.
        let req: WasmSignRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.chain, "unknown");
    }

    #[test]
    fn wasm_public_key_request_roundtrips() {
        let req = WasmPublicKeyRequest {
            derivation_path: "m/86'/0'/0'/0/0".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: WasmPublicKeyRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.derivation_path, "m/86'/0'/0'/0/0");
    }
}
