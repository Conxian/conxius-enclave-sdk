//! Offline AWS Nitro attestation verifier — callable CI entrypoint (issue #242).
//!
//! Verifies a real Nitro attestation document (CBOR/COSE, ES384) against a
//! caller-supplied policy + release binding using the SDK's production
//! [`AwsNitroTrustBoundary`] (embedded AWS Nitro Root CA G1). This is the
//! verification half of the `provision-nitro` workflow: CI builds an EIF,
//! launches a Nitro enclave, captures the attestation document, and calls this
//! binary so any measurement / trust / freshness / binding mismatch fails closed.
//!
//! This verifier is deliberately **offline**: it does not contact NSM, vsock,
//! KMS, or the network. It returns a structural verification receipt and exits
//! non-zero on any rejection. It does not consume durable replay state and does
//! not create value-bearing authorization (see #240 for that contract).
//!
//! # Usage
//! ```sh
//! cargo run --example nitro_attest_verify -- request.json
//! ```
//!
//! `request.json` shape:
//! ```json
//! {
//!   "attestation_document_path": "/tmp/attestation.cbor",
//!   "module_id": "i-0123456789abcdef0-enc0123456789abcdef0",
//!   "nonce": "deadbeef...",
//!   "recipient_public_key_hash": "<32-byte hex>",
//!   "operation_digest": "<32-byte hex>",
//!   "purpose": "KMS_RELEASE",
//!   "kms_key_identifier_hash": "<32-byte hex>",
//!   "policy_version": 1,
//!   "policy_digest": "<32-byte hex>",
//!   "expires_at_ms": 1720000000000,
//!   "replay_identity": "<32-byte hex>",
//!   "pcrs": [
//!     { "index": 0, "value": "<48-byte hex>" },
//!     { "index": 1, "value": "<48-byte hex>" },
//!     { "index": 2, "value": "<48-byte hex>" },
//!     { "index": 8, "value": "<48-byte hex>" }
//!   ]
//! }
//! ```

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use conxius_enclave_sdk::enclave::nitro::{
    NitroAttestationDocument, NitroAttestationPolicy, NitroError, NitroPcrPolicy,
    NitroReleaseBinding, NITRO_SHA384_PCR_BYTES,
};
use conxius_enclave_sdk::enclave::verifiers::nitro_trust::AwsNitroTrustBoundary;

#[derive(Debug, Deserialize)]
struct NitroVerifyRequest {
    attestation_document_path: String,
    #[serde(default)]
    module_id: Option<String>,
    nonce: String,
    recipient_public_key_hash: String,
    operation_digest: String,
    purpose: String,
    kms_key_identifier_hash: String,
    policy_version: u32,
    policy_digest: String,
    expires_at_ms: u64,
    replay_identity: String,
    pcrs: Vec<PcrEntry>,
}

#[derive(Debug, Deserialize)]
struct PcrEntry {
    index: u8,
    value: String,
}

fn decode_hex<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(value.trim()).map_err(|e| format!("{field}: invalid hex: {e}"))?;
    if bytes.len() != N {
        return Err(format!("{field}: expected {N} bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| usage_and_exit());
    if let Err(err) = run(PathBuf::from(path)) {
        eprintln!("NITRO ATTESTATION REJECTED: {err}");
        std::process::exit(1);
    }
    println!("NITRO ATTESTATION VERIFIED (offline structural receipt)");
}

fn usage_and_exit() -> ! {
    eprintln!("usage: nitro_attest_verify <request.json>");
    std::process::exit(2);
}

fn run(path: PathBuf) -> Result<(), String> {
    let raw = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let req: NitroVerifyRequest =
        serde_json::from_str(&raw).map_err(|e| format!("parse request: {e}"))?;

    let doc_bytes = fs::read(&req.attestation_document_path)
        .map_err(|e| format!("read attestation document {}: {e}", req.attestation_document_path))?;

    let document = NitroAttestationDocument::parse(&doc_bytes)
        .map_err(|e: NitroError| format!("parse attestation document: {e:?}"))?;

    let measurements: Result<Vec<(u8, [u8; NITRO_SHA384_PCR_BYTES])>, String> = req
        .pcrs
        .iter()
        .map(|p| -> Result<(u8, [u8; NITRO_SHA384_PCR_BYTES]), String> {
            let value =
                decode_hex::<NITRO_SHA384_PCR_BYTES>(&format!("pcrs[{}]", p.index), &p.value)?;
            Ok((p.index, value))
        })
        .collect();
    let measurements = measurements?;

    let pcr_policy = NitroPcrPolicy::new(measurements)
        .map_err(|e: NitroError| format!("PCR policy: {e:?}"))?;
    let mut policy = NitroAttestationPolicy::new(pcr_policy);
    if let Some(module_id) = &req.module_id {
        policy = policy
            .with_module_id(module_id.clone())
            .map_err(|e: NitroError| format!("module id: {e:?}"))?;
    }

    let release_binding = NitroReleaseBinding::new(
        decode_hex::<32>("operation_digest", &req.operation_digest)?,
        req.purpose.clone(),
        decode_hex::<32>("kms_key_identifier_hash", &req.kms_key_identifier_hash)?,
        req.policy_version,
        decode_hex::<32>("policy_digest", &req.policy_digest)?,
        req.expires_at_ms,
        decode_hex::<32>("replay_identity", &req.replay_identity)?,
    )
    .map_err(|e: NitroError| format!("release binding: {e:?}"))?;

    let nonce = hex::decode(req.nonce.trim()).map_err(|e| format!("nonce: {e}"))?;
    let recipient_key_hash =
        decode_hex::<32>("recipient_public_key_hash", &req.recipient_public_key_hash)?;

    let trust = AwsNitroTrustBoundary::new();
    let receipt = document
        .verify_offline(
            &policy,
            &trust,
            now_millis(),
            &nonce,
            recipient_key_hash,
            &release_binding,
        )
        .map_err(|e: NitroError| format!("verify: {e:?}"))?;

    println!("module_id       = {}", receipt.module_id());
    println!("timestamp_ms    = {}", receipt.timestamp_ms());
    println!("status          = {:?}", receipt.status());
    println!("replay_status   = {:?}", receipt.replay_status());
    println!("production_stat = {:?}", receipt.production_status());
    Ok(())
}
