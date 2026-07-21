//! WASM runtime and provider support policy.
//!
//! A WASM build proves that bindings can be compiled; it does not prove that
//! a browser, Node, bundler, worker, or provider boundary is safe or supported
//! for value-bearing operations. This module keeps that decision fail-closed.

#[cfg(any(target_arch = "wasm32", test))]
use crate::{protocol_unsupported, UnsupportedOperation, UnsupportedProtocol};
use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};

/// Runtime labels used by the public WASM support matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmRuntime {
    Browser,
    Node,
    Bundler,
    Worker,
}

impl WasmRuntime {
    /// Parse the stable runtime labels accepted by documentation and tests.
    pub fn parse(value: &str) -> ConclaveResult<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "browser" | "web" => Ok(Self::Browser),
            "node" | "nodejs" => Ok(Self::Node),
            "bundler" => Ok(Self::Bundler),
            "worker" | "webworker" => Ok(Self::Worker),
            other => Err(ConclaveError::UnsupportedRuntime(format!(
                "unknown runtime `{other}`"
            ))),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Node => "node",
            Self::Bundler => "bundler",
            Self::Worker => "worker",
        }
    }
}

/// Return the known runtime labels in the order used by the support matrix.
pub const fn known_runtimes() -> [WasmRuntime; 4] {
    [
        WasmRuntime::Browser,
        WasmRuntime::Node,
        WasmRuntime::Bundler,
        WasmRuntime::Worker,
    ]
}

/// Reject a runtime until a matching artifact, provider, and runtime test are
/// attached to the exact release scope.
pub fn reject_unverified_runtime(runtime: WasmRuntime) -> ConclaveResult<()> {
    Err(ConclaveError::UnsupportedRuntime(format!(
        "{} has no verified WASM runtime/provider evidence; compilation alone is insufficient",
        runtime.as_str()
    )))
}

/// Reject a provider that has not been explicitly approved for the WASM
/// boundary. This prevents CloudEnclave, localhost, and software-only mocks
/// from becoming an accidental production default.
pub fn reject_unapproved_provider(provider: &str) -> ConclaveResult<()> {
    Err(ConclaveError::UnsupportedProvider(format!(
        "provider `{provider}` has no approved opaque-key or signing capability"
    )))
}

/// Map the legacy WASM BitVM surface to the typed BitVM2 quarantine boundary.
/// Generic MuSig2 values from the legacy module are not BitVM2 evidence.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn legacy_bitvm2_unsupported(operation: UnsupportedOperation) -> ConclaveError {
    protocol_unsupported(UnsupportedProtocol::BitVm2, operation)
}

/// Keep WASM error codes stable while the human-readable error remains typed.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn wasm_error_code(error: &ConclaveError) -> &'static str {
    match error {
        ConclaveError::ProtocolUnsupported { .. } => "PROTOCOL_UNSUPPORTED",
        ConclaveError::BoundaryValidation(_) => "BOUNDARY_VALIDATION",
        ConclaveError::UnsupportedRuntime(_) => "UNSUPPORTED_RUNTIME",
        ConclaveError::UnsupportedProvider(_) => "UNSUPPORTED_PROVIDER",
        ConclaveError::SecretExportForbidden => "SECRET_EXPORT_FORBIDDEN",
        ConclaveError::InvalidPayload => "INVALID_INPUT",
        _ => "CONXIAN_ERROR",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_runtime_fails_closed_without_evidence() {
        for runtime in known_runtimes() {
            assert!(matches!(
                reject_unverified_runtime(runtime),
                Err(ConclaveError::UnsupportedRuntime(_))
            ));
        }
    }

    #[test]
    fn unknown_runtime_is_typed_as_unsupported() {
        assert!(matches!(
            WasmRuntime::parse("deno"),
            Err(ConclaveError::UnsupportedRuntime(_))
        ));
    }

    #[test]
    fn unapproved_provider_is_typed_as_unsupported() {
        assert!(matches!(
            reject_unapproved_provider("cloud-enclave"),
            Err(ConclaveError::UnsupportedProvider(_))
        ));
    }

    #[test]
    fn stable_error_codes_preserve_input_protocol_and_secret_semantics() {
        assert_eq!(
            wasm_error_code(&ConclaveError::InvalidPayload),
            "INVALID_INPUT"
        );
        assert_eq!(
            wasm_error_code(&ConclaveError::ProtocolUnsupported {
                protocol: UnsupportedProtocol::BitVm2,
                operation: UnsupportedOperation::ChallengeSubmission,
                reason: crate::UnsupportedReason::NoAuditedImplementation,
            }),
            "PROTOCOL_UNSUPPORTED"
        );
        assert_eq!(
            wasm_error_code(&ConclaveError::SecretExportForbidden),
            "SECRET_EXPORT_FORBIDDEN"
        );
    }

    #[test]
    fn legacy_wasm_bitvm_surface_is_exactly_bitvm2_unsupported() {
        let sign_error = legacy_bitvm2_unsupported(UnsupportedOperation::ChallengeSubmission);
        assert_eq!(
            sign_error,
            ConclaveError::ProtocolUnsupported {
                protocol: UnsupportedProtocol::BitVm2,
                operation: UnsupportedOperation::ChallengeSubmission,
                reason: crate::UnsupportedReason::NoAuditedImplementation,
            }
        );
        assert_eq!(wasm_error_code(&sign_error), "PROTOCOL_UNSUPPORTED");

        let aggregate_error = legacy_bitvm2_unsupported(UnsupportedOperation::ThresholdAggregation);
        assert_eq!(
            aggregate_error,
            ConclaveError::ProtocolUnsupported {
                protocol: UnsupportedProtocol::BitVm2,
                operation: UnsupportedOperation::ThresholdAggregation,
                reason: crate::UnsupportedReason::NoAuditedImplementation,
            }
        );
        assert_eq!(wasm_error_code(&aggregate_error), "PROTOCOL_UNSUPPORTED");

        let source = include_str!("wasm_bindings.rs");
        let bitvm_surface = source
            .split("pub struct WasmBitVmClient")
            .nth(1)
            .and_then(|rest| {
                rest.split("#[wasm_bindgen]\npub struct Iso20022Wrapper")
                    .next()
            })
            .unwrap_or("");
        assert!(bitvm_surface.contains("legacy_bitvm2_error"));
        assert!(bitvm_surface.contains("UnsupportedOperation::ChallengeSubmission"));
        assert!(bitvm_surface.contains("UnsupportedOperation::ThresholdAggregation"));
        assert!(bitvm_surface.contains("Err(legacy_bitvm2_error("));
        assert!(!bitvm_surface.contains("serde_wasm_bindgen::from_value"));
        assert!(!bitvm_surface.contains("serde_json::from_str"));
        assert!(!bitvm_surface.contains(".inner\n            .sign_challenge("));
        assert!(!bitvm_surface.contains(".inner\n            .aggregate_challenge_signatures("));
        assert!(!bitvm_surface.contains("to_value(&aggregate)"));
    }

    #[test]
    fn wasm_surface_has_no_private_key_export_or_cloud_default() {
        let source = include_str!("wasm_bindings.rs");
        let support_source = include_str!("wasm_support.rs");

        assert!(!source.contains("pub fn derive_vutxo_key"));
        assert!(!source.contains("hex::encode(key)"));
        assert!(!source.contains("master_seed_hex"));
        assert!(!source.contains("crate::enclave::cloud::CloudEnclave::new("));
        assert!(!source.contains("UnavailableEnclave"));
        assert!(!source.contains("expect(\"Failed to create enclave\")"));
        assert!(!source.contains("EnclaveManager::sign"));
        assert!(!source.contains(".sign(request"));
        assert!(source.contains("Err(unsupported_provider("));
        assert!(source.contains("pub fn new() -> Result<WasmBitVm2Orchestrator, JsValue>"));
        assert!(source.contains("pub fn bitvm2(&self) -> Result<WasmBitVm2Orchestrator, JsValue>"));
        assert!(source.contains("fn invalid_input()"));
        assert!(!source.contains("JsValue::from_str(\"Invalid key length\")"));
        assert!(!source.contains("JsValue::from_str(\"Invalid hash length\")"));
        assert!(!source.contains("JsValue::from_str(\"Invalid state hash length\")"));
        assert!(
            !source.contains("JsValue::from_str(\"Invalid taproot internal public key length\")")
        );
        let source_lines: Vec<&str> = source.lines().collect();
        let mut gated_development_constructors = 0;
        for (index, line) in source_lines.iter().enumerate() {
            if line.trim_start().starts_with("pub fn new_for_development") {
                gated_development_constructors += 1;
                assert_eq!(
                    source_lines
                        .get(index.saturating_sub(1))
                        .map(|line| line.trim()),
                    Some("#[cfg(feature = \"development-simulators\")]"),
                    "WASM development constructors must remain explicitly feature-gated"
                );
            }
        }
        assert_eq!(gated_development_constructors, 2);
        assert!(source.contains("derive_vutxo_public_key"));
        assert!(source.contains("sign_vutxo"));
        assert!(source.contains("wasm_error_code"));
        assert!(support_source.contains("SECRET_EXPORT_FORBIDDEN"));
    }

    #[test]
    fn wasm_surface_does_not_serialize_fedimint_blinding_factors() {
        let source = include_str!("wasm_bindings.rs");

        assert!(!source.contains("\"blinding_factors\": bf"));
        assert!(!source.contains("serde_wasm_bindgen::to_value(&ecash)"));
    }
}
