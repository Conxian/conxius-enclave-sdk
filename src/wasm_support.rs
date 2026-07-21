//! WASM runtime and provider support policy.
//!
//! A WASM build proves that bindings can be compiled; it does not prove that
//! a browser, Node, bundler, worker, or provider boundary is safe or supported
//! for value-bearing operations. This module keeps that decision fail-closed.

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
    fn wasm_surface_has_no_private_key_export_or_cloud_default() {
        let source = include_str!("wasm_bindings.rs");

        assert!(!source.contains("pub fn derive_vutxo_key"));
        assert!(!source.contains("hex::encode(key)"));
        assert!(!source.contains("master_seed_hex"));
        assert!(!source.contains("crate::enclave::cloud::CloudEnclave::new("));
        assert!(source.contains("UnavailableEnclave"));
        assert!(!source.contains("expect(\"Failed to create enclave\")"));
        assert!(!source.contains("EnclaveManager::sign"));
        assert!(!source.contains(".sign(request"));
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
        assert!(source.contains("SECRET_EXPORT_FORBIDDEN"));
    }

    #[test]
    fn wasm_surface_does_not_serialize_fedimint_blinding_factors() {
        let source = include_str!("wasm_bindings.rs");

        assert!(!source.contains("\"blinding_factors\": bf"));
        assert!(!source.contains("serde_wasm_bindgen::to_value(&ecash)"));
    }
}
