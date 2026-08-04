//! Phase 1 test harness (SDK-009).
//!
//! Reusable test infrastructure for integration testing of Phase 1
//! signing modules. Provides fixture generation, assertion helpers,
//! and protocol-vector validation utilities.
//!
//! # SDK-009
//! See `docs/PHASE1_ISSUES_ROADMAP.md` for acceptance criteria.

use conxius_enclave_sdk::enclave::{
    EnclaveManager, SignRequest, SignResponse,
};
use conxius_enclave_sdk::signing::ucs::{EnclaveUniversalSigner, UniversalChainSigner};
use conxius_enclave_sdk::ConclaveError;
use conxius_enclave_sdk::ConclaveResult;

// ---------------------------------------------------------------------------
// Test enclave fixture
// ---------------------------------------------------------------------------

/// Minimal enclave manager for integration tests. Uses the default
/// (fail-closed) `sign_value_bearing` implementation — integration tests
/// that need real signing should use the full attestation pipeline via
/// `FixtureProvider` in `src/enclave/mod.rs`.
pub struct HarnessEnclave {
    pub public_key_hex: String,
}

impl HarnessEnclave {
    pub fn new() -> Self {
        Self {
            public_key_hex: "02deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe".into(),
        }
    }

    pub fn ucs(&self) -> EnclaveUniversalSigner<'_> {
        EnclaveUniversalSigner::new(self)
    }
}

impl Default for HarnessEnclave {
    fn default() -> Self {
        Self::new()
    }
}

impl EnclaveManager for HarnessEnclave {
    fn initialize(&self) -> ConclaveResult<()> {
        Ok(())
    }

    fn generate_key(&self, _key_id: &str) -> ConclaveResult<String> {
        Ok(self.public_key_hex.clone())
    }

    fn get_public_key(&self, _derivation_path: &str) -> ConclaveResult<String> {
        Ok(self.public_key_hex.clone())
    }

    fn sign(&self, _request: SignRequest) -> ConclaveResult<SignResponse> {
        Err(ConclaveError::Unsupported(
            "harness enclave: use sign_value_bearing".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

/// Assert that a signing operation fails with `ConclaveError::Unsupported`.
pub fn assert_unsupported(result: ConclaveResult<String>) {
    match result {
        Err(ConclaveError::Unsupported(_)) => {}
        other => panic!("expected Unsupported, got {:?}", other),
    }
}

/// Assert that a signing operation succeeds and returns a non-empty hex
/// signature.
pub fn assert_signature_ok(result: ConclaveResult<String>) -> String {
    match result {
        Ok(_sig) if !_sig.is_empty() => _sig,
        Ok(_sig) => panic!("signature is empty"),
        Err(e) => panic!("expected Ok signature, got {:?}", e),
    }
}

// ---------------------------------------------------------------------------
// Test vectors
// ---------------------------------------------------------------------------

/// Standard derivation paths used across chain families.
pub mod derivation_paths {
    pub const BITCOIN_TAPROOT: &str = "m/86'/0'/0'/0/0";
    pub const BITCOIN_LEGACY: &str = "m/44'/0'/0'/0/0";
    pub const BITCOIN_SEGWIT: &str = "m/84'/0'/0'/0/0";
    pub const ETHEREUM: &str = "m/44'/60'/0'/0/0";
    pub const SOLANA: &str = "m/44'/501'/0'/0'";
    pub const STACKS: &str = "m/44'/5757'/0'/0/0";
}

/// Standard test message digests (all 32-byte arrays).
pub mod digests {
    pub const DIGEST_A: [u8; 32] = [0xAA; 32];
    pub const DIGEST_B: [u8; 32] = [0xBB; 32];
    pub const DIGEST_C: [u8; 32] = [0xCC; 32];
    pub const DIGEST_D: [u8; 32] = [0xDD; 32];
    pub const DIGEST_E: [u8; 32] = [0xEE; 32];
    pub const DIGEST_F: [u8; 32] = [0xFF; 32];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_enclave_constructs() {
        let enclave = HarnessEnclave::new();
        assert_eq!(
            enclave.get_public_key("m/86'/0'/0'/0/0").unwrap(),
            enclave.public_key_hex
        );
    }

    #[test]
    fn harness_enclave_ucs_constructs() {
        let enclave = HarnessEnclave::new();
        let ucs = enclave.ucs();
        let _ = ucs.enclave();
    }

    #[test]
    fn assert_unsupported_accepts_unsupported_error() {
        let result: ConclaveResult<String> =
            Err(ConclaveError::Unsupported("test".into()));
        assert_unsupported(result);
    }

    #[test]
    #[should_panic]
    fn assert_unsupported_panics_on_ok() {
        assert_unsupported(Ok("sig".into()));
    }

    #[test]
    fn derivation_paths_are_valid() {
        use derivation_paths::*;
        for path in &[
            BITCOIN_TAPROOT,
            BITCOIN_LEGACY,
            BITCOIN_SEGWIT,
            ETHEREUM,
            SOLANA,
            STACKS,
        ] {
            assert!(!path.is_empty());
            assert!(path.starts_with("m/"));
        }
    }

    #[test]
    fn digests_are_32_bytes() {
        assert_eq!(digests::DIGEST_A.len(), 32);
        assert_eq!(digests::DIGEST_F.len(), 32);
    }
}
