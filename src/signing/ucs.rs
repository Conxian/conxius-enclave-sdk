//! Universal Chain Signer (UCS) — multi-chain signing gateway.
//!
//! Defines the [`UniversalChainSigner`] trait and its primary implementor
//! [`EnclaveUniversalSigner`]. This is the single entry-point for all
//! chain-family signing operations, routing through the enclave's
//! value-bearing signing path.
//!
//! # SDK-001
//! See `docs/PHASE1_ISSUES_ROADMAP.md` for acceptance criteria.

use crate::enclave::{
    sign_value_bearing, EnclaveManager, OperationContext, SignerKeyBinding, SigningAlgorithm,
    TrustRequirement, ValueBearingPurpose, ValueBearingSignRequest, VALUE_BEARING_POLICY_ID,
};
use crate::ConclaveResult;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Universal interface for enclave-backed signing across all supported chain
/// families.
pub trait UniversalChainSigner {
    /// Sign a Bitcoin Taproot key-path sighash (BIP-341).
    fn sign_bitcoin_taproot(
        &self,
        sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
        merkle_root: Option<[u8; 32]>,
    ) -> ConclaveResult<String>;

    /// Sign a Bitcoin ECDSA message hash (legacy / segwit).
    fn sign_bitcoin_ecdsa(
        &self,
        message_hash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String>;

    /// Sign an Ethereum transaction digest (ECDSA secp256k1, EIP-155).
    fn sign_ethereum(
        &self,
        transaction_digest: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String>;

    /// Sign a Solana message hash (Ed25519).
    fn sign_solana(
        &self,
        message_hash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String>;

    /// Sign a Stacks prepared transaction hash (ECDSA secp256k1).
    fn sign_stacks(
        &self,
        message_hash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String>;

    /// Sign a Babylon BTC delegation commitment (placeholder — SDK-005).
    fn sign_babylon(
        &self,
        delegation_hash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String>;
}

// ---------------------------------------------------------------------------
// Primary implementor
// ---------------------------------------------------------------------------

/// Enclave-backed [`UniversalChainSigner`] implementation.
pub struct EnclaveUniversalSigner<'a> {
    enclave: &'a dyn EnclaveManager,
}

impl<'a> EnclaveUniversalSigner<'a> {
    pub fn new(enclave: &'a dyn EnclaveManager) -> Self {
        Self { enclave }
    }

    pub fn enclave(&self) -> &dyn EnclaveManager {
        self.enclave
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

struct SignContext<'a> {
    domain: &'a str,
    purpose: ValueBearingPurpose,
    algorithm: SigningAlgorithm,
    message_digest: [u8; 32],
    derivation_path: &'a str,
    key_id: &'a str,
    taproot_tweak: Option<Vec<u8>>,
}

fn sign_with_context(enclave: &dyn EnclaveManager, ctx: SignContext<'_>) -> ConclaveResult<String> {
    let context_bytes = ctx.message_digest.to_vec();
    let operation_context = OperationContext::new(ctx.domain, ctx.purpose, context_bytes)?;
    let trust_requirement = TrustRequirement::hardware_backed(VALUE_BEARING_POLICY_ID)?;

    let public_key = algorithm_placeholder_public_key(ctx.algorithm);
    let key_binding = SignerKeyBinding::new(ctx.key_id, ctx.derivation_path, public_key)?;

    let request = ValueBearingSignRequest::new(
        operation_context,
        ctx.algorithm,
        trust_requirement,
        ctx.message_digest,
        key_binding,
        ctx.taproot_tweak,
    )?;

    let response = sign_value_bearing(enclave, request)?;
    Ok(response.sign_response().signature_hex.clone())
}

fn algorithm_placeholder_public_key(algorithm: SigningAlgorithm) -> Vec<u8> {
    match algorithm {
        SigningAlgorithm::EcdsaSecp256k1 => vec![0x02; 33],
        SigningAlgorithm::SchnorrSecp256k1 => vec![0x02; 32],
        SigningAlgorithm::Ed25519 => vec![0x00; 32],
    }
}

// ---------------------------------------------------------------------------
// Trait implementation
// ---------------------------------------------------------------------------

impl UniversalChainSigner for EnclaveUniversalSigner<'_> {
    fn sign_bitcoin_taproot(
        &self,
        sighash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
        merkle_root: Option<[u8; 32]>,
    ) -> ConclaveResult<String> {
        sign_with_context(
            self.enclave,
            SignContext {
                domain: "conxian/bitcoin/taproot",
                purpose: ValueBearingPurpose::Transaction,
                algorithm: SigningAlgorithm::SchnorrSecp256k1,
                message_digest: sighash,
                derivation_path,
                key_id,
                taproot_tweak: merkle_root.map(|mr| mr.to_vec()),
            },
        )
    }

    fn sign_bitcoin_ecdsa(
        &self,
        message_hash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        sign_with_context(
            self.enclave,
            SignContext {
                domain: "conxian/bitcoin/ecdsa",
                purpose: ValueBearingPurpose::Transaction,
                algorithm: SigningAlgorithm::EcdsaSecp256k1,
                message_digest: message_hash,
                derivation_path,
                key_id,
                taproot_tweak: None,
            },
        )
    }

    fn sign_ethereum(
        &self,
        transaction_digest: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        sign_with_context(
            self.enclave,
            SignContext {
                domain: "conxian/ethereum/transaction",
                purpose: ValueBearingPurpose::Transaction,
                algorithm: SigningAlgorithm::EcdsaSecp256k1,
                message_digest: transaction_digest,
                derivation_path,
                key_id,
                taproot_tweak: None,
            },
        )
    }

    fn sign_solana(
        &self,
        message_hash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        sign_with_context(
            self.enclave,
            SignContext {
                domain: "conxian/solana/transaction",
                purpose: ValueBearingPurpose::Transaction,
                algorithm: SigningAlgorithm::Ed25519,
                message_digest: message_hash,
                derivation_path,
                key_id,
                taproot_tweak: None,
            },
        )
    }

    fn sign_stacks(
        &self,
        message_hash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        sign_with_context(
            self.enclave,
            SignContext {
                domain: "conxian/stacks/transaction",
                purpose: ValueBearingPurpose::Transaction,
                algorithm: SigningAlgorithm::EcdsaSecp256k1,
                message_digest: message_hash,
                derivation_path,
                key_id,
                taproot_tweak: None,
            },
        )
    }

    fn sign_babylon(
        &self,
        delegation_hash: [u8; 32],
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        sign_with_context(
            self.enclave,
            SignContext {
                domain: "conxian/babylon/delegation",
                purpose: ValueBearingPurpose::Authorization,
                algorithm: SigningAlgorithm::SchnorrSecp256k1,
                message_digest: delegation_hash,
                derivation_path,
                key_id,
                taproot_tweak: None,
            },
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::{
        EnclaveManager, SignRequest, SignResponse, SignerCapability, ValueBearingSignRequest,
        ValueBearingSignResponse,
    };
    use crate::ConclaveError;

    struct TestEnclave;

    impl EnclaveManager for TestEnclave {
        fn initialize(&self) -> ConclaveResult<()> {
            Ok(())
        }

        fn generate_key(&self, _key_id: &str) -> ConclaveResult<String> {
            Err(ConclaveError::Unsupported(
                "test enclave does not generate keys".to_string(),
            ))
        }

        fn get_public_key(&self, _derivation_path: &str) -> ConclaveResult<String> {
            Ok("02cafebabe".to_string())
        }

        fn sign(&self, _request: SignRequest) -> ConclaveResult<SignResponse> {
            Err(ConclaveError::Unsupported(
                "use sign_value_bearing for tests".to_string(),
            ))
        }

        fn signer_capability(&self) -> SignerCapability {
            SignerCapability::provider_verified(VALUE_BEARING_POLICY_ID).unwrap()
        }

        fn sign_value_bearing(
            &self,
            _request: ValueBearingSignRequest,
        ) -> ConclaveResult<ValueBearingSignResponse> {
            Err(ConclaveError::Unsupported(
                "full value-bearing response not available in unit tests".to_string(),
            ))
        }
    }

    #[test]
    fn ucs_can_be_constructed() {
        let enclave = TestEnclave;
        let ucs = EnclaveUniversalSigner::new(&enclave);
        let _ = ucs.enclave();
    }

    #[test]
    fn ucs_is_send_and_sync() {
        fn _assert(_s: impl Send + Sync) {}
        let enclave = TestEnclave;
        let ucs = EnclaveUniversalSigner::new(&enclave);
        _assert(ucs);
    }

    #[test]
    fn ucs_sign_methods_type_check() {
        let enclave = TestEnclave;
        let ucs = EnclaveUniversalSigner::new(&enclave);

        let _: ConclaveResult<String> =
            ucs.sign_bitcoin_taproot([0xAB; 32], "m/86'/0'/0'/0/0", "key-1", None);
        let _: ConclaveResult<String> =
            ucs.sign_bitcoin_ecdsa([0xCD; 32], "m/44'/0'/0'/0/0", "key-2");
        let _: ConclaveResult<String> = ucs.sign_ethereum([0xEF; 32], "m/44'/60'/0'/0/0", "key-3");
        let _: ConclaveResult<String> = ucs.sign_solana([0x01; 32], "m/44'/501'/0'/0'", "key-4");
        let _: ConclaveResult<String> = ucs.sign_stacks([0x02; 32], "m/44'/5757'/0'/0/0", "key-5");
        let _: ConclaveResult<String> = ucs.sign_babylon([0xBA; 32], "m/44'/0'/0'/0/0", "key-6");
    }

    #[test]
    fn ucs_methods_fail_closed_on_unsupported_enclave() {
        let enclave = TestEnclave;
        let ucs = EnclaveUniversalSigner::new(&enclave);

        let result = ucs.sign_bitcoin_taproot([0xAB; 32], "m/86'/0'/0'/0/0", "k", None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConclaveError::Unsupported(_)));
    }
}
