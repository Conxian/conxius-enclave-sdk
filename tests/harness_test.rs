//! Phase 1 harness integration tests.
//!
//! Exercises the test harness fixtures against the UCS and signing modules.

mod harness;

use conxius_enclave_sdk::signing::ucs::UniversalChainSigner;

#[test]
fn harness_exercises_ucs() {
    let enclave = harness::HarnessEnclave::new();
    let ucs = enclave.ucs();

    // All UCS methods should return Unsupported from the harness enclave
    // (it doesn't implement the full attestation pipeline)
    let result = ucs.sign_bitcoin_taproot([0xAB; 32], "m/86'/0'/0'/0/0", "k1", None);
    harness::assert_unsupported(result);
}

#[test]
fn harness_derivation_paths() {
    use harness::derivation_paths;
    assert!(derivation_paths::BITCOIN_TAPROOT.starts_with("m/86'"));
    assert!(derivation_paths::ETHEREUM.starts_with("m/44'/60'"));
    assert!(derivation_paths::SOLANA.starts_with("m/44'/501'"));
}

#[test]
fn harness_digests_are_distinct() {
    use harness::digests;
    assert_ne!(digests::DIGEST_A, digests::DIGEST_B);
    assert_ne!(digests::DIGEST_C, digests::DIGEST_D);
}

#[test]
fn harness_enclave_returns_public_key() {
    let enclave = harness::HarnessEnclave::new();
    let pk = conxius_enclave_sdk::enclave::EnclaveManager::get_public_key(
        &enclave,
        "m/86'/0'/0'/0/0",
    );
    assert!(pk.is_ok());
    assert_eq!(pk.unwrap(), enclave.public_key_hex);
}
