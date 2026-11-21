//! End-to-end PKCS#11 signing conformance against a real token.
//!
//! Exercises the same `Pkcs11Verifier` code path a hardware token uses
//! (YubiKey PIV slot, on-prem HSM). SoftHSM2 stands in for the token so the
//! adapter is validated without hardware attached; the code under test is
//! identical for a physical device.
//!
//! Requires the `cryptoki` feature and a provisioned SoftHSM token:
//!
//! ```sh
//! export SOFTHSM2_CONF=/tmp/softhsm2.conf
//! softhsm2-util --init-token --free --label conclave-test --pin 1234 --so-pin 5678
//! pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 \
//!   --keypairgen --key-type EC:prime256v1 --id 01 --label conclave-key
//! CONCLAVE_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
//! CONCLAVE_PKCS11_SLOT=<slot> CONCLAVE_PKCS11_PIN=1234 \
//!   cargo test --features cryptoki --test pkcs11_softhsm_signing -- --nocapture
//! ```
//!
//! When the environment is not provisioned the test exits cleanly (skipped),
//! so it never fails a machine that has no token.
#![cfg(feature = "cryptoki")]

use conxius_enclave_sdk::enclave::verifiers::pkcs11_verifier::{
    Pkcs11Config, Pkcs11KeyType, Pkcs11Verifier,
};

fn env_usize(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

// The verifier keeps a process-global PKCS#11 context (OnceLock). Serialize the
// tests so concurrent C_Initialize/session use on one token never races.
static TOKEN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn pkcs11_sign_and_verify_roundtrip() {
    let _guard = TOKEN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(module) = std::env::var("CONCLAVE_PKCS11_MODULE") else {
        eprintln!("skipping: CONCLAVE_PKCS11_MODULE not set");
        return;
    };
    let Some(slot_id) = env_usize("CONCLAVE_PKCS11_SLOT") else {
        eprintln!("skipping: CONCLAVE_PKCS11_SLOT not set");
        return;
    };
    let pin = std::env::var("CONCLAVE_PKCS11_PIN").ok();

    let verifier = Pkcs11Verifier::new(Pkcs11Config {
        library_path: module,
        pin,
        slot_id: Some(slot_id),
    });

    // Discovery must find the sign-only private key and classify the curve.
    let keys = verifier.discover_keys(slot_id).expect("discover_keys");
    let key = keys
        .iter()
        .find(|k| k.key_id == vec![0x01])
        .expect("expected key id 01");
    assert_eq!(
        key.key_type,
        Pkcs11KeyType::EcdsaSecp256r1,
        "EC P-256 key should classify as EcdsaSecp256r1, got {:?}",
        key.key_type
    );

    // A 32-byte digest signed with raw ECDSA (token hashes nothing extra).
    let digest = [0x42u8; 32];
    let sig = verifier
        .sign(slot_id, &key.key_id, "ECDSA", &digest)
        .expect("sign");
    assert!(!sig.is_empty(), "signature must be non-empty");

    let ok = verifier
        .verify(slot_id, &key.key_id, "ECDSA", &digest, &sig)
        .expect("verify");
    assert!(ok, "signature must verify under the token public key");

    // A tampered digest must not verify.
    let mut bad = digest;
    bad[0] ^= 0xff;
    let bad_ok = verifier
        .verify(slot_id, &key.key_id, "ECDSA", &bad, &sig)
        .expect("verify bad");
    assert!(
        !bad_ok,
        "signature must NOT verify against a different digest"
    );

    // Public key extraction returns a DER EC point (0x04-prefixed).
    let pk = verifier
        .get_public_key(slot_id, &key.key_id)
        .expect("pubkey");
    assert_eq!(pk.first(), Some(&0x04u8), "EC point must be 0x04-prefixed");
}

#[test]
fn pkcs11_ed25519_sign_and_verify_roundtrip() {
    let _guard = TOKEN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(module) = std::env::var("CONCLAVE_PKCS11_MODULE") else {
        eprintln!("skipping: CONCLAVE_PKCS11_MODULE not set");
        return;
    };
    let Some(slot_id) = env_usize("CONCLAVE_PKCS11_SLOT") else {
        eprintln!("skipping: CONCLAVE_PKCS11_SLOT not set");
        return;
    };
    let pin = std::env::var("CONCLAVE_PKCS11_PIN").ok();

    let verifier = Pkcs11Verifier::new(Pkcs11Config {
        library_path: module,
        pin,
        slot_id: Some(slot_id),
    });

    let keys = verifier.discover_keys(slot_id).expect("discover_keys");
    let Some(key) = keys.iter().find(|k| k.key_id == vec![0x02]) else {
        eprintln!("skipping: no Ed25519 key id 02 on token");
        return;
    };
    assert_eq!(
        key.key_type,
        Pkcs11KeyType::Ed25519,
        "EC_EDWARDS key should classify as Ed25519, got {:?}",
        key.key_type
    );

    let digest = [0x11u8; 32];
    let sig = verifier
        .sign(slot_id, &key.key_id, "EdDSA", &digest)
        .expect("ed25519 sign");
    let ok = verifier
        .verify(slot_id, &key.key_id, "EdDSA", &digest, &sig)
        .expect("ed25519 verify");
    assert!(ok, "Ed25519 signature must verify");
}
