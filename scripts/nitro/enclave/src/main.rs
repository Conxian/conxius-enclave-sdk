//! Nitro enclave attestation probe (DRAFT — validate against the pinned
//! `aws-nitro-enclaves-nsm-api` version before first production use).
//!
//! Runs *inside* a Nitro enclave. It requests an attestation document from the
//! Nitro Security Module (NSM) with optional user-data / nonce / public-key, and
//! prints the resulting CBOR/COSE document as a single base64 line to console.
//! The parent instance captures that line and hands it to
//! `examples/nitro_attest_verify.rs` for fail-closed verification.
//!
//! The NSM binds the *current* PCR measurements into the document, so the
//! parent can only verify if the running EIF matches the pinned PCR policy.

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver as nsm_driver;
use base64::Engine;

fn main() {
    let user_data = env_b64("USER_DATA_B64");
    let nonce = env_b64("NONCE_B64");
    let public_key = env_b64("PUBLIC_KEY_B64");

    let request = Request::Attestation {
        user_data,
        nonce,
        public_key,
    };

    match nsm_driver::nsm_process_request(request) {
        Ok(Response::Attestation { document }) => {
            println!(
                "{}",
                base64::engine::general_purpose::STANDARD.encode(document)
            );
        }
        Ok(other) => {
            eprintln!("unexpected NSM response: {other:?}");
            std::process::exit(1);
        }
        Err(err) => {
            eprintln!("NSM request failed: {err}");
            std::process::exit(1);
        }
    }
}

fn env_b64(name: &str) -> Option<Vec<u8>> {
    std::env::var(name).ok().map(|value| {
        base64::engine::general_purpose::STANDARD
            .decode(value.trim())
            .expect("base64 env value")
    })
}
