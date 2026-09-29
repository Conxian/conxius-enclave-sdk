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
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use base64::Engine;
use serde_bytes::ByteBuf;
use std::io::Write;
use std::os::unix::io::FromRawFd;

/// vsock CID of the parent instance (AWS Nitro `VMADDR_CID_PARENT`).
const VSOCK_PARENT_CID: u32 = 3;
/// vsock port the parent listens on for the attestation document.
const VSOCK_PORT: u32 = 5005;

fn main() {
    let user_data = env_b64("USER_DATA_B64").map(ByteBuf::from);
    let nonce = env_b64("NONCE_B64").map(ByteBuf::from);
    let public_key = env_b64("PUBLIC_KEY_B64").map(ByteBuf::from);

    let fd = nsm_init();
    let request = Request::Attestation {
        user_data,
        nonce,
        public_key,
    };

    let response = nsm_process_request(fd, request);
    nsm_exit(fd);

    match response {
        Response::Attestation { document } => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(document);
            println!("{encoded}");
            send_via_vsock(encoded.as_bytes());
        }
        Response::Error(err) => {
            eprintln!("NSM error: {err:?}");
            std::process::exit(1);
        }
        other => {
            eprintln!("unexpected NSM response: {other:?}");
            std::process::exit(1);
        }
    }
}

fn send_via_vsock(data: &[u8]) {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        eprintln!("vsock socket failed");
        std::process::exit(1);
    }
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = VSOCK_PARENT_CID;
    addr.svm_port = VSOCK_PORT;
    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        eprintln!("vsock connect failed");
        std::process::exit(1);
    }
    let mut stream = unsafe { std::fs::File::from_raw_fd(fd) };
    if stream.write_all(data).is_err() {
        eprintln!("vsock write failed");
        std::process::exit(1);
    }
}

fn env_b64(name: &str) -> Option<Vec<u8>> {
    std::env::var(name).ok().map(|value| {
        base64::engine::general_purpose::STANDARD
            .decode(value.trim())
            .expect("base64 env value")
    })
}
