//! Nitro enclave attestation probe (DRAFT — validate against the pinned
//! `aws-nitro-enclaves-nsm-api` version before first production use).
//!
//! Runs *inside* a Nitro enclave. The probe connects out to the parent
//! instance over vsock, reads the runtime inputs (user data, nonce, recipient
//! public key) the parent sends, requests an attestation document from the
//! Nitro Security Module (NSM) bound to those inputs, and writes the CBOR/COSE
//! document back as base64 on the same socket. The parent hands it to
//! `examples/nitro_attest_verify.rs` for fail-closed verification.
//!
//! The NSM binds the *current* PCR measurements into the document, so the
//! parent can only verify if the running EIF matches the pinned PCR policy.
//!
//! Note: `nitro-cli run-enclave` does not inject environment variables and the
//! enclave console is only readable in `--debug-mode` (which zeroes the PCRs).
//! Runtime inputs and the document therefore travel over vsock, not env/console.

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use base64::Engine;
use serde_bytes::ByteBuf;
use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;

/// vsock CID of the parent instance (AWS Nitro `VMADDR_CID_PARENT`).
const VSOCK_PARENT_CID: u32 = 3;
/// vsock port the parent listens on for the attestation document.
const VSOCK_PORT: u32 = 5005;

fn main() {
    let mut stream = connect_parent();
    let (user_data, nonce, public_key) = match read_request(&mut stream) {
        Ok(parts) => parts,
        Err(err) => {
            eprintln!("request read failed: {err}");
            std::process::exit(1);
        }
    };

    let fd = nsm_init();
    let request = Request::Attestation {
        user_data: user_data.map(ByteBuf::from),
        nonce: nonce.map(ByteBuf::from),
        public_key: public_key.map(ByteBuf::from),
    };

    let response = nsm_process_request(fd, request);
    nsm_exit(fd);

    match response {
        Response::Attestation { document } => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(document);
            // Console print is a convenience for debug-mode runs only; the
            // vsock write below is the authoritative capture path.
            println!("{encoded}");
            if stream.write_all(encoded.as_bytes()).is_err() {
                eprintln!("vsock write failed");
                std::process::exit(1);
            }
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

/// Connect out to the parent instance's vsock listener.
fn connect_parent() -> std::fs::File {
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
    unsafe { std::fs::File::from_raw_fd(fd) }
}

/// Read the parent's fixed-width request frame: three length-prefixed fields.
fn read_request(
    stream: &mut std::fs::File,
) -> std::io::Result<(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> {
    let user_data = read_field(stream)?;
    let nonce = read_field(stream)?;
    let public_key = read_field(stream)?;
    Ok((user_data, nonce, public_key))
}

fn read_field(stream: &mut std::fs::File) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(None);
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(Some(buf))
}
