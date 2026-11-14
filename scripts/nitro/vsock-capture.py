#!/usr/bin/env python3
"""Parent-side vsock capture for the Conxian Nitro attestation probe.

Runs *on the parent instance*. The probe (inside the enclave) connects out to
the parent over vsock; this script accepts that connection, sends the probe's
runtime inputs (user data, nonce, recipient public key), then reads back the
base64 attestation document. This is the receiving half the pipeline was
missing: `nitro-cli run-enclave` does not print the enclave's stdout, and the
enclave console is only available in `--debug-mode`, which zeroes the PCRs and
cannot produce production evidence.

Topology: the *enclave* connects to `VMADDR_CID_PARENT` (CID 3); the *parent*
listens on `VMADDR_CID_ANY` at port 5005. A vsock connection carries traffic in
both directions, so the inputs are written first and the document read back on
the same socket.

Usage:
    python3 vsock-capture.py <out-file> [port] [timeout-seconds]
      [user-data-file] [nonce-hex-file] [public-key-hex-file]

The inputs are optional; the attestation document is the only required output.
Exits non-zero on timeout or empty capture so a failed capture fails the
pipeline instead of silently verifying an empty document.
"""

import socket
import sys
import time

DEFAULT_PORT = 5005
DEFAULT_TIMEOUT = 120


def read_optional(path):
    if not path:
        return b""
    with open(path, "rb") as handle:
        return handle.read().strip()


def main():
    if len(sys.argv) < 2:
        print(
            "usage: vsock-capture.py <out-file> [port] [timeout-seconds]"
            " [user-data-file] [nonce-hex-file] [public-key-hex-file]",
            file=sys.stderr,
        )
        return 2

    out_path = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    timeout = float(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_TIMEOUT
    user_data = read_optional(sys.argv[4] if len(sys.argv) > 4 else None)
    nonce = read_optional(sys.argv[5] if len(sys.argv) > 5 else None)
    public_key = read_optional(sys.argv[6] if len(sys.argv) > 6 else None)

    if not hasattr(socket, "AF_VSOCK"):
        print("AF_VSOCK unavailable in this Python build", file=sys.stderr)
        return 3

    listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    listener.settimeout(timeout)
    listener.bind((socket.VMADDR_CID_ANY, port))
    listener.listen(1)
    print(f"listening on vsock port {port} (timeout {timeout:g}s)", file=sys.stderr)

    conn, _ = listener.accept()
    print("enclave connected", file=sys.stderr)

    # Fixed-width request frame so the probe reads it deterministically.
    request = (
        len(user_data).to_bytes(4, "big")
        + user_data
        + len(nonce).to_bytes(4, "big")
        + nonce
        + len(public_key).to_bytes(4, "big")
        + public_key
    )
    conn.sendall(request)

    deadline = time.monotonic() + timeout
    conn.settimeout(max(1.0, deadline - time.monotonic()))

    chunks = []
    while True:
        try:
            chunk = conn.recv(65536)
        except socket.timeout:
            print("timed out reading attestation document", file=sys.stderr)
            return 4
        if not chunk:
            break
        chunks.append(chunk)

    conn.close()
    listener.close()

    payload = b"".join(chunks)
    if not payload:
        print("received empty attestation document", file=sys.stderr)
        return 5

    with open(out_path, "wb") as handle:
        handle.write(payload)
    print(f"wrote {len(payload)} bytes to {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
