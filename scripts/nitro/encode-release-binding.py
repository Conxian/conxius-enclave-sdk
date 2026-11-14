#!/usr/bin/env python3
"""Encode a Conxian Nitro KMS release binding for use as enclave `user_data`.

Mirrors `NitroReleaseBinding::encode` in `src/enclave/nitro.rs` exactly so the
parent can produce the `user_data` blob the enclave binds into its attestation
document. Keeping one byte layout in one place avoids a hand-rolled encoding
that silently drifts from the Rust decoder and fails closed for the wrong
reason.

Layout (all integers big-endian):
    domain              b"CONXIAN-NITRO-KMS-RELEASE-BINDING/v1\\0"
    version             u16  (NITRO_RELEASE_BINDING_VERSION)
    purpose             u16 length + UTF-8 bytes
    operation_digest    [u8; 32]
    kms_key_identifier_hash [u8; 32]
    policy_version      u32
    policy_digest       [u8; 32]
    expires_at_ms       u64
    replay_identity     [u8; 32]

Usage:
    python3 encode-release-binding.py <out-file> \\
        --purpose KMS_RELEASE \\
        --operation-digest <64-hex> \\
        --kms-key-identifier-hash <64-hex> \\
        --policy-version 1 \\
        --policy-digest <64-hex> \\
        --expires-at-ms <int> \\
        --replay-identity <64-hex>

Exits non-zero on any malformed or zero-valued field, matching the Rust
constructor's fail-closed validation.
"""

import argparse
import sys

DOMAIN = b"CONXIAN-NITRO-KMS-RELEASE-BINDING/v1\x00"
BINDING_VERSION = 1
MAX_PURPOSE_BYTES = 128


def hex32(name: str, value: str) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise SystemExit(f"{name}: not valid hex")
    if len(raw) != 32:
        raise SystemExit(f"{name}: expected 32 bytes, got {len(raw)}")
    if all(byte == 0 for byte in raw):
        raise SystemExit(f"{name}: must not be all zero")
    return raw


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("out_file")
    parser.add_argument("--purpose", required=True)
    parser.add_argument("--operation-digest", required=True)
    parser.add_argument("--kms-key-identifier-hash", required=True)
    parser.add_argument("--policy-version", type=int, required=True)
    parser.add_argument("--policy-digest", required=True)
    parser.add_argument("--expires-at-ms", type=int, required=True)
    parser.add_argument("--replay-identity", required=True)
    args = parser.parse_args()

    purpose = args.purpose.encode("utf-8")
    if not purpose or len(purpose) > MAX_PURPOSE_BYTES:
        raise SystemExit("purpose: empty or exceeds 128 bytes")
    if args.policy_version == 0:
        raise SystemExit("policy_version: must be non-zero")
    if args.expires_at_ms == 0:
        raise SystemExit("expires_at_ms: must be non-zero")

    encoded = bytearray()
    encoded += DOMAIN
    encoded += BINDING_VERSION.to_bytes(2, "big")
    encoded += len(purpose).to_bytes(2, "big")
    encoded += purpose
    encoded += hex32("operation_digest", args.operation_digest)
    encoded += hex32("kms_key_identifier_hash", args.kms_key_identifier_hash)
    encoded += args.policy_version.to_bytes(4, "big")
    encoded += hex32("policy_digest", args.policy_digest)
    encoded += args.expires_at_ms.to_bytes(8, "big")
    encoded += hex32("replay_identity", args.replay_identity)

    with open(args.out_file, "wb") as handle:
        handle.write(encoded)
    print(f"wrote {len(encoded)} bytes to {args.out_file}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
