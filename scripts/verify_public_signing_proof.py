#!/usr/bin/env python3
"""Verify the public, non-release AWS KMS signing conformance artifact."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "docs/architecture/public-signing-conformance-2026-10-14.json"


def openssl_verify(public_pem: Path, signature_der: Path, message: Path) -> bool:
    verified = subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(public_pem),
            "-signature",
            str(signature_der),
            str(message),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    return verified.returncode == 0 and "Verified OK" in verified.stdout


def main() -> None:
    document = json.loads(PROOF.read_text())
    challenge = document["challenge"].encode("utf-8")
    digest = hashlib.sha256(challenge).hexdigest()
    if digest != document["challengeSha256"]:
        raise SystemExit("challenge digest mismatch")

    aliases: set[str] = set()
    public_keys: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="conxian-signing-proof-") as directory:
        root = Path(directory)
        challenge_path = root / "challenge.txt"
        challenge_path.write_bytes(challenge)
        tampered_path = root / "tampered-challenge.txt"
        tampered_path.write_bytes(challenge + b"\x00")

        for index, proof in enumerate(document["proofs"], start=1):
            alias = proof["alias"]
            if alias in aliases:
                raise SystemExit(f"duplicate signer alias: {alias}")
            aliases.add(alias)
            public_key = proof["publicKeySpkiDerBase64"]
            if public_key in public_keys:
                raise SystemExit(f"duplicate signer public key: {alias}")
            public_keys.add(public_key)

            public_der = root / f"public-{index}.der"
            public_pem = root / f"public-{index}.pem"
            signature_der = root / f"signature-{index}.der"
            public_der.write_bytes(base64.b64decode(proof["publicKeySpkiDerBase64"], validate=True))
            signature_der.write_bytes(base64.b64decode(proof["signatureDerBase64"], validate=True))

            subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-pubin",
                    "-inform",
                    "DER",
                    "-in",
                    str(public_der),
                    "-out",
                    str(public_pem),
                ],
                check=True,
                capture_output=True,
            )
            if not openssl_verify(public_pem, signature_der, challenge_path):
                raise SystemExit(f"signature verification failed for {alias}")
            if openssl_verify(public_pem, signature_der, tampered_path):
                raise SystemExit(f"tampered challenge was accepted for {alias}")

    if len(aliases) != 3:
        raise SystemExit(f"expected 3 distinct signers, found {len(aliases)}")

    print(
        f"public signing proof valid: {len(aliases)} signatures; "
        f"tamper rejection valid; sha256={digest}"
    )


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, subprocess.SubprocessError) as error:
        print(f"public signing proof invalid: {error}", file=sys.stderr)
        raise SystemExit(1) from error
