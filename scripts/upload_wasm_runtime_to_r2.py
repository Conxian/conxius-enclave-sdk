#!/usr/bin/env python3
"""Upload the WASM runtime evidence directory to Cloudflare R2 (REST API).

Reads credentials from the environment (never from the repo). Skips (exit 0)
when the evidence directory, token or account ID are absent so an unconfigured
publish never breaks a build; set R2_REQUIRED=1 to fail closed instead. The
retired pre-2026-11-06 account is rejected outright.

Env:
  CLOUDFLARE_API_TOKEN       (required for upload)
  CLOUDFLARE_ACCOUNT_ID      (required; Cloudflare account ID, no default)
  R2_REQUIRED                optional; "1" makes a missing account ID a failure
  S3_BUCKET                  (default: conxian-wasm-runtime)
  WASM_RUNTIME_EVIDENCE_DIR  (required; the evidence manifest directory)
  WASM_EXPECTED_TESTED_SHA   (used as the object prefix; default 'local')
"""

import os
import pathlib
import sys
import urllib.parse
import urllib.request

RETIRED_ACCOUNT_ID = "9df5b1e8c9a89154418b7a152ca81e2d"
ACCOUNT_ID = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN", "")
BUCKET = os.environ.get("S3_BUCKET", "conxian-wasm-runtime")
EVIDENCE_DIR = os.environ.get("WASM_RUNTIME_EVIDENCE_DIR", "")
SHA = os.environ.get("WASM_EXPECTED_TESTED_SHA", "local")
REQUIRED = os.environ.get("R2_REQUIRED", "").strip().lower() in ("1", "true", "yes")

if not EVIDENCE_DIR or not os.path.isdir(EVIDENCE_DIR):
    print("R2 upload skipped: evidence directory not found")
    sys.exit(0)

if not TOKEN:
    print("R2 upload skipped: credentials not set")
    sys.exit(0)

if not ACCOUNT_ID:
    message = "R2 upload skipped: CLOUDFLARE_ACCOUNT_ID is not set"
    if REQUIRED:
        print(f"ERROR: {message}", file=sys.stderr)
        sys.exit(1)
    print(message)
    sys.exit(0)

if ACCOUNT_ID == RETIRED_ACCOUNT_ID:
    print(
        "ERROR: CLOUDFLARE_ACCOUNT_ID points at the retired pre-2026-11-06 "
        "account; refusing to publish. Set it to the current account.",
        file=sys.stderr,
    )
    sys.exit(1)

BASE = (
    f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}"
    f"/r2/buckets/{BUCKET}/objects"
)
prefix = f"wasm-runtime/{SHA}"

uploaded = 0
for path in sorted(pathlib.Path(EVIDENCE_DIR).rglob("*")):
    if not path.is_file():
        continue
    key = f"{prefix}/{path.relative_to(EVIDENCE_DIR)}"
    req = urllib.request.Request(
        f"{BASE}/{urllib.parse.quote(key, safe='/')}",
        data=path.read_bytes(),
        method="PUT",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        resp.read()
    uploaded += 1

print(f"R2 upload complete: {uploaded} files -> {BUCKET}/{prefix}")
