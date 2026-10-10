#!/usr/bin/env python3
"""Upload the WASM runtime evidence directory to Cloudflare R2 (REST API).

Reads credentials from the environment (never from the repo). Fails open: if
the evidence directory or credentials are absent, it logs and exits 0 so the
evidence lane does not break a build when R2 is not configured.

Env:
  CLOUDFLARE_API_TOKEN       (required for upload)
  CLOUDFLARE_ACCOUNT_ID      Cloudflare account ID (default Conxian)
  S3_BUCKET                  (default: conxian-wasm-runtime)
  WASM_RUNTIME_EVIDENCE_DIR  (required; the evidence manifest directory)
  WASM_EXPECTED_TESTED_SHA   (used as the object prefix; default 'local')
"""

import os
import pathlib
import sys
import urllib.parse
import urllib.request

ACCOUNT_ID = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "9df5b1e8c9a89154418b7a152ca81e2d")
TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN", "")
BUCKET = os.environ.get("S3_BUCKET", "conxian-wasm-runtime")
EVIDENCE_DIR = os.environ.get("WASM_RUNTIME_EVIDENCE_DIR", "")
SHA = os.environ.get("WASM_EXPECTED_TESTED_SHA", "local")

if not EVIDENCE_DIR or not os.path.isdir(EVIDENCE_DIR):
    print("R2 upload skipped: evidence directory not found")
    sys.exit(0)

if not TOKEN:
    print("R2 upload skipped: credentials not set")
    sys.exit(0)

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
