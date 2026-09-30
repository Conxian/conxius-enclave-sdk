#!/usr/bin/env python3
"""Upload the WASM runtime evidence directory to Cloudflare R2.

Reads credentials from the environment (never from the repo). Fails open: if
the evidence directory or credentials are absent, it logs and exits 0 so the
evidence lane does not break a build when R2 is not configured.

Env:
  S3_ENDPOINT              (default: Conxian R2 endpoint)
  S3_BUCKET                (default: conxian-wasm-runtime)
  S3_ACCESS_KEY_ID         (required for upload)
  S3_SECRET_ACCESS_KEY     (required for upload)
  WASM_RUNTIME_EVIDENCE_DIR  (required; the evidence manifest directory)
  WASM_EXPECTED_TESTED_SHA   (used as the object prefix; default 'local')
"""

import os
import pathlib
import sys

ENDPOINT = os.environ.get(
    "S3_ENDPOINT",
    "https://9df5b1e8c9a89154418b7a152ca81e2d.r2.cloudflarestorage.com",
)
BUCKET = os.environ.get("S3_BUCKET", "conxian-wasm-runtime")
ACCESS_KEY = os.environ.get("S3_ACCESS_KEY_ID", "")
SECRET_KEY = os.environ.get("S3_SECRET_ACCESS_KEY", "")
EVIDENCE_DIR = os.environ.get("WASM_RUNTIME_EVIDENCE_DIR", "")
SHA = os.environ.get("WASM_EXPECTED_TESTED_SHA", "local")

if not EVIDENCE_DIR or not os.path.isdir(EVIDENCE_DIR):
    print("R2 upload skipped: evidence directory not found")
    sys.exit(0)

if not ACCESS_KEY or not SECRET_KEY:
    print("R2 upload skipped: S3 credentials not set")
    sys.exit(0)

import boto3  # noqa: E402

prefix = f"wasm-runtime/{SHA}"
s3 = boto3.client(
    "s3",
    endpoint_url=ENDPOINT,
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    region_name="auto",
)

uploaded = 0
for path in sorted(pathlib.Path(EVIDENCE_DIR).rglob("*")):
    if not path.is_file():
        continue
    key = f"{prefix}/{path.relative_to(EVIDENCE_DIR)}"
    s3.upload_file(str(path), BUCKET, key)
    uploaded += 1

print(f"R2 upload complete: {uploaded} files -> s3://{BUCKET}/{prefix}")
