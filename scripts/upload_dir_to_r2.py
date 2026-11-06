#!/usr/bin/env python3
"""Publish a directory of evidence to Cloudflare R2 (REST API).

Credentials come from the environment only. Skips (exit 0) when the source
directory, token or account ID are absent so an unconfigured publish never
breaks a build; set R2_REQUIRED=1 to fail closed instead. The retired
pre-2026-11-06 account is rejected outright so publishing can never silently
target it.

Env:
  CLOUDFLARE_API_TOKEN    required; API token with R2 edit permission
  CLOUDFLARE_ACCOUNT_ID   required; Cloudflare account ID (no default)
  R2_REQUIRED             optional; "1" makes a missing account ID a failure
  S3_BUCKET               (default: conxian-wasm-runtime)
  S3_SOURCE_DIR           required; local directory to upload
  S3_PREFIX               object-key prefix, e.g. "dkg-ceremony/<sha>"
  S3_LATEST_KEY           optional; also copy every file under this prefix
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
SRC = os.environ.get("S3_SOURCE_DIR", "")
PREFIX = os.environ.get("S3_PREFIX", "").strip("/")
LATEST = os.environ.get("S3_LATEST_KEY", "").strip("/")
REQUIRED = os.environ.get("R2_REQUIRED", "").strip().lower() in ("1", "true", "yes")

if not (SRC and os.path.isdir(SRC) and TOKEN):
    print("R2 publish skipped (missing source directory or credentials)")
    sys.exit(0)

if not ACCOUNT_ID:
    message = "R2 publish skipped: CLOUDFLARE_ACCOUNT_ID is not set"
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


def put_object(key, data):
    req = urllib.request.Request(
        f"{BASE}/{urllib.parse.quote(key, safe='/')}",
        data=data,
        method="PUT",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        resp.read()


count = 0
for path in sorted(pathlib.Path(SRC).rglob("*")):
    if not path.is_file():
        continue
    rel = path.relative_to(SRC)
    data = path.read_bytes()
    keys = [f"{PREFIX}/{rel}"] if PREFIX else [str(rel)]
    if LATEST:
        keys.append(f"{LATEST}/{rel}")
    for key in keys:
        put_object(key, data)
        count += 1

print(f"R2 publish complete: {count} objects under {BUCKET}/{PREFIX or '.'}")
