#!/usr/bin/env python3
"""Publish a directory of evidence to Cloudflare R2 (REST API).

Credentials come from the environment only. Fails open: if the source directory
or credentials are absent it logs and exits 0, so a missing publish never breaks
a build.

Env:
  CLOUDFLARE_API_TOKEN    required; API token with R2 edit permission
  CLOUDFLARE_ACCOUNT_ID   Cloudflare account ID (default Conxian)
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

ACCOUNT_ID = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "9df5b1e8c9a89154418b7a152ca81e2d")
TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN", "")
BUCKET = os.environ.get("S3_BUCKET", "conxian-wasm-runtime")
SRC = os.environ.get("S3_SOURCE_DIR", "")
PREFIX = os.environ.get("S3_PREFIX", "").strip("/")
LATEST = os.environ.get("S3_LATEST_KEY", "").strip("/")

if not (SRC and os.path.isdir(SRC) and TOKEN):
    print("R2 publish skipped (missing source directory or credentials)")
    sys.exit(0)

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
