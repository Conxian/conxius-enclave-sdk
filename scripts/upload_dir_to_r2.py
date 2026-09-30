#!/usr/bin/env python3
"""Publish a directory of evidence to Cloudflare R2.

Credentials come from the environment only. Fails open: if the source directory
or credentials are absent it logs and exits 0, so a missing publish never breaks
a build.

Env:
  S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY
  S3_SOURCE_DIR  required; local directory to upload
  S3_PREFIX      object-key prefix, e.g. "dkg-ceremony/<sha>"
  S3_LATEST_KEY  optional; also copy every file under this prefix (stable
                 "latest" path so consumers do not need the commit SHA)
"""

import os
import pathlib
import sys

ENDPOINT = os.environ.get(
    "S3_ENDPOINT",
    "https://9df5b1e8c9a89154418b7a152ca81e2d.r2.cloudflarestorage.com",
)
BUCKET = os.environ.get("S3_BUCKET", "conxian-wasm-runtime")
ACCESS = os.environ.get("S3_ACCESS_KEY_ID", "")
SECRET = os.environ.get("S3_SECRET_ACCESS_KEY", "")
SRC = os.environ.get("S3_SOURCE_DIR", "")
PREFIX = os.environ.get("S3_PREFIX", "").strip("/")
LATEST = os.environ.get("S3_LATEST_KEY", "").strip("/")

if not (SRC and os.path.isdir(SRC) and ACCESS and SECRET):
    print("R2 publish skipped (missing source directory or credentials)")
    sys.exit(0)

import boto3  # noqa: E402

s3 = boto3.client(
    "s3",
    endpoint_url=ENDPOINT,
    aws_access_key_id=ACCESS,
    aws_secret_access_key=SECRET,
    region_name="auto",
)

count = 0
for path in sorted(pathlib.Path(SRC).rglob("*")):
    if not path.is_file():
        continue
    rel = path.relative_to(SRC)
    keys = [f"{PREFIX}/{rel}"] if PREFIX else [str(rel)]
    if LATEST:
        keys.append(f"{LATEST}/{rel}")
    for key in keys:
        s3.upload_file(str(path), BUCKET, key)
        count += 1

print(f"R2 publish complete: {count} objects under s3://{BUCKET}/{PREFIX or '.'}")
