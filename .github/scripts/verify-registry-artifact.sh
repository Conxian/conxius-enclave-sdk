#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: .github/scripts/verify-registry-artifact.sh <version> <crate> <checksum> <output-json>

Downloads the named conxius-enclave-sdk release from crates.io with bounded
retry/backoff and compares its SHA-256 digest with the previously packaged
release crate. A concise JSON comparison record is written on success.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

version="${1:-}"
expected_crate_path="${2:-}"
checksum_path="${3:-}"
output_path="${4:-}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: version must be X.Y.Z, got '$version'" >&2
  exit 1
fi

for path in "$expected_crate_path" "$checksum_path"; do
  if [[ ! -f "$path" ]]; then
    echo "error: required release evidence file not found: $path" >&2
    exit 1
  fi
done

expected_name="conxius-enclave-sdk-${version}.crate"
if [[ "$(basename "$expected_crate_path")" != "$expected_name" ]]; then
  echo "error: crate filename '$(basename "$expected_crate_path")' does not match '$expected_name'" >&2
  exit 1
fi

expected_sha256="$(awk 'NF {print $1; exit}' "$checksum_path")"
if [[ ! "$expected_sha256" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "error: checksum file does not contain a SHA-256 digest" >&2
  exit 1
fi
packaged_sha256="$(sha256sum "$expected_crate_path" | awk '{print $1}')"
if [[ "$packaged_sha256" != "$expected_sha256" ]]; then
  echo "error: attested crate does not match its checksum file" >&2
  exit 1
fi

registry_url="https://crates.io/api/v1/crates/conxius-enclave-sdk/${version}/download"
work_dir="$(mktemp -d)"
download_path="${work_dir}/${expected_name}"
trap 'rm -rf "$work_dir"' EXIT

# Registry indexes and the download CDN can converge at different times after
# publication. Keep the retry window finite and fail closed after the final try.
retry_delays=(5 10 20 40 60)
attempts=0
registry_sha256=""
for delay in "${retry_delays[@]}"; do
  attempts=$((attempts + 1))
  rm -f "$download_path"
  if curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "$registry_url" --output "$download_path"; then
    registry_sha256="$(sha256sum "$download_path" | awk '{print $1}')"
    if [[ "$registry_sha256" == "$expected_sha256" ]]; then
      break
    fi
    echo "registry artifact digest mismatch on attempt ${attempts}; retrying" >&2
  else
    echo "registry artifact unavailable on attempt ${attempts}; retrying" >&2
  fi
  if (( attempts < ${#retry_delays[@]} )); then
    sleep "$delay"
  fi
done

if [[ "$registry_sha256" != "$expected_sha256" ]]; then
  echo "error: crates.io artifact did not match the attested crate after ${attempts} attempts" >&2
  exit 1
fi

mkdir -p "$(dirname "$output_path")"
python3 - "$output_path" "$expected_name" "$packaged_sha256" "$registry_sha256" "$registry_url" "$attempts" <<'PY'
import json
import sys
from pathlib import Path

output_path, artifact_name, expected_sha256, registry_sha256, registry_url, attempts = sys.argv[1:]
record = {
    "artifact": artifact_name,
    "expectedSha256": expected_sha256,
    "matched": expected_sha256 == registry_sha256,
    "package": "conxius-enclave-sdk",
    "registry": "crates.io",
    "registrySha256": registry_sha256,
    "registryUrl": registry_url,
    "version": artifact_name.removeprefix("conxius-enclave-sdk-").removesuffix(".crate"),
    "verificationMethod": "sha256(downloaded crates.io crate) == sha256(attested crate)",
    "attempts": int(attempts),
}
if not record["matched"]:
    raise SystemExit("registry comparison is not a match")
Path(output_path).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo "Registry artifact verification passed for v${version} after ${attempts} attempt(s)"
