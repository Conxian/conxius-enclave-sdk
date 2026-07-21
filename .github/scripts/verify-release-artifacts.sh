#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: .github/scripts/verify-release-artifacts.sh <version> <crate> <checksum> <sbom> [manifest]

Verifies that a packaged crate, its SHA-256 checksum, and SPDX JSON SBOM all
describe the requested package version. If a manifest is supplied, its version,
tag, source identity, evidence hashes, and optional registry comparison are
checked as well.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

version="${1:-}"
crate_path="${2:-}"
checksum_path="${3:-}"
sbom_path="${4:-}"
manifest_path="${5:-}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: version must be X.Y.Z, got '$version'" >&2
  exit 1
fi

for path in "$crate_path" "$checksum_path" "$sbom_path"; do
  if [[ ! -f "$path" ]]; then
    echo "error: required release evidence file not found: $path" >&2
    exit 1
  fi
done

expected_name="conxius-enclave-sdk-${version}.crate"
if [[ "$(basename "$crate_path")" != "$expected_name" ]]; then
  echo "error: crate filename '$(basename "$crate_path")' does not match '$expected_name'" >&2
  exit 1
fi

actual_sha256="$(sha256sum "$crate_path" | awk '{print $1}')"
expected_sha256="$(awk 'NF {print $1; exit}' "$checksum_path")"
if [[ -z "$expected_sha256" || "$actual_sha256" != "$expected_sha256" ]]; then
  echo "error: crate checksum does not match the checksum file" >&2
  exit 1
fi

package_manifest="$(mktemp)"
trap 'rm -f "$package_manifest"' EXIT
tar -xOf "$crate_path" "conxius-enclave-sdk-${version}/Cargo.toml" >"$package_manifest"

python3 - "$package_manifest" "$sbom_path" "$version" <<'PY'
import json
import sys
import tomllib

package_manifest, sbom_path, expected_version = sys.argv[1:]
with open(package_manifest, 'rb') as f:
    cargo = tomllib.load(f)
package = cargo.get('package', {})
if package.get('name') != 'conxius-enclave-sdk':
    raise SystemExit(f"packaged Cargo.toml has unexpected name: {package.get('name')!r}")
if package.get('version') != expected_version:
    raise SystemExit(
        f"packaged Cargo.toml version {package.get('version')!r} does not match {expected_version!r}"
    )

with open(sbom_path, encoding='utf-8') as f:
    sbom = json.load(f)
if sbom.get('spdxVersion') != 'SPDX-2.3':
    raise SystemExit(
        f"expected SPDX-2.3 SBOM, found {sbom.get('spdxVersion')!r}"
    )
matches = [
    item for item in sbom.get('packages', [])
    if item.get('name') == 'conxius-enclave-sdk'
    and item.get('versionInfo') == expected_version
]
if len(matches) != 1:
    raise SystemExit(
        f"expected exactly one SPDX package for conxius-enclave-sdk {expected_version}, found {len(matches)}"
    )
PY

if [[ -n "$manifest_path" ]]; then
  if [[ ! -f "$manifest_path" ]]; then
    echo "error: release manifest not found: $manifest_path" >&2
    exit 1
  fi
  python3 - "$manifest_path" "$version" "$crate_path" "$actual_sha256" "$sbom_path" <<'PY'
import hashlib
import json
import sys
import subprocess
from pathlib import Path

manifest_path, expected_version, crate_path, crate_sha256, sbom_path = sys.argv[1:]
with open(manifest_path, encoding='utf-8') as f:
    manifest = json.load(f)
manifest_dir = Path(manifest_path).parent
if manifest.get('package') != 'conxius-enclave-sdk':
    raise SystemExit('release manifest package does not match conxius-enclave-sdk')
if manifest.get('version') != expected_version:
    raise SystemExit('release manifest version does not match the requested version')
if manifest.get('tag') != f'v{expected_version}':
    raise SystemExit('release manifest tag does not match the requested version')
if manifest.get('workflow') != 'release-strict':
    raise SystemExit('release manifest was not produced by release-strict')
if manifest.get('crate') != Path(crate_path).name:
    raise SystemExit('release manifest crate filename does not match the packaged crate')
if manifest.get('sbom') != Path(sbom_path).name:
    raise SystemExit('release manifest SBOM filename does not match the SBOM')
if manifest.get('crateSha256') != crate_sha256:
    raise SystemExit('release manifest crate checksum does not match the packaged crate')
with open(sbom_path, 'rb') as f:
    sbom_sha256 = hashlib.sha256(f.read()).hexdigest()
if manifest.get('sbomSha256') != sbom_sha256:
    raise SystemExit('release manifest SBOM checksum does not match the SBOM')
lock_path = Path('Cargo.lock')
if not lock_path.is_file():
    raise SystemExit('Cargo.lock is required when verifying a release manifest')
lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest()
if manifest.get('lockSha256') != lock_sha256:
    raise SystemExit('release manifest lockfile checksum does not match Cargo.lock')
if not manifest.get('commit'):
    raise SystemExit('release manifest is missing the source commit')
if not manifest.get('sourceRef'):
    raise SystemExit('release manifest is missing the source ref')

workflow_run = manifest.get('workflowRun')
if not isinstance(workflow_run, dict):
    raise SystemExit('release manifest is missing workflow run identity')
for field in ('repository', 'workflow', 'runId', 'runAttempt', 'event', 'ref', 'commit'):
    if workflow_run.get(field) in (None, ''):
        raise SystemExit(f'release manifest workflow run is missing {field}')
if workflow_run.get('ref') != manifest.get('sourceRef'):
    raise SystemExit('release manifest workflow ref does not match sourceRef')
if workflow_run.get('commit') != manifest.get('commit'):
    raise SystemExit('release manifest workflow commit does not match source commit')

def evidence_path(field: str) -> Path:
    value = manifest.get(field)
    if not isinstance(value, str) or not value:
        raise SystemExit(f'release manifest is missing {field}')
    path = manifest_dir / value
    if not path.is_file():
        raise SystemExit(f'release manifest evidence file is missing: {path}')
    return path

lock_evidence_path = evidence_path('lockfileSha256File')
lock_evidence_sha256 = lock_evidence_path.read_text(encoding='utf-8').split()[0]
if lock_evidence_sha256 != lock_sha256:
    raise SystemExit('lockfile evidence digest does not match Cargo.lock')

provenance_path = evidence_path('provenanceVerification')
provenance_sha256 = hashlib.sha256(provenance_path.read_bytes()).hexdigest()
if manifest.get('provenanceVerificationSha256') != provenance_sha256:
    raise SystemExit('provenance verification digest does not match the evidence file')
with provenance_path.open(encoding='utf-8') as f:
    provenance = json.load(f)
if provenance.get('verified') is not True:
    raise SystemExit('provenance verification evidence is not marked verified')
provenance_policy = provenance.get('policy')
if not isinstance(provenance_policy, dict):
    raise SystemExit('provenance verification evidence is missing its policy identity')
if provenance_policy.get('sourceCommit') != manifest.get('commit'):
    raise SystemExit('provenance source commit does not match the release manifest')
if provenance_policy.get('sourceRef') != manifest.get('sourceRef'):
    raise SystemExit('provenance source ref does not match the release manifest')

registry_name = manifest.get('registryVerification')
if registry_name is not None:
    registry_path = evidence_path('registryVerification')
    registry_sha256 = hashlib.sha256(registry_path.read_bytes()).hexdigest()
    if manifest.get('registryVerificationSha256') != registry_sha256:
        raise SystemExit('registry verification digest does not match the evidence file')
    with registry_path.open(encoding='utf-8') as f:
        registry = json.load(f)
    if registry.get('registry') != 'crates.io':
        raise SystemExit('registry verification did not use crates.io')
    if registry.get('matched') is not True:
        raise SystemExit('registry verification evidence is not marked matched')
    if registry.get('version') != expected_version:
        raise SystemExit('registry verification version does not match the requested version')
    if registry.get('expectedSha256') != crate_sha256:
        raise SystemExit('registry verification expected digest does not match the crate')
    if registry.get('registrySha256') != crate_sha256:
        raise SystemExit('registry verification downloaded digest does not match the crate')
try:
    checked_out_commit = subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], text=True, stderr=subprocess.DEVNULL
    ).strip()
except (OSError, subprocess.CalledProcessError):
    checked_out_commit = ''
if checked_out_commit and manifest.get('commit') != checked_out_commit:
    raise SystemExit('release manifest source commit does not match the checked-out commit')
PY
fi

echo "Release artifact verification passed for v${version}"
