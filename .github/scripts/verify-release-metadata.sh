#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: .github/scripts/verify-release-metadata.sh <version>

Accepted version formats:
- X.Y.Z
- vX.Y.Z

Behavior:
- In tag context (GITHUB_REF_TYPE=tag), validates tag format is vX.Y.Z.
- Verifies Cargo.toml [package].version matches the expected release version.
- Verifies CHANGELOG.md contains a section for that release version.
- Verifies Cargo.lock is tracked and is current under `cargo metadata --locked`.
- In tag context, verifies the checked-out commit is the tagged commit.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

expected_input="${1:-${RELEASE_VERSION:-}}"
if [[ -z "$expected_input" ]]; then
  if [[ "${GITHUB_REF_TYPE:-}" == "tag" && -n "${GITHUB_REF_NAME:-}" ]]; then
    expected_input="${GITHUB_REF_NAME}"
  else
    echo "error: missing expected release version argument" >&2
    usage >&2
    exit 1
  fi
fi

normalize_version() {
  local raw="$1"
  if [[ "$raw" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$raw" =~ ^([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

normalize_tag() {
  local raw="$1"
  if [[ "$raw" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

if ! expected_version="$(normalize_version "$expected_input")"; then
  echo "error: expected version must be X.Y.Z or vX.Y.Z, got '$expected_input'" >&2
  exit 1
fi

expected_tag="v${expected_version}"

if [[ "${GITHUB_REF_TYPE:-}" == "tag" ]]; then
  if ! tag_version="$(normalize_tag "${GITHUB_REF_NAME:-}")"; then
    echo "error: release tags must use format vX.Y.Z, got '${GITHUB_REF_NAME:-<unset>}'" >&2
    exit 1
  fi

  if [[ "$tag_version" != "$expected_version" ]]; then
    echo "error: tag version '${GITHUB_REF_NAME}' does not match expected '${expected_tag}'" >&2
    exit 1
  fi
fi

if [[ ! -f Cargo.toml ]]; then
  echo "error: Cargo.toml not found" >&2
  exit 1
fi

if [[ ! -f CHANGELOG.md ]]; then
  echo "error: CHANGELOG.md not found" >&2
  exit 1
fi

if ! git ls-files --error-unmatch Cargo.lock >/dev/null 2>&1; then
  echo "error: Cargo.lock must be tracked for release verification" >&2
  exit 1
fi

if ! cargo metadata --locked --no-deps --format-version 1 >/dev/null; then
  echo "error: Cargo.lock is missing, stale, or otherwise rejected by cargo metadata --locked" >&2
  exit 1
fi

cargo_version="$({
  python3 - <<'PY'
import tomllib
with open('Cargo.toml', 'rb') as f:
    cargo = tomllib.load(f)
print(cargo['package']['version'])
PY
} | tr -d '[:space:]')"

if [[ "$cargo_version" != "$expected_version" ]]; then
  echo "error: Cargo.toml version '$cargo_version' does not match expected '$expected_version'" >&2
  exit 1
fi

lock_version="$({
  python3 - <<'PY'
import tomllib
with open('Cargo.lock', 'rb') as f:
    lock = tomllib.load(f)
matches = [
    package['version']
    for package in lock.get('package', [])
    if package.get('name') == 'conxius-enclave-sdk'
]
if len(matches) != 1:
    raise SystemExit(f"expected one conxius-enclave-sdk package in Cargo.lock, found {len(matches)}")
print(matches[0])
PY
} | tr -d '[:space:]')"

if [[ "$lock_version" != "$expected_version" ]]; then
  echo "error: Cargo.lock package version '$lock_version' does not match expected '$expected_version'" >&2
  exit 1
fi

escaped_version="$(printf '%s' "$expected_version" | sed 's/\./\\./g')"
if ! grep -Eiq "^##[[:space:]]+\\[?v?${escaped_version}\\]?([[:space:]]*-[[:space:]]*[0-9]{4}-[0-9]{2}-[0-9]{2})?[[:space:]]*$" CHANGELOG.md; then
  echo "error: CHANGELOG.md is missing a section header for version '$expected_version'" >&2
  echo "expected something like: '## [${expected_version}] - YYYY-MM-DD'" >&2
  exit 1
fi

if [[ "${GITHUB_REF_TYPE:-}" == "tag" ]]; then
  checked_out_commit="$(git rev-parse HEAD)"
  tagged_commit="$(git rev-list -n 1 "${GITHUB_REF_NAME}^{commit}")"
  if [[ "$checked_out_commit" != "$tagged_commit" ]]; then
    echo "error: checked-out commit '$checked_out_commit' does not match tag '${GITHUB_REF_NAME}' commit '$tagged_commit'" >&2
    exit 1
  fi
  if [[ -n "${GITHUB_SHA:-}" && "$checked_out_commit" != "$GITHUB_SHA" ]]; then
    echo "error: checked-out commit '$checked_out_commit' does not match GITHUB_SHA '$GITHUB_SHA'" >&2
    exit 1
  fi
fi

echo "Release metadata verification passed for ${expected_tag}"
