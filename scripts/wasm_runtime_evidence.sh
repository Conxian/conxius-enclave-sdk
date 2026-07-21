#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATED="$ROOT/tests/wasm/.generated"
EVIDENCE_DIR="${WASM_RUNTIME_EVIDENCE_DIR:-${RUNNER_TEMP:-/tmp}/conxius-wasm-runtime-evidence}"
EVIDENCE_FILE="$EVIDENCE_DIR/runtime-evidence.env"
CFLAGS_VALUE="-Dmemmove=__builtin_memmove -Dmemcpy=__builtin_memcpy -Dmemset=__builtin_memset -Dmemcmp=__builtin_memcmp"
EXPECTED_NODE_VERSION="${WASM_EXPECTED_NODE_VERSION:-22.23.1}"
EXPECTED_NPM_VERSION="${WASM_EXPECTED_NPM_VERSION:-11.18.0}"
EXPECTED_RUST_VERSION="${WASM_EXPECTED_RUST_VERSION:-1.97.1}"
EXPECTED_PLAYWRIGHT_VERSION="${WASM_EXPECTED_PLAYWRIGHT_VERSION:-1.54.2}"
STRICT_TOOLCHAIN="${WASM_STRICT_TOOLCHAIN:-0}"
KEEP_GENERATED="${CONXIAN_KEEP_WASM_GENERATED:-0}"

WORKFLOW_EVENT="${GITHUB_EVENT_NAME:-local}"
WORKFLOW_REF="${GITHUB_REF:-local}"
WORKFLOW_SHA="${GITHUB_SHA:-local}"
EXPECTED_TESTED_SHA="${WASM_EXPECTED_TESTED_SHA:-}"
PR_HEAD_SHA="${WASM_PR_HEAD_SHA:-}"
MERGE_REF_SHA="${WASM_MERGE_REF_SHA:-}"

cd "$ROOT"
rm -rf "$EVIDENCE_DIR"
mkdir -p "$EVIDENCE_DIR"

TESTED_HEAD_SHA="$(git rev-parse HEAD)"
TESTED_BRANCH="$(git branch --show-current)"
TESTED_BRANCH="${TESTED_BRANCH:-detached}"

{
  printf 'tested_head_sha=%s\n' "$TESTED_HEAD_SHA"
  printf 'expected_tested_sha=%s\n' "${EXPECTED_TESTED_SHA:-none}"
  printf 'pr_head_sha=%s\n' "${PR_HEAD_SHA:-none}"
  printf 'merge_ref_sha=%s\n' "${MERGE_REF_SHA:-none}"
  printf 'workflow_event=%s\n' "$WORKFLOW_EVENT"
  printf 'workflow_ref=%s\n' "$WORKFLOW_REF"
  printf 'workflow_sha=%s\n' "$WORKFLOW_SHA"
  printf 'tested_branch=%s\n' "$TESTED_BRANCH"
} | tee "$EVIDENCE_FILE"

provenance_failure() {
  printf 'provenance_status=failed\nprovenance_failure=%s\n' "$1" | tee -a "$EVIDENCE_FILE" >&2
  exit 1
}

if [[ -n "$EXPECTED_TESTED_SHA" && "$TESTED_HEAD_SHA" != "$EXPECTED_TESTED_SHA" ]]; then
  provenance_failure "expected-tested-head-mismatch"
fi
if [[ "$WORKFLOW_EVENT" == "pull_request" && -z "$PR_HEAD_SHA" ]]; then
  provenance_failure "missing-pr-head-sha"
fi
if [[ -n "$PR_HEAD_SHA" && "$TESTED_HEAD_SHA" != "$PR_HEAD_SHA" ]]; then
  provenance_failure "pr-head-mismatch"
fi

printf 'provenance_status=verified\n' | tee -a "$EVIDENCE_FILE"

if [[ "${CI:-}" == "true" || "${CI:-}" == "1" ]]; then
  STRICT_TOOLCHAIN=1
fi

cleanup() {
  if [[ "$KEEP_GENERATED" == "1" ]]; then
    echo "Retaining generated WASM output because CONXIAN_KEEP_WASM_GENERATED=1"
  else
    rm -rf "$GENERATED"
  fi
}
trap cleanup EXIT

for command in node npm rustc cargo; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "$command is required" >&2
    exit 1
  }
done

validate_toolchain() {
  local label="$1"
  local actual="$2"
  local expected="$3"

  if [[ "$STRICT_TOOLCHAIN" == "1" && "$actual" != "$expected" ]]; then
    echo "expected $label $expected, found: $actual" >&2
    exit 1
  fi
  echo "$label: $actual (expected $expected)"
}

validate_toolchain "Node.js" "$(node --version | sed 's/^v//')" "$EXPECTED_NODE_VERSION"
validate_toolchain "npm" "$(npm --version)" "$EXPECTED_NPM_VERSION"
validate_toolchain "Rust" "$(rustc --version | awk '{print $2}')" "$EXPECTED_RUST_VERSION"
validate_toolchain "Cargo" "$(cargo --version | awk '{print $2}')" "$EXPECTED_RUST_VERSION"

command -v wasm-pack >/dev/null 2>&1 || {
  echo "wasm-pack 0.15.0 is required" >&2
  exit 1
}

if [[ "$(wasm-pack --version)" != "wasm-pack 0.15.0" ]]; then
  echo "expected wasm-pack 0.15.0, found: $(wasm-pack --version)" >&2
  exit 1
fi

if [[ ! -x "$ROOT/tests/wasm/node_modules/.bin/playwright" ]]; then
  npm --prefix "$ROOT/tests/wasm" ci
fi

PLAYWRIGHT_VERSION="$(node -p 'require("./tests/wasm/node_modules/playwright/package.json").version')"
validate_toolchain "Playwright" "$PLAYWRIGHT_VERSION" "$EXPECTED_PLAYWRIGHT_VERSION"

PLAYWRIGHT_EXECUTABLE="$(
  cd "$ROOT/tests/wasm"
  node --input-type=module -e 'import { chromium } from "playwright"; process.stdout.write(chromium.executablePath());'
)"
if [[ -z "$PLAYWRIGHT_EXECUTABLE" || ! -x "$PLAYWRIGHT_EXECUTABLE" ]]; then
  printf 'playwright_status=blocked\nplaywright_executable=%s\n' "${PLAYWRIGHT_EXECUTABLE:-none}" | tee -a "$EVIDENCE_FILE" >&2
  echo "Playwright-managed Chromium executable is unavailable" >&2
  exit 1
fi

PLAYWRIGHT_EXECUTABLE="$(realpath "$PLAYWRIGHT_EXECUTABLE")"
BROWSER_VERSION="$("$PLAYWRIGHT_EXECUTABLE" --version)"
BROWSER_SHA256="$(sha256sum "$PLAYWRIGHT_EXECUTABLE" | awk '{print $1}')"
{
  printf 'playwright_status=verified\n'
  printf 'playwright_version=%s\n' "$PLAYWRIGHT_VERSION"
  printf 'playwright_executable=%s\n' "$PLAYWRIGHT_EXECUTABLE"
  printf 'browser_version=%s\n' "$BROWSER_VERSION"
  printf 'browser_sha256=%s\n' "$BROWSER_SHA256"
} | tee -a "$EVIDENCE_FILE"

rm -rf "$GENERATED"
mkdir -p "$GENERATED"

build_lane() {
  local target="$1"
  local output="$2"
  echo "Building generated WASM package: target=$target output=$output"
  CFLAGS="$CFLAGS_VALUE" wasm-pack build --release --target "$target" --out-dir "$output" -- --locked
}

build_lane nodejs "$GENERATED/node"
build_lane web "$GENERATED/web"

node "$ROOT/tests/wasm/run.mjs"
