#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${1:-${RUNNER_TEMP:-/tmp}/conxius-wasm-runtime-evidence}"

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
cd "$ROOT_DIR"

exec > >(tee "$OUTPUT_DIR/evidence.txt") 2>&1

TESTED_HEAD_SHA="$(git rev-parse HEAD)"
WORKFLOW_EVENT="${GITHUB_EVENT_NAME:-local}"
WORKFLOW_REF="${GITHUB_REF:-local}"
WORKFLOW_SHA="${GITHUB_SHA:-local}"
PR_HEAD_SHA="${WASM_PR_HEAD_SHA:-}"
EXPECTED_TESTED_SHA="${WASM_EXPECTED_TESTED_SHA:-}"

if [[ -n "$EXPECTED_TESTED_SHA" && "$TESTED_HEAD_SHA" != "$EXPECTED_TESTED_SHA" ]]; then
  echo "PROVENANCE_FAILED reason=unexpected-tested-head expected=$EXPECTED_TESTED_SHA actual=$TESTED_HEAD_SHA"
  exit 1
fi
if [[ -n "$PR_HEAD_SHA" && "$TESTED_HEAD_SHA" != "$PR_HEAD_SHA" ]]; then
  echo "PROVENANCE_FAILED reason=pr-head-mismatch expected=$PR_HEAD_SHA actual=$TESTED_HEAD_SHA"
  exit 1
fi

echo "WASM runtime evidence"
echo "tested_head_sha=$TESTED_HEAD_SHA"
echo "workflow_event=$WORKFLOW_EVENT"
echo "workflow_ref=$WORKFLOW_REF"
echo "workflow_sha=$WORKFLOW_SHA"
echo "pr_head_sha=${PR_HEAD_SHA:-none}"
echo "expected_tested_sha=${EXPECTED_TESTED_SHA:-none}"
echo "branch=$(git branch --show-current)"
echo "rust=$(rustc --version)"
echo "wasm_pack=$(wasm-pack --version)"
echo "node=$(node --version)"
echo "npm=$(npm --version)"
echo "platform=$(uname -a)"

PROVENANCE_FILE="$OUTPUT_DIR/provenance.env"
{
  printf 'tested_head_sha=%s\n' "$TESTED_HEAD_SHA"
  printf 'workflow_event=%s\n' "$WORKFLOW_EVENT"
  printf 'workflow_ref=%s\n' "$WORKFLOW_REF"
  printf 'workflow_sha=%s\n' "$WORKFLOW_SHA"
  printf 'pr_head_sha=%s\n' "${PR_HEAD_SHA:-none}"
  printf 'expected_tested_sha=%s\n' "${EXPECTED_TESTED_SHA:-none}"
  printf 'branch=%s\n' "$(git branch --show-current)"
} > "$PROVENANCE_FILE"

export CFLAGS="-Dmemmove=__builtin_memmove -Dmemcpy=__builtin_memcpy -Dmemset=__builtin_memset -Dmemcmp=__builtin_memcmp"

build_target() {
  local target="$1"
  echo "BUILD target=$target output=$OUTPUT_DIR/$target"
  wasm-pack build --release --target "$target" --out-dir "$OUTPUT_DIR/$target" -- --locked
}

build_target nodejs
build_target bundler
build_target web

echo "ARTIFACTS"
for target in nodejs bundler web; do
  echo "target=$target"
  find "$OUTPUT_DIR/$target" -maxdepth 1 -type f -printf '%f %s bytes\n' | sort
  sha256sum "$OUTPUT_DIR/$target"/*.js "$OUTPUT_DIR/$target"/*.wasm "$OUTPUT_DIR/$target/package.json" \
    | tee -a "$OUTPUT_DIR/artifact-sha256sums.txt"
done
echo "artifact_hashes=$OUTPUT_DIR/artifact-sha256sums.txt"

node scripts/wasm_runtime_harness.mjs node "$OUTPUT_DIR/nodejs"
node scripts/wasm_runtime_harness.mjs worker "$OUTPUT_DIR/nodejs"
node --experimental-wasm-modules scripts/wasm_runtime_harness.mjs bundler "$OUTPUT_DIR/bundler"

cp scripts/wasm_runtime/browser.html \
  scripts/wasm_runtime/boundary_assertions.mjs \
  scripts/wasm_runtime/worker.mjs \
  "$OUTPUT_DIR/web/"

PLAYWRIGHT_DIR="${RUNNER_TEMP:-/tmp}/conxius-wasm-playwright-driver"
rm -rf "$PLAYWRIGHT_DIR"
npm install --prefix "$PLAYWRIGHT_DIR" --no-save --no-package-lock --ignore-scripts playwright@1.61.1
PLAYWRIGHT_VERSION="$(node -p 'require(process.argv[1]).version' "$PLAYWRIGHT_DIR/node_modules/playwright/package.json")"
PLAYWRIGHT_EXECUTABLE="$(NODE_PATH="$PLAYWRIGHT_DIR/node_modules" node -e 'const { chromium } = require("playwright"); process.stdout.write(chromium.executablePath());')"

if [[ -z "$PLAYWRIGHT_EXECUTABLE" || ! -x "$PLAYWRIGHT_EXECUTABLE" ]]; then
  echo "BROWSER_RUNTIME_BLOCKED reason=playwright-managed-chromium-not-found"
  printf 'browser_status=blocked\nplaywright_version=%s\nplaywright_executable=%s\n' \
    "$PLAYWRIGHT_VERSION" "${PLAYWRIGHT_EXECUTABLE:-none}" >> "$PROVENANCE_FILE"
  if [[ "${WASM_RUNTIME_REQUIRE_BROWSER:-0}" == "1" ]]; then
    exit 1
  fi
  echo "WASM_RUNTIME_EVIDENCE_PARTIAL browser=blocked"
  exit 0
fi

BROWSER_BIN="$(realpath "$PLAYWRIGHT_EXECUTABLE")"
BROWSER_VERSION="$("$BROWSER_BIN" --version)"
BROWSER_SHA256="$(sha256sum "$BROWSER_BIN" | awk '{print $1}')"
echo "playwright=$PLAYWRIGHT_VERSION"
echo "playwright_executable=$BROWSER_BIN"
echo "browser=$BROWSER_BIN"
echo "browser_version=$BROWSER_VERSION"
echo "browser_sha256=$BROWSER_SHA256"
{
  printf 'browser_status=ready\n'
  printf 'playwright_version=%s\n' "$PLAYWRIGHT_VERSION"
  printf 'playwright_executable=%s\n' "$BROWSER_BIN"
  printf 'browser_version=%s\n' "$BROWSER_VERSION"
  printf 'browser_sha256=%s\n' "$BROWSER_SHA256"
} >> "$PROVENANCE_FILE"

SERVER_LOG="$OUTPUT_DIR/http-server.log"
python3 -u -m http.server 0 --bind 127.0.0.1 --directory "$OUTPUT_DIR/web" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
cleanup() {
  kill "$SERVER_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

PORT=""
for _ in $(seq 1 50); do
  if grep -q "Serving HTTP" "$SERVER_LOG"; then
    PORT="$(sed -n 's/.* port \([0-9][0-9]*\).*/\1/p' "$SERVER_LOG" | head -n 1)"
    [[ -n "$PORT" ]] && break
  fi
  sleep 0.1
done

if [[ -z "$PORT" ]]; then
  echo "BROWSER_RUNTIME_FAILED reason=http-server-did-not-start"
  cat "$SERVER_LOG"
  exit 1
fi

NODE_PATH="$PLAYWRIGHT_DIR/node_modules" \
  node scripts/wasm_runtime_browser.cjs "http://127.0.0.1:${PORT}/browser.html" "$BROWSER_BIN" \
  | tee "$OUTPUT_DIR/browser-result.txt"

echo "WASM_RUNTIME_EVIDENCE_COMPLETE output=$OUTPUT_DIR"
