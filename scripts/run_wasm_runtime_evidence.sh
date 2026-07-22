#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${1:-${RUNNER_TEMP:-/tmp}/conxius-wasm-runtime-evidence}"

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
cd "$ROOT_DIR"

exec > >(tee "$OUTPUT_DIR/evidence.txt") 2>&1

echo "WASM runtime evidence"
echo "commit=$(git rev-parse HEAD)"
echo "branch=$(git branch --show-current)"
echo "rust=$(rustc --version)"
echo "wasm_pack=$(wasm-pack --version)"
echo "node=$(node --version)"
echo "npm=$(npm --version)"
echo "platform=$(uname -a)"

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
  sha256sum "$OUTPUT_DIR/$target"/*.js "$OUTPUT_DIR/$target"/*.wasm "$OUTPUT_DIR/$target/package.json"
done

node scripts/wasm_runtime_harness.mjs node "$OUTPUT_DIR/nodejs"
node scripts/wasm_runtime_harness.mjs worker "$OUTPUT_DIR/nodejs"
node --experimental-wasm-modules scripts/wasm_runtime_harness.mjs bundler "$OUTPUT_DIR/bundler"

cp scripts/wasm_runtime/browser.html \
  scripts/wasm_runtime/boundary_assertions.mjs \
  scripts/wasm_runtime/worker.mjs \
  "$OUTPUT_DIR/web/"

find_browser() {
  if [[ -n "${WASM_BROWSER_BIN:-}" ]]; then
    printf '%s\n' "$WASM_BROWSER_BIN"
    return 0
  fi

  for command_name in chromium chromium-browser google-chrome; do
    if command -v "$command_name" >/dev/null 2>&1; then
      command -v "$command_name"
      return 0
    fi
  done

  if [[ -d "${HOME}/.cache/ms-playwright" ]]; then
    find "${HOME}/.cache/ms-playwright" -type f \
      \( -name chrome -o -name chromium \) -executable -print -quit
  fi
}

BROWSER_BIN="$(find_browser || true)"
if [[ -z "$BROWSER_BIN" ]]; then
  echo "BROWSER_RUNTIME_BLOCKED reason=no Chromium-compatible browser found"
  if [[ "${WASM_RUNTIME_REQUIRE_BROWSER:-0}" == "1" ]]; then
    exit 1
  fi
  echo "WASM_RUNTIME_EVIDENCE_PARTIAL browser=blocked"
  exit 0
fi

echo "browser=$BROWSER_BIN"
"$BROWSER_BIN" --version

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

PLAYWRIGHT_DIR="${RUNNER_TEMP:-/tmp}/conxius-wasm-playwright-driver"
rm -rf "$PLAYWRIGHT_DIR"
npm install --prefix "$PLAYWRIGHT_DIR" --no-save --no-package-lock --ignore-scripts playwright@1.61.1
echo "playwright=$(node -p 'require(process.argv[1]).version' "$PLAYWRIGHT_DIR/node_modules/playwright/package.json")"
NODE_PATH="$PLAYWRIGHT_DIR/node_modules" \
  node scripts/wasm_runtime_browser.cjs "http://127.0.0.1:${PORT}/browser.html" "$BROWSER_BIN" \
  | tee "$OUTPUT_DIR/browser-result.txt"

echo "WASM_RUNTIME_EVIDENCE_COMPLETE output=$OUTPUT_DIR"
