#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATED="$ROOT/tests/wasm/.generated"
CFLAGS_VALUE="-Dmemmove=__builtin_memmove -Dmemcpy=__builtin_memcpy -Dmemset=__builtin_memset -Dmemcmp=__builtin_memcmp"
EXPECTED_NODE_VERSION="${WASM_EXPECTED_NODE_VERSION:-22.23.1}"
EXPECTED_NPM_VERSION="${WASM_EXPECTED_NPM_VERSION:-11.18.0}"
EXPECTED_RUST_VERSION="${WASM_EXPECTED_RUST_VERSION:-1.97.1}"
STRICT_TOOLCHAIN="${WASM_STRICT_TOOLCHAIN:-0}"
KEEP_GENERATED="${CONXIAN_KEEP_WASM_GENERATED:-0}"

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

if [[ ! -x "$ROOT/tests/wasm/node_modules/.bin/esbuild" ]]; then
  npm --prefix "$ROOT/tests/wasm" ci
fi

node "$ROOT/tests/wasm/run.mjs"
