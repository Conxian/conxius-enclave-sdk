#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATED="$ROOT/tests/wasm/.generated"
CFLAGS_VALUE="-Dmemmove=__builtin_memmove -Dmemcpy=__builtin_memcpy -Dmemset=__builtin_memset -Dmemcmp=__builtin_memcmp"

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
