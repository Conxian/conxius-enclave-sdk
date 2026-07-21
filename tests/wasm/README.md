# WASM runtime evidence harness

This harness executes the generated bindings, rather than only compiling the
Rust crate. It covers four negative/runtime-containment lanes:

- Node.js imports the `wasm-pack --target nodejs` package.
- Browser loads the `wasm-pack --target web` package in Chromium.
- Worker loads that generated package in a real module `Web Worker`.
- Bundler consumes the generated web package through `esbuild` and runs the
  resulting bundle in Chromium.

Each lane runs the same shared checks. They cover runtime support decisions,
provider-less construction, direct zero-state Ark and legacy BitVM client
construction, valid-shaped Ark derive/sign/recovery requests that return
`PROTOCOL_UNSUPPORTED`, malformed Ark signing digests that return
`INVALID_INPUT`, and malformed legacy BitVM signing/aggregation requests that
fail before decode with `PROTOCOL_UNSUPPORTED` and no signature or aggregate
result. They also cover malformed covenant inputs, public-only structural
results, a valid DLC `Offered -> Accepted` transition with a remote public
key, a rejected repeated transition without state mutation,
development-constructor absence, and secret-shaped export/result absence.
These are negative/runtime and structural lifecycle tests only; passing them
does not establish provider, attestation, hardware, artifact-provenance, or
production support.

From the repository root, install the pinned local tools and run all lanes with:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --version 0.15.0 --locked
npm ci --prefix tests/wasm
tests/wasm/node_modules/.bin/playwright install --with-deps chromium
./scripts/wasm_runtime_evidence.sh
```

The script creates `tests/wasm/.generated/` and uses `tests/wasm/node_modules/`;
both are intentionally untracked. A shell trap removes `.generated/` on both
success and failure. Set `CONXIAN_KEEP_WASM_GENERATED=1` only when retaining
the generated package is useful for debugging.

CI uses `ubuntu-24.04`, Node.js `22.23.1`, npm `11.18.0`, Rust/Cargo
`1.97.1`, wasm-pack `0.15.0`, Chromium from the pinned Playwright lockfile,
and the locked JavaScript dependencies. The script validates these versions
in CI; local runs report mismatches without making a different developer
toolchain needlessly unusable. Override the expected versions only for a
deliberate local investigation with `WASM_EXPECTED_NODE_VERSION`,
`WASM_EXPECTED_NPM_VERSION`, and `WASM_EXPECTED_RUST_VERSION`.
