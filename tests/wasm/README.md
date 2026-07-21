# WASM runtime evidence harness

This harness executes the generated bindings, rather than only compiling the
Rust crate. It covers four negative/runtime-containment lanes:

- Node.js imports the `wasm-pack --target nodejs` package.
- Browser loads the `wasm-pack --target web` package in Chromium.
- Worker loads that generated package in a real module `Web Worker`.
- Bundler consumes the generated web package through `esbuild` and runs the
  resulting bundle in Chromium.

Each lane checks runtime support decisions, provider-less construction,
signing-shaped failures, malformed covenant inputs, public-only structural
results, lifecycle state, development-constructor absence, and secret-shaped
export absence. These are negative/runtime tests only; passing them does not
establish provider, attestation, hardware, artifact-provenance, or production
support.

From the repository root, install the pinned local tools and run all lanes with:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --version 0.15.0 --locked
npm ci --prefix tests/wasm
tests/wasm/node_modules/.bin/playwright install --with-deps chromium
./scripts/wasm_runtime_evidence.sh
```

The script creates `tests/wasm/.generated/` and uses `tests/wasm/node_modules/`;
both are intentionally untracked. The CI workflow
`.github/workflows/wasm-runtime.yml` runs the same script on pinned Rust,
wasm-pack, Node.js, Chromium, and JavaScript dependencies.
