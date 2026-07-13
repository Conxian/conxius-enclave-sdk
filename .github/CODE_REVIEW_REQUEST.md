## Summary of Changes
- Hardened GitHub Action workflows by correcting misleading version comments and switching to safer installation patterns.
- Fixed WASM compilation errors in `src/wasm_bindings.rs` and `src/lib.rs`.
- Aligned `src/wasm_bindings.rs` with `src/protocol/asset.rs` by adding missing `Chain::COSMOS` support.
- Standardized `actions/checkout` version comments to match the actual SHA (`v4.2.2`).

## Remediated Checks
- **WASM Build**: Fixed trait bound errors and visibility issues that prevented the SDK from compiling for WASM targets.
- **CodeQL**: Fixed incorrect action calls in `codeql.yml`.
- **Security/Hygiene**: Replaced insecure `curl | sh` installation of `wasm-pack` with `taiki-e/install-action`.

## Verification Results
- `cargo test`: 54/54 passed.
- `cargo check --target wasm32-unknown-unknown`: Passed with required CFLAGS for `secp256k1-sys`.
- `cargo fmt`: All files formatted correctly.
