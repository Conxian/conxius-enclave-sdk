# WASM Key-Boundary Migration

This is an unreleased breaking change for the `2.x` line. Cargo metadata is
not a release claim; the repository's latest visible release/tag remains
`v2.0.11`.

## API changes

- `WasmArkClient::derive_vutxo_key(seedHex, index)` has been removed. It
  returned private key bytes as hex and must not be used for recovery or
  signing.
- `WasmArkClient` now names provider-backed `derive_vutxo_public_key(index)`
  and `sign_vutxo(txHashHex, index)` capabilities. These methods never return
  private key material. They remain conditional until an approved provider is
  wired to the WASM artifact.
- `WasmArkClient::recovery_scan` no longer accepts a JavaScript seed. Seed-based
  recovery through WASM fails closed until an opaque provider capability exists.
- `ConclaveWasmClient::new(url)` no longer constructs `CloudEnclave`; it
  returns `UNSUPPORTED_PROVIDER`. `new_with_provider(runtime, provider)` is a
  compatibility seam for a future approved adapter and currently fails closed.
- `WasmBitVm2Orchestrator::new()` and `ConclaveWasmClient::bitvm2()` are now
  fallible. They return `UNSUPPORTED_PROVIDER` instead of creating a localhost
  mock or panicking.
- Generated bindings now include the same fallible constructor behavior; do
  not assume that a JavaScript `new` expression returning an object means a
  provider is available.
- Malformed JSON, event, and boundary decoding errors return `INVALID_INPUT`.
  Callers should not parse error strings or retry with a software key.
- BitVM2's public input is named `taproot_internal_key_hex` to distinguish a
  public Taproot internal key from private key material.
- WASM Fedimint mint/issue methods return `SECRET_EXPORT_FORBIDDEN` rather than
  serializing secrets or blinding factors.

## Migration guidance

1. Remove all JavaScript calls to `derive_vutxo_key` and any seed handling in
   browser, Node, bundler, or worker code.
2. Do not replace it with a key string, byte array, or reversible derivation
   token. Use a provider-owned opaque handle or provider-backed public-key and
   signing operation once the matching adapter is available.
3. Treat `UNSUPPORTED_RUNTIME`, `UNSUPPORTED_PROVIDER`, and
   `SECRET_EXPORT_FORBIDDEN` as terminal capability errors, not prompts to fall
   back to local software keys.
4. Keep CloudEnclave, localhost, and mock providers confined to clearly marked
   tests. Their output is not production runtime or hardware evidence.

## Runtime evidence

The repository's executable runtime checks are intentionally fail-closed and
do not promote a runtime lane to production support. Run the reproducible
artifact harness from the repository root:

```bash
./scripts/run_wasm_runtime_evidence.sh /tmp/conxius-wasm-runtime-evidence
```

The harness builds the Node.js, bundler, and web packages from the same commit,
executes Node and `worker_threads` checks, imports the bundler ESM package, and
uses a real browser module Web Worker when a Chromium-compatible browser is
available. CI requires the browser lane and uploads the toolchain, runtime,
artifact-digest, and result evidence. Passing these checks still does not prove
provider approval, hardware attestation, release provenance, or production
support.

The existing native Ark derivation function is retained for native/structural
tests only. Changing the derivation scheme or using an external provider for
recovery requires versioned recovery vectors; this patch does not claim that
provider-backed derivation is recovery-compatible with the old Blake2s path.
