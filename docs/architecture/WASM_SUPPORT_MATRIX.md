# WASM Runtime and Provider Support Matrix

> **Status:** Beta / conditional. This document records support boundaries; it
> does not promote any WASM lane to production support.

Compilation and generated bindings are not runtime, provider, hardware,
secret-boundary, or release-artifact evidence. A runtime can move out of
`Unsupported` only when the exact artifact, provider, runtime test, CI result,
and retained evidence are attached to the same release scope.

| Runtime / packaging lane | Current status | What is verified | Explicitly unsupported |
| --- | --- | --- | --- |
| Browser / Web | Unsupported | Rust/WASM compilation only | Value-bearing signing, seed-based recovery, and default client construction |
| Node.js | Unsupported | Rust/WASM compilation only | Value-bearing signing, seed-based recovery, and default client construction |
| Bundler | Unsupported | Rust/WASM compilation only | Value-bearing signing, seed-based recovery, and default client construction |
| Web Worker | Unsupported | Rust/WASM compilation only | Value-bearing signing, seed-based recovery, and default client construction |

## Provider boundary

- `ConclaveWasmClient::new` no longer creates `CloudEnclave` or a localhost
  software-backed key. It returns `UNSUPPORTED_PROVIDER`.
- `WasmBitVm2Orchestrator::new` is fallible and returns
  `UNSUPPORTED_PROVIDER`; it never uses a localhost or simulated enclave.
- `WasmArkClient` exposes public-key and signing capability names only. The
  removed `derive_vutxo_key` API did not provide a safe boundary and must not be
  reintroduced.
- Seed-based Ark recovery is not available through WASM. Native Rust recovery
  remains a separate, conditional API and is not evidence of browser support.
- Legacy `WasmBitVmClient::sign_challenge` and
  `aggregate_challenge_signatures` return `PROTOCOL_UNSUPPORTED` before
  decoding inputs or producing a signature/aggregate. Generic MuSig2 values
  from the legacy native module are not BitVM2 challenge evidence.
- Fedimint secret/blinding-factor flows fail with `SECRET_EXPORT_FORBIDDEN`
  until a provider-owned opaque flow exists.
- Cloud, localhost, software-only, and mock implementations are test/development
  paths. They cannot satisfy production hardware or runtime evidence.

## Required evidence before support promotion

For each runtime lane, retain all of the following for the exact artifact and
provider configuration:

1. Browser, Node, bundler, and worker runtime tests covering initialization,
   public-key/signing requests, lifecycle, and failure paths.
2. An approved provider adapter that returns only public results, signatures,
   or opaque handles; private keys and seeds must not be serialized into JS.
3. Hardware/attestation evidence for value-bearing operations.
4. CI results and the generated artifact/provenance for the same commit.

Until then, the matrix remains explicitly unsupported and the repository's
beta/conditional posture is unchanged. See [issue #200](https://github.com/Conxian/conxius-enclave-sdk/issues/200).
