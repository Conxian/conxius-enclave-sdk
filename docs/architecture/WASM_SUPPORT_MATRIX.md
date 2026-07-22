# WASM Runtime and Provider Support Matrix

> **Status:** Beta / conditional. This document records support boundaries; it
> does not promote any WASM lane to production support.

Compilation and generated bindings are not runtime, provider, hardware,
secret-boundary, or release-artifact evidence. A runtime can move out of
`Unsupported` only when the exact artifact, provider, runtime test, CI result,
and retained evidence are attached to the same release scope.

| Runtime / packaging lane | Runtime test execution | Support decision | Unsupported until evidence exists |
| --- | --- | --- | --- |
| Browser / Web | The tracked harness loads the generated web package in a real browser | Unsupported | Provider-backed value-bearing signing, seed-based recovery, and default client construction |
| Node.js | The tracked harness imports and executes the generated Node package | Unsupported | Provider-backed value-bearing signing, seed-based recovery, and default client construction |
| Bundler | The tracked harness bundles the generated package and executes the bundle in a browser | Unsupported | Provider-backed value-bearing signing, seed-based recovery, and default client construction |
| Web Worker | The tracked harness imports the generated package in a real browser Worker | Unsupported | Provider-backed value-bearing signing, seed-based recovery, and default client construction |

The runtime-test column records execution evidence for the exact checkout and
generated package built by CI. A passing negative/runtime harness does **not**
change the support decision column.

Each lane remains conditional/unsupported until the same release scope has an
approved provider, hardware/attestation evidence, resolved dependency and
lockfile evidence, exact artifact/provenance, and a retained CI result.

## Exact generated-runtime assertions

The shared checks run in Node.js, a real browser page, a real module Worker,
and the browser-executed esbuild bundle. In every lane they:

- instantiate direct `WasmArkClient` and `WasmBitVmClient` objects that retain
  no provider, enclave, URL, key, secret, or mock hardware;
- call valid-shaped Ark public-key derivation, signing, and async recovery
  requests and require `PROTOCOL_UNSUPPORTED`;
- pass a malformed Ark signing digest and require `INVALID_INPUT`;
- pass malformed legacy BitVM signing and aggregation values and require the
  typed `PROTOCOL_UNSUPPORTED` response before decode, with no signature or
  aggregate result;
- run a valid DLC `Offered -> Accepted` transition, verify the remote public
  key and state, then reject a repeated acceptance without mutating the
  accepted contract; and
- verify that no signing-shaped success, secret-shaped result, private-key
  export, or development constructor is exposed.

These assertions are negative containment/runtime evidence and a pure
in-memory lifecycle check. They do not enable Ark, BitVM, DLC signing,
provider/network access, hardware-backed operations, attestation, artifact
provenance, or production support.

## Provider boundary

- `ConclaveWasmClient::new` no longer creates `CloudEnclave` or a localhost
  software-backed key. It returns `UNSUPPORTED_PROVIDER`.
- `WasmBitVm2Orchestrator::new` is fallible and returns
  `UNSUPPORTED_PROVIDER`; it never uses a localhost or simulated enclave.
- `WasmArkClient` has a direct zero-state constructor and exposes only
  quarantined public-key/signing/recovery capability names. Valid-shaped calls
  return `PROTOCOL_UNSUPPORTED`; malformed signing digests return
  `INVALID_INPUT`. The removed `derive_vutxo_key` API did not provide a safe
  boundary and must not be reintroduced.
- Seed-based Ark recovery is not available through WASM. Native Rust recovery
  remains a separate, conditional API and is not evidence of browser support.
- Legacy `WasmBitVmClient::sign_challenge` and
  `aggregate_challenge_signatures` return `PROTOCOL_UNSUPPORTED` before
  decoding inputs or producing a signature/aggregate. Generic MuSig2 values
  from the legacy native module are not BitVM2 challenge evidence.
- Fedimint methods that accept already-opaque handles currently return
  `PROTOCOL_UNSUPPORTED`; they do not expose or accept raw secret material.
  Any future API that explicitly exposes or accepts raw secret/blinding-factor
  material must fail with `SECRET_EXPORT_FORBIDDEN` until a provider-owned
  opaque flow exists; no such default WASM API exists.
- Malformed hex, length, JSON, and shape inputs at the signing/covenant
  boundary return the stable `INVALID_INPUT` code before native processing.
- Cloud, localhost, software-only, and mock implementations are test/development
  paths. They cannot satisfy production hardware or runtime evidence.
- `new_for_development` constructors remain behind the
  `development-simulators` feature and are absent from the default generated
  artifacts. Simulator execution therefore cannot satisfy the production
  attestation policy.

## Required evidence before support promotion

The dedicated `wasm-runtime` workflow checks out the exact tested commit,
pins Rust, Node.js, npm, wasm-pack, and Chromium, builds fresh Node.js and Web
artifacts, derives the browser bundler bundle from the generated Web package,
and uploads the runtime provenance manifest. The manifest binds the tested
head to the pull-request/merge-ref context and records toolchain, runtime, and
browser identity; retained artifact/provenance digests and the CI result must
remain attached to the same release scope.

For each runtime lane, retain all of the following for the exact artifact and
provider configuration:

1. Browser, Node, bundler, and worker runtime tests covering initialization,
   signing-shaped negative requests, lifecycle, malformed input, and failure
   paths. The tracked harness in `tests/wasm/` supplies execution evidence but
   does not promote a runtime to supported.
2. An approved provider adapter that returns only public results, signatures,
   or opaque handles; private keys and seeds must not be serialized into JS.
3. Hardware/attestation evidence for value-bearing operations.
4. CI results, resolved dependency/lockfile evidence, and the generated
   artifact/provenance for the same commit.

Hardware mocks, software simulators, and negative runtime tests cannot satisfy
the production attestation or hardware policy. They are containment and test
evidence only.

Until then, the matrix remains explicitly unsupported and the repository's
beta/conditional posture is unchanged. See [issue #200](https://github.com/Conxian/conxius-enclave-sdk/issues/200).

> **Evidence-path note:** The repository currently has separate WASM workflow
> and Playwright/runtime evidence paths. They are intentionally noted here but
> not consolidated in Issue #240 Phase A. Any future consolidation must retain
> exact commit/artifact/runtime provenance and be handled in the dedicated
> WASM/release lanes (#200 and #199); duplicate paths are not evidence of
> additional support.
