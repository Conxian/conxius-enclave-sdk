# Android StrongBox offline signing boundary

## Current verified state

`AndroidAuthorizationRequest` and `AndroidAuthorizationEvidence` bind the requested hardware tier, opaque key id, public-key digest, application package and signing-certificate digest, nonce, challenge, operation digest, key purpose, algorithm, certificate chain, provider evidence, and bounded lifetime. The structures reject unknown fields, oversized inputs, stale evidence, mismatched requests, and a software/TEE result when StrongBox is required.

This is a structural and semantic boundary. The registered Android verifier remains explicitly unavailable. The repository does not currently validate the Android Key Attestation extension, a Google root chain, revocation state, security patch levels, verified boot state, rollback resistance, or Play Integrity with Google’s server-side service. There is no production JNI/Kotlin adapter that proves key generation and signing occurred in StrongBox.

## Offline-first contract

An Android provider integration must meet all of these conditions before value-bearing enablement:

1. Generate a non-exportable signing key through Android Keystore with StrongBox requested and reject fallback when policy requires StrongBox.
2. Accept a bounded request containing only an opaque key id and 32-byte operation digest. Private-key bytes, seed material, PINs, and recovery secrets must never enter Rust, application storage, logs, analytics, backups, or network requests.
3. Sign locally while network access is unavailable. Network services may provide policy or freshness challenges before signing and may verify evidence after signing; they must never receive or reconstruct the key.
4. Return the signature, public key, and attestation evidence bound to the exact request. A signature without independently verified provider evidence remains unverified.
5. Consume the request through a durable replay store before authorization. Process-local replay state is insufficient for a multi-device or multi-replica managed service.
6. Keep broadcast and chain observation outside this SDK. The caller submits the signed transaction and obtains Bitcoin L1 evidence through its owning component.

## Clean integration surface

Applications should use the existing `EnclaveManager` value-bearing request types for policy and signer binding and the Android authorization types for provider evidence. A provider adapter should expose opaque key creation, public-key retrieval, digest signing, attestation collection, and deletion. It must not expose key export or arbitrary provider claims.

The software manager in `android_strongbox.rs` exists for deterministic development and tests. Its `SignerCapability::software_unverified()` result is intentional and must not be upgraded based on naming, configuration, or caller assertions.

## Production evidence gate

Production support requires official positive and negative vectors, physical-device tests for supported OS/device combinations, root and revocation policy, rollback/patch-level policy, offline signing tests, key non-export evidence, durable replay integration, exact artifact provenance, and independent review. Until those artifacts exist, Android value-bearing signing remains unavailable.

