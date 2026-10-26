# Phala dstack TEE Abstraction & Integration Architecture (CON-884)

**Verified:** 2026-10-21
**Scope:** `conxius-enclave-sdk`, `conxius-platform`, and `lib-conxian-core`
**Boundary:** Hardware-backed confidential computing proof verification for Intel SGX / TDX and AMD SEV-SNP using Phala's open-source dstack abstraction framework.

---

## 1. Executive Summary & Architectural Motivation

Conxian's security framework relies on fail-closed, hardware-attested execution boundaries. While `conxius-platform` manages private, non-custodial container orchestration, workload execution inside confidential hardware requires advanced enclave attestation frameworks.

By integrating the open-source **dstack** TEE/SGX abstraction model pioneered by Phala Network into `conxius-enclave-sdk`:
- **Conxian retains total control** over its private container deployment, key custody, and fail-closed orchestration via `conxius-platform`.
- **`conxius-enclave-sdk` gains native dstack quote attestation verification**, binding enclave application measurements (`MRENCLAVE`, `MRSIGNER`), runtime container layer states (`RTMR0`..`RTMR3`), and hardware quote signatures to Conxian's value-bearing signing pipeline.

---

## 2. Separation of Concerns & System Boundaries

```
┌────────────────────────────────────────────────────────────────────────┐
│                        conxius-platform                                │
│           (Private Fail-Closed Container Orchestration)                 │
│  - Enclave deployment & vsock/TLS isolation                           │
│  - Non-custodial container lifecycle & key generation                  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Generates dstack Attestation Evidence
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      conxius-enclave-sdk                               │
│           (Hardware-Backed Proof Verification Engine)                 │
│  - PhalaDstackVerifier (ProofKind::Tee)                                │
│  - DstackAttestationDocument & DstackAppPolicy                         │
│  - DstackReleaseBinding (Digest + Nonce + Purpose + Audience)          │
│  - Fail-closed quote verification against Intel SGX/TDX DCAP roots     │
└────────────────────────────────────────────────────────────────────────┘
```

1. **`conxius-platform` (Orchestration Layer):** Responsible for configuring and executing containers inside dstack TEE environments (Intel SGX DCAP / TDX or AMD SEV-SNP), maintaining vsock boundaries, and acquiring hardware attestation quotes.
2. **`conxius-enclave-sdk` (Verification & Signing Boundary):** Responsible for parsing dstack attestation documents, verifying measurement policies (`MRENCLAVE`, `MRSIGNER`, `ISV_SVN`, `RTMR`), validating `report_data` request bindings, and releasing cryptographic authorizations only upon zero-error verification.

---

## 3. dstack Attestation Evidence Structure

The dstack attestation evidence carried in `ProofEnvelope.evidence` is represented by `DstackAttestationDocument`:

| Field | Type | Description |
| --- | --- | --- |
| `app_id` | `String` | Unique application identifier assigned during dstack container initialization. |
| `mrenclave` | `[u8; 32]` | SHA-256 measurement of the enclave image code and initial memory layout. |
| `mrsigner` | `[u8; 32]` | SHA-256 key digest of the authority that signed the enclave application. |
| `isv_prod_id` | `u16` | Independent Software Vendor product identifier. |
| `isv_svn` | `u16` | Independent Software Vendor security version number (SVN). |
| `rtmr0`..`rtmr3` | `Option<[u8; 48]>` | Runtime Measurement Registers tracking OS kernel, initrd, container image, and configuration layers. |
| `report_data` | `Vec<u8>` | 64-byte or 32-byte hash binding challenge nonce, operation digest, and release policy. |
| `quote_bytes` | `Vec<u8>` | Raw Intel SGX DCAP / TDX quote binary containing header, report body, and ECDSA signature chain. |
| `timestamp` | `u64` | UNIX epoch timestamp (seconds) when the attestation report was generated. |

---

## 4. Measurement Policy Enforcement (`DstackAppPolicy`)

To ensure that only authorized, untampered container workloads can produce value-bearing signatures, `PhalaDstackVerifier` evaluates the report against a strict `DstackAppPolicy`:

- **Code Identity (`expected_mrenclave`):** Optional exact match against the target binary hash.
- **Signer Identity (`expected_mrsigner`):** Mandatory match against Conxian's release signing key.
- **Minimum Security Version (`min_isv_svn`):** Fail-closed enforcement ensuring vulnerable builds cannot be attested.
- **Product ID (`expected_isv_prod_id`):** Ensures the attestation corresponds to the designated service class.
- **Container Layer Measurements (`expected_rtmr0`..`expected_rtmr3`):** Validates OS and container runtime layer integrity.

---

## 5. Key Release & Operation Binding (`DstackReleaseBinding`)

Attestation evidence is strictly bound to the requested operation via `DstackReleaseBinding`:

```rust
let release_binding = DstackReleaseBinding::new(
    context.operation_digest,
    context.purpose.clone(),
    context.audience.clone(),
    now_secs + max_age_secs,
    Sha256::digest(&context.nonce).into(),
)?;
```

The SHA-256 digest of this binding is placed into `report_data`, guaranteeing that a quote generated for one operation or challenge nonce cannot be replayed for another transaction.

---

## 6. Verification Status & Security Invariants

1. **Zero TEE Bypass:** No signature or value-bearing authorization is granted without a fully verified `DstackAttestationDocument`.
2. **Replay Protection:** Replay of attestation quotes is prevented by enforcing single-use challenge nonces and time-window bounds (`MAX_ATTESTATION_AGE_SECS = 300`).
3. **Fail-Closed Default:** Any parse failure, measurement mismatch, expired timestamp, or corrupted signature immediately returns `ConclaveError::Attestation`.
