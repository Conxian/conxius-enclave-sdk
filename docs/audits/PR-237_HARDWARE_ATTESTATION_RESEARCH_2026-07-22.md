# PR #237 Hardware Attestation Research and Evidence Audit

**Access date:** 2026-07-22
**Scope:** proof-policy hardening, provider capability research, and public
evidence boundaries for `conxius-enclave-sdk`
**Support decision:** beta / conditional; no provider or production-support
claim is made

This audit separates repository implementation evidence from external research.
Official standards and vendor specifications explain what a verifier would need
to establish; they are not evidence that this repository implements, integrates,
tests, reviews, releases, or supports those providers.

## Requirement → code → test → CI → artifact chain

| Requirement | Code evidence | Test evidence | CI evidence | Artifact / support decision |
| --- | --- | --- | --- | --- |
| Commit the complete exact proof policy, not only `policy_id` | `src/enclave/proof.rs`: versioned `CONXIAN-PROOF-POLICY/v1`, policy-mode tag, operation/purpose/challenge/replay/freshness fields, canonical requirement digests, private `VerifiedProofSet` policy digest | `policy_digest_binds_exact_fields_and_requirement_order_is_canonical`; duplicate, type-substitution, stale, future, malformed, and fixture-exclusion tests | Required local gates: `cargo fmt --all -- --check`; locked all-target/all-feature clippy; unit/all-feature/doc tests | No release artifact or independent review is established by this change; `proof-composition` remains beta/conditional and production-unsupported |
| Carry the expected digest from request-side policy through authorization | `src/enclave/mod.rs`: request-side derivation and response storage; `src/protocol/rails/mod.rs`: independent expected/verified digest fields | `typed_settlement_authorization_rejects_same_id_weaker_policy_digest`; complete fixture authorization remains covered | Same required Rust gates | The branch contains containment code only; no provider/runtime artifact is claimed |
| Recheck policy integrity at final dispatch | `src/protocol/rails/mod.rs`: final dispatch rejects zero or unequal expected/verified digests before rail lookup/execution | `typed_settlement_dispatch_rechecks_expected_and_verified_policy_digest`; existing replay and downstream-failure tests remain | Same required Rust gates | No live rail, distributed replay, or release-support evidence |
| Refactor test fixtures without weakening coverage | `RawProofEvidence::test_fixture(TestProofEvidenceInput)` and private builder input under `cfg(test)` | Existing proof negative tests plus clippy `too_many_arguments` regression | `cargo clippy --locked --all-targets --all-features -- -D warnings` | Test fixtures cannot satisfy production policy |
| Record provider capability boundaries | `docs/architecture/capability-evidence.json` rows and generated matrix | Validator checks schema, IDs, refs, blockers, and generated drift | `python3 scripts/validate_capability_evidence.py --check` | Research-only rows are explicitly unsupported; no row is promoted from documentation |

The `artifact` stage is intentionally not satisfied. A commit, local test
result, generated document, or workflow definition is not a production release
artifact with provenance, SBOM, independent review, runtime evidence, and a
scoped support decision.

## Conservative provider capability matrix

| Capability / specification | What the primary source describes | Repository status after PR #237 |
| --- | --- | --- |
| TLS 1.3 server identity | Certificate authentication and server identity behavior; RFC 9266 identity guidance | Research boundary only; not TEE proof or provider attestation |
| WebAuthn authorization | RP/origin-bound authenticator ceremony and user authorization semantics | Research boundary only; no WebAuthn provider verifier |
| FIDO authenticator provenance | Attestation metadata and provenance information | Research boundary only; no MDS/attestation-chain verifier |
| TPM 2.0 quote | AK-backed quote, qualifying data, PCR selection/digest, and event-log/replay inputs | Research boundary only; no TPM quote verifier or EK/AK trust store |
| Android TEE Key Attestation | Key-attestation challenge, app identity, verified boot, OS/patch, chain/status inputs | Research boundary only; no Android chain/status verifier |
| Android StrongBox | Hardware-backed key isolation and attestation distinctions | Research boundary only; no StrongBox provider integration |
| Apple App Attest | Server validation of app-integrity assertions | Research boundary only; no App Attest provider verifier |
| Apple Secure Enclave key operation | Device-local key isolation and constrained key operations | Research boundary only; no generic remote Secure Enclave attestation claim |
| Intel SGX DCAP | ECDSA quote, QE/PCK, TCB, collateral, certificates, and revocation inputs | Research boundary only; no DCAP verifier or Intel collateral service |
| Intel TDX | Trust-domain measurements, report data, quote/collateral, and TCB policy inputs | Research boundary only; no TDX verifier/runtime |
| AMD SEV-SNP | `REPORT_DATA`, VCEK/VLEK, policy, TCB, debug, and migration semantics | Research boundary only; no SEV-SNP verifier/runtime |
| AWS Nitro | NSM attestation document, COSE, PCRs, nonce/user data/public key, AWS root/debug boundary | Offline structural boundary only: native bounded parser, P-384 COSE signature check, exact local policy, release binding, and recipient-contract tests; no AWS PKI/root or runtime integration |
| ARM PSA | PSA attestation token, challenge, lifecycle, implementation, and platform claims | Research boundary only; no PSA token verifier |
| ARM CCA Realm/Platform | EAT/COSE evidence and distinct realm/platform/lifecycle semantics | Research boundary only; no CCA verifier/runtime |
| Collateral/revocation verification | Provider-specific certificates, CRLs/status, TCB collateral, metadata, and freshness | Unsupported; no common collateral/revocation service is implemented |

The corresponding machine-readable rows remain production-unsupported. The AWS
Nitro row records `api: yes` and `implementation: partial` only for the
native-only offline structural boundary; it keeps `integration: no`,
`independentReview: not-evidenced`, and `productionSupport: unsupported`. This
does not promote the parser or its test fixtures to a provider verifier. The
existing `proof-composition` row remains unchanged at beta/conditional maturity
with production support unsupported.

## Primary sources

All links below were accessed on 2026-07-22.

- TLS 1.3: [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) and
  [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html).
- WebAuthn Level 3: <https://www.w3.org/TR/webauthn-3/>.
- FIDO metadata and attestation provenance:
  [FIDO MDS 3.1.1 RD02](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-rd02-20260105.pdf)
  and [The Truth About Attestation](https://fidoalliance.org/fido-technotes-the-truth-about-attestation/).
- TPM 2.0: [TCG TPM Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
  and [Part 2: Structures, Version 1.85](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-2-Structures_Version-185_pub.pdf).
- Android: [Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
  and [Android attestation status](https://android.googleapis.com/attestation/status).
- Apple: [App Attest server validation](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server),
  [app integrity](https://developer.apple.com/documentation/DeviceCheck/establishing-your-apps-integrity),
  and [Secure Enclave key protection](https://developer.apple.com/documentation/Security/protecting-keys-with-the-secure-enclave).
- Intel: [SGX DCAP ECDSA orientation, 1.23](https://download.01.org/intel-sgx/sgx-dcap/1.23/linux/docs/DCAP_ECDSA_Orientation.pdf)
  and [TDX documentation](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html).
- AMD: [SEV-SNP guest-hypervisor interface specification](https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf).
- AWS Nitro: [verify the Nitro root](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)
  and [obtain an attestation document](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestation-get-doc.html).
- Arm: [PSA Attestation API 1.0.2](https://developer.arm.com/-/media/Files/pdf/PlatformSecurityArchitecture/Implement/IHI0085-PSA_Attestation_API-1.0.2.pdf)
  and [RFC 9783](https://www.rfc-editor.org/rfc/rfc9783.html).

## Unsupported gaps and follow-up gates

The repository still needs, per provider and exact deployment scope:

1. authenticated provider response and key-binding contracts;
2. vendor roots, certificate/quote chains, collateral, TCB policy, and
   revocation/status freshness. For Nitro, this is the unresolved injected
   trust boundary tracked by #240 and the provider qualification work tracked
   by #242;
3. NSM/vsock/KMS/CloudTrail runtime integration, EIF/PCR provenance, and
   provider-backed negative integration tests;
4. distributed replay coordination across replicas, restarts, and provider
   boundaries;
5. independent security/cryptographic review of the exact code and artifact;
6. reproducible release artifact, digest, SBOM, provenance, retained CI result,
   and scoped support decision.

Until those gates are evidenced, test fixtures remain test-only, provider
verification remains unavailable, value-bearing paths fail closed, and this
research record must not be used as a production-support claim.
