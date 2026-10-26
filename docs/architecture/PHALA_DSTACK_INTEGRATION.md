# Phala dstack integration: research and qualification boundary

Reviewed 2026-10-26 for PR #620. **Unavailable; no production verification or signing support.**

## Implemented boundary

`PhalaDstackVerifier` reserves `conxian.trust.phala.dstack.v1` and always returns
`Unavailable`; direct verification always returns the standard unsupported error.
It is not installed as an available production verifier. Local diagnostic parsing,
policy comparisons, and binding digests cannot create verified receipts or release keys.
The JSON document is a Conxian diagnostic schema, not an upstream wire protocol.
Its measurements, report data, and timestamp are untrusted claims.
Parsing caps JSON at 16 KiB, identifiers at 256 bytes, report data at 64 bytes and
optional RTMR values at 48 bytes; it rejects unknown fields. Header inspection is
only diagnostic. Larger real evidence requires a separately reviewed bounded wire format.

`DSTACK` and `PHALA_DSTACK` are not aliases for Intel SGX. The framework extension
is metadata and does not identify a hardware provider. Existing provider enum tags,
policy-v2 serialization and replay semantics are unchanged. SGX enclave measurements,
TDX runtime measurement registers, AMD SNP reports, and Nitro NSM evidence require
distinct parsing and trust policies. No AMD SNP verifier is supplied here.

## Primary-source research

- [dstack verification](https://github.com/Dstack-TEE/dstack/blob/next/docs/verification.md)
  describes quote verification and application/event-log appraisal as separate work.
- [Phala dcap-qvl](https://github.com/Phala-Network/dcap-qvl) provides an SGX/TDX
  cryptographic verification candidate, not a general SNP or Nitro verifier.
  Its README requires quote bytes, verification collateral and trusted current time.
- [dcap-qvl policy](https://github.com/Phala-Network/dcap-qvl/blob/master/docs/policy.md)
  distinguishes cryptographic verification from acceptance policy; strict policy
  rejects stale collateral and non-UpToDate TCB by default.
- [Phala dstack-cloud](https://github.com/Phala-Network/dstack-cloud) distinguishes
  GCP Intel TDX and AWS Nitro environments. Framework identity cannot select the
  hardware trust root.

The upstream `master` Cargo manifest observed during this review reports version
0.7.0 under MIT. This is research, not an approved version pin. No QVL dependency,
network collateral fetch, new trust root or acceptance exception is added by #620.
The candidate's default report feature includes networking; a production design must
explicitly choose offline verification or an authenticated, bounded collateral service.

## Required implementation sequence

| Gate | Required implementation and evidence | Current state |
| --- | --- | --- |
| Backend selection | Pin reviewed commit/crate and lockfile; verify license, advisories, crypto dependency graph, native/WASM support and MSRV. Never enable TCB override/bypass features. | Open |
| Quote authentication | Validate complete signature and certificate chain, trusted roots, collateral signatures, CRLs, validity and platform-specific TCB policy against trusted time. Bound all inputs. | Open |
| Authenticated claims | Extract measurement, debug state and full report data from the verified quote body. Do not substitute JSON copies. SGX and TDX require explicit distinct identities. | Open |
| Workload appraisal | Replay authenticated dstack event logs; match pinned OS, app compose/image digests and deployment policy; specify RTMR0 through RTMR3 meaning per version. | Open |
| Operation binding | Define exact signed 64-byte report-data layout, canonical purpose/audience, operation digest, nonce and fixed envelope expiry. Validate route, shape and context; use checked time arithmetic. | Candidate digest only |
| Release and replay | Enforce provider-bound policy-v2, durable nonce consumption and restart/rollback resistance; bind the returned signer key and non-exportability evidence. | Open, #240 |
| Qualification | Real hardware positive fixtures with provenance, mutation/signature/chain/TCB/revocation/staleness/debug/measurement/nonce/expiry negatives and independent review. | Open, #202 |

Acceptance requires the full chain above. A dependency import, green unit tests,
synthetic quote, cloud deployment or matching measurement string cannot close it.
Track this work in #620 and existing hardware acceptance issues #240 / #202;
retain fail-closed status until those requirements have independent evidence.
Private orchestration and custody procedures stay outside the public SDK.

## Recommended default platform policy

This is the recommended baseline for a future qualified backend, **not an enabled
backend or a claim of hardware acceptance**. Existing proof context defaults supply
300-second maximum age and 30-second future skew. Additional choices below are
Conxian recommendations where the standards do not mandate an application value.

| Control | Recommended default | Basis |
| --- | --- | --- |
| Authority | Deny unless every required check succeeds; no software or cross-provider fallback. Unknown/missing security-critical claims deny. | Existing Conxian fail-closed and provider-bound policy-v2 rules; NIST SP 800-207 separates authentication and authorization. |
| Platform | Explicit provider family and version, pinned production trust roots and workload allowlist; no automatic trust from cloud account, brand or framework. | Existing provider identity rules; zero trust. |
| TCB and collateral | Only UpToDate; no TCB or expired-collateral grace; enforce certificate/CRL/TCB validity and revocation at trusted time. Refresh before signed expiration. | Candidate QVL strict policy; Intel collateral verification. |
| Advisories and TCB metadata | Deny unreviewed advisory IDs; maintain a reviewed denylist even when TCB is UpToDate. Set a provider-specific minimum TCB evaluation-data number from current verified collateral at qualification; never lower it implicitly. | Conxian recommendation: upstream strict defaults otherwise leave the advisory denylist empty and skip the minimum evaluation-data number. No universal integer is safe across providers. |
| Platform configuration | Keep dynamic-platform, cached-key and SMT flags rejected when True. Accept Undefined only under an explicitly qualified certificate/profile rule; it is not proof of False. Pin supported SGX types per provider; no wildcard type acceptance. | Candidate QVL defaults reject True but permit Undefined and skip SGX type checking; explicit profile restrictions are Conxian recommendations. |
| Debug and migration | Debug disabled. Migration disabled until its additional trust boundary is independently qualified. Reject unknown required attributes. | Intel prohibits trusting debug enclaves with secrets; migration restriction is a Conxian recommendation. |
| Workload | Exact reviewed image/compose/OS measurements and authenticated event-log replay; explicit minimum security versions. No permissive empty measurement policy. | Conxian evidence-led qualification; deployment-specific reviewed allowlist. |
| Freshness | Maximum evidence age 300 seconds; future skew 30 seconds; fixed operation expiry no more than 300 seconds after issuance; no expiry extension on retry. Trusted clock failure denies. | First two values match existing SDK proof-context defaults; 300-second operation lifetime is proposed. Challenge freshness must be authenticated, not inferred from a JSON timestamp. |
| Operation and custody | Bind full report data to operation, purpose, audience, nonce, fixed expiry and signer-key identity; consume nonce durably across restarts. No raw key export. | Existing provider-bound release and durable replay requirements. |
| Changes and acceptance | Versioned policy digest, independent review and evidence before activation; preserve replay history across updates. Exceptions require explicit scoped, expiring reviewed policy and never activate implicitly. | Existing Conxian governance and policy-v2 continuity. |

References: [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final),
[Intel attestation claims and debug guidance](https://portal.trustauthority.intel.com/eat_profile.html),
[Intel DCAP QVL](https://github.com/intel/confidential-computing.tee.dcap.qvl),
and the candidate [QVL policy reference](https://github.com/Phala-Network/dcap-qvl/blob/master/docs/policy.md).
These sources do not prescribe Conxian's exact lifetime, workload allowlist or
migration restriction; those are application policy choices requiring qualification.
