# Production Enablement Audit — 2026-07-20

> **Verdict: Beta / conditional.** The SDK exposes a broad security and settlement API surface, but the repository does not currently provide the evidence required for an unqualified production-support claim.
>
> **Operational decision:** Do not enable value-bearing production signing or settlement from this tree. Simulated, software-backed, structural, or placeholder paths are suitable only for development and interface validation until the acceptance gates below are met.

This report records the public-safe outcome of the production-enablement review tracked by [CON-1506](https://linear.app/conxian-labs/issue/CON-1506/production-enablement) and [GitHub issue #191](https://github.com/Conxian/conxius-enclave-sdk/issues/191). It is intentionally limited to repository evidence and does not include private endpoints, credentials, privileged identifiers, custody procedures, key-recovery details, or incident secrets.

## Audit identity

| Item | Value |
| --- | --- |
| Audited default-branch ref | `1d9ef9b8d1745c51366d34a1624a8d3c76426769` (current `origin/main` fetched 2026-07-21) |
| Reviewed containment checkpoint | `5a936ba97373ebdbd809580c5e9c9f4df1966b40` (reconciled follow-up code commit, including gated WASM simulator coverage) |
| Dependency merge refs | PR #205 `35f7843a1ee8994de98b00cfacbae7dab1a1eaf5`; PR #216 `0bdb323255279893c246f06659ec05875338c296` |
| Audit ref description | Current main after fail-closed containment and signer-identity follow-ups, plus typed settlement evidence propagation |
| Documentation correction base | Latest `origin/main` at follow-up start: `1d9ef9b8d1745c51366d34a1624a8d3c76426769` |
| Audit date | 2026-07-21 follow-up (historical audit filename retained) |
| Maturity language | Beta / conditional |
| Scope | Public repository source, tests, documentation, package metadata, and CI/release definitions |

The follow-up branch is based on the merged `origin/main` ref above. The reviewed containment checkpoint is recorded separately so the capability evidence points to the exact code commit rather than the later documentation commit. Historical audit context remains attributable to its original ref and date.

## Executive verdict

The repository has useful primitives and a meaningful test/documentation foundation, but its current evidence chain stops at API presence and simulated or structural validation for several high-impact capabilities. In particular:

- The reviewed checkpoint now contains a fail-closed typed value-bearing signing boundary, rejects raw production settlement dispatch, isolates software simulators, and makes the default/WASM provider boundary unavailable until an approved provider exists.
- Rail policy now invokes the complete report verification path and carries typed settlement authorization through canonical intent/key, provider response, policy, attestation, and replay bindings; the real provider verifier, distributed replay, and deployment/artifact evidence remain open.
- BIP-322 verification returns success after address and encoding checks without cryptographically verifying the signature.
- Ethereum and Taproot helpers contain non-canonical hashing behavior.
- FROST, Fedimint threshold/DLEQ, BitVM2/Ark, CCTP, and account-abstraction surfaces require explicit protocol boundaries and evidence before support. PR #209 adds typed quarantine for FROST, Fedimint, Ark, and BitVM2; it does not implement or enable those protocols.
- Release, dependency, test-matrix, telemetry/privacy, asset-registry, and operational evidence is incomplete or duplicated.

These are production-enablement blockers, not merely documentation polish. The public status should remain conditional until the matrix and acceptance gates are satisfied with durable artifacts and independent verification.

## Scope and method

The review used a requirement-to-evidence pass over:

1. Public status and readiness documents, including `README.md`, `PRODUCTION_READINESS.md`, `SECURITY.md`, `AGENTS.md`, `TRACKING.md`, and `REPOSITORY_ANALYSIS.md`.
2. Enclave, attestation, rail-policy, protocol-adapter, telemetry, asset, and WASM source paths.
3. In-repository unit and structural tests, with explicit separation between simulated fixtures and vendor/mainnet integration evidence.
4. Package metadata, ignored/generated files, release workflows, provenance/SBOM definitions, and visible GitHub tags/releases.

The review did not exercise deployed hardware, vendor attestation services, mainnet/testnet settlement, external custodians, production gateways, or consumer applications. A passing unit test is therefore recorded as API or structural evidence, not as production support.

## Strengths worth preserving

- The repository has a clear `EnclaveManager` boundary and typed `ConclaveResult` error surface (`src/enclave/mod.rs`).
- Sensitive buffers use `zeroize` in several signing/key paths (`src/enclave/android_strongbox.rs`, `src/enclave/cloud.rs`).
- `DeviceIntegrityReport::verify()` contains explicit nonce, freshness, signature, certificate, and hardware-extension checks (`src/enclave/attestation.rs:50-111`). The remaining issue is that important callers do not consistently invoke it and the certificate fallback accepts simulated root strings.
- A replay guard exists and is exercised by unit tests (`src/enclave/replay_guard.rs`).
- The repository has separate CI, WASM, security, SBOM, provenance, and release definitions. Their presence is useful evidence of intended controls, but workflow definitions alone do not prove successful, durable release artifacts.
- Existing documentation already labels the FROST treasury guide as design/runbook material rather than a production implementation. This audit extends that distinction to the rest of the public surface.

## Capability status

The canonical capability/evidence matrix is [CAPABILITY_MATRIX.md](../architecture/CAPABILITY_MATRIX.md). It distinguishes API presence from implementation completeness, real integration testing, independent review, and production support. A public API or green structural test must not be promoted to a production claim without the remaining evidence columns.

## P0 findings — block production enablement

| ID | Finding | Repository evidence | Required correction |
| --- | --- | --- | --- |
| P0-01 | **Production signing remains unavailable until a real provider is integrated.** | Containment is implemented in the reviewed checkpoint: `ValueBearingSignRequest`/`ValueBearingSignResponse` bind the canonical operation digest, algorithm, key identity, verified signature, attestation, provenance, policy, and replay authorization (`src/enclave/mod.rs:300-760`); `UnavailableEnclave` fails closed; software/cloud simulators are test/development-gated (`src/enclave/mod.rs:1-12`, `src/enclave/android_strongbox.rs`, `src/enclave/cloud.rs`, `Cargo.toml`). Negative tests cover provider absence and simulator exclusion (`src/enclave/mod.rs:1000-1618`, `src/protocol/rails/mod.rs:900-1190`). | **Containment complete; P0 remains open.** Integrate an authenticated hardware/provider verifier and signer, vendor roots/collateral, deployment evidence, independent review, and exact release artifacts. Until then, do not claim value-bearing production signing or close issue #195. |
| P0-02 | **Typed rail settlement containment is implemented, but production evidence is incomplete.** | `RailProxy` performs full attestation-policy verification and rejects legacy request-only hashes (`src/protocol/rails/mod.rs:450-550`). The typed rail boundary requires `ValueBearingPurpose::Settlement`, canonical domain `conxian/settlement/v1`, and the canonical intent digest as operation context before creating a private `VerifiedOperation`; built-in rails receive only typed envelopes carrying canonical intent, operation/key binding, signature, attestation, provenance, policy, and replay authorization. Opportunity preflight is validation-only in non-test builds, while the legacy raw-signature shim remains rejected (`src/protocol/rails/mod.rs:63-260,450-760`, `src/protocol/opportunity.rs:90-150`). Ark, BitVM/Taproot, Business, Chain Abstraction, Economy/Stacks, and Opportunity routes use the typed signing boundary (`src/protocol/{ark,bitvm,business,chain_abstraction,economy,opportunity,stacks}.rs`). | **Containment complete; P0 remains open.** Add the real provider verifier/signer contract and vendor evidence, replace process-local replay with distributed deployment-safe authorization, attach provider/runtime/integration evidence, and retain independent-review/artifact evidence. |
| P0-03 | **BIP-322 verification is acceptance-only, not signature verification.** | `Bip322Bridge::verify_simple_signature` parses the address, constructs a transaction, decodes base64, then returns `Ok(true)` when the address script is non-empty; the decoded bytes are never verified (`src/protocol/bip322.rs:81-138`). Tests use placeholder base64 strings and assert only `is_ok()` (`src/protocol/bip322.rs:141-176`). | Implement BIP-322 simple verification for each supported script type with official vectors, reject invalid signatures, and add mutation/negative tests. Do not expose the current function as proof of address ownership. |
| P0-04 | **Non-canonical Ethereum and Taproot hashing.** | `EthereumManager::get_address` and `sign_message` use SHA-256 where the documented Ethereum operations require Keccak-family hashing (`src/protocol/ethereum.rs:24-32,73-94`). `TaprootManager` uses a locally defined `TapTweakTag` with a hard-coded non-standard midstate (`src/protocol/bitcoin.rs:47-74,105-115`). | Use audited library implementations and canonical test vectors for Ethereum address/message hashing and BIP-340/BIP-341 Taproot tweaks. Add cross-checks against independent implementations before enabling value-bearing signing. |
| P0-05 | **High-impact protocol surfaces require protocol-conformant evidence.** | FROST, Fedimint, Ark, and BitVM2 now expose typed structural boundaries and exact unsupported operations in PR #209; they do not implement cryptography, network calls, proof verification, transaction construction, or settlement. CCTP still returns an empty burn payload and accepts any non-empty attestation (`src/protocol/cctp.rs:27-36`). Account abstraction validates only that a module address is non-empty (`src/protocol/account_abstraction.rs:46-60`). | Keep the four protocol rows explicitly quarantined and follow [`PROTOCOL_IMPLEMENTATION_ROADMAP.md`](../architecture/PROTOCOL_IMPLEMENTATION_ROADMAP.md). Any future implementation requires pinned protocol revisions, official/independent vectors, provider/network evidence, independent review, and exact artifact evidence before promotion. |

## P1 findings — required before stable production support

| ID | Finding | Repository evidence | Required correction |
| --- | --- | --- | --- |
| P1-01 | **Historical at the 2026-07-20 audit checkpoint: release publishers and creators were duplicated.** | At that checkpoint, `.github/workflows/crates-publish.yml` published on tags and created releases; `.github/workflows/release.yml` had manual publishing plus tag-based release creation; `.github/workflows/release-strict.yml` had both `publish-crates-io` and `auto-publish-crates-io` paths. | PR #213 removed the competing workflow files and publisher path. The current follow-up keeps `release-strict.yml` as the sole publisher/release creator and adds registry-equality ordering; hosted tag evidence and independent acceptance remain open. |
| P1-02 | **Historical at the 2026-07-20 audit checkpoint: dependency and toolchain evidence was not reproducible.** | At that checkpoint, `Cargo.lock` was ignored, `Cargo.toml` declared `rust-version = "1.85"` while workflows floated on `stable`, and the local resolver selected packages requiring Rust 1.90–1.94.1. | PR #213 tracks the lockfile and pins the supported MSRV/CI toolchain. Continue to verify lockfile/toolchain consistency in the exact tagged release evidence. |
| P1-03 | **Package metadata and visible release evidence drift.** | `Cargo.toml` declares `2.0.12`, while the visible GitHub release/tag list inspected on 2026-07-20 ended at `v2.0.11`. The repository does not contain durable evidence that `2.0.12` was published and promoted as a supported release. | Reconcile Cargo metadata, tags, changelog, GitHub release, registry publication, SBOM, provenance, and release notes. Treat an untagged package version as metadata, not a supported release. |
| P1-04 | **Historical at the 2026-07-20 audit checkpoint: the secret-scan workflow was an echo-only gate.** | At that checkpoint, `.github/workflows/secret-scan.yml:22-28` printed that native scanning was enabled but did not run a scanner or inspect repository contents. | PR #213 replaced the placeholder with a pinned, checksum-verified full-history Gitleaks scan; the current release workflow reuses that scan on tag paths. Exact tagged results and independent acceptance remain external evidence gates. |
| P1-05 | **WASM, runtime, platform, and hardware evidence is incomplete.** | CI builds `wasm32-unknown-unknown` and runs a bundler build but has no browser/runtime matrix or hardware-provider matrix (`.github/workflows/ci.yml:50-68`, `.github/workflows/ci-strict.yml:53-79`). Hardware tests use a mock generator and simulated trust tiers (`src/enclave/hardware_attestation_tests.rs:1-11,115-125,417-443`). | Add supported-runtime/platform matrices, vendor-backed attestation tests, browser/WASM integration tests, and durable reports for the supported release artifacts. |
| P1-06 | **Telemetry and privacy controls are underspecified.** | `TelemetryClient` sends an API key and signature hash to a configured endpoint, runs detached, and ignores network/backend errors without documented consent, redaction, retention, or retry policy (`src/telemetry.rs:9-59`). | Define opt-in/opt-out behavior, data minimization and retention, hashing/redaction rules, endpoint trust, failure semantics, and privacy/security review. Do not make telemetry a hidden dependency of signing. |
| P1-07 | **Active asset metadata includes unverified or missing addresses.** | Many registry entries mark assets active while leaving `contract_address: None` (`src/protocol/asset.rs:110-117,160-170,177-244`); test and rail fixtures use values such as `0x123`, `0xabc`, `addr`, and `0x...` (`src/protocol/rails/mod.rs`, `src/protocol/rails/ntt.rs`). | Separate display/catalog assets from executable assets, require chain-specific address validation and provenance, and block settlement for missing or placeholder addresses. |
| P1-08 | **Operational evidence and rollback/monitoring runbooks are incomplete.** | The readiness checklist leaves hardware, WASM, fuzzing, dependency, and independent-audit items open, while the release workflows do not attach a complete production-support decision record (`PRODUCTION_READINESS.md`). | Add public-safe deployment, monitoring, incident, rollback, artifact-retention, and release-approval runbooks. Keep sensitive operational procedures outside public documentation. |

## P2 findings — follow-up hardening

| ID | Finding | Repository evidence | Follow-up |
| --- | --- | --- | --- |
| P2-01 | **Executable examples still overstate trust tiers.** | `examples/attestation_verification.rs:8-29` prints CloudTEE and StrongBox as “Production” even though the repository’s implementation evidence is simulation-heavy. | Align examples with the capability matrix in a separate code/example change. This docs-only PR does not change executable code. |
| P2-02 | **Test assertions are often structural rather than behavioral.** | BIP-322 tests assert success for placeholder signatures; several protocol tests assert non-empty output or state transitions without external protocol vectors (`src/protocol/bip322.rs`, `src/protocol/bitvm2.rs`, `src/protocol/nexus/fedimint.rs`). | Add negative, mutation, property, fuzz, and independent-vector tests; report coverage by capability rather than test count alone. |
| P2-03 | **Status and branding drift exists across historical documents.** | Older documents use “Conclave SDK”, `v2.0.12` release language, or broad completion checkmarks (`AGENTS.md`, `TRACKING.md`, `REPOSITORY_ANALYSIS.md`). | Keep the audit and capability matrix canonical, update linked readiness indexes, and treat older history as historical rather than current support evidence. |
| P2-04 | **Public operational documentation needs a review cadence.** | Existing readiness, research, and release documents have different dates and evidence standards. | Assign an owner and review date for the audit, matrix, release evidence, and public security policy; record material changes by commit/tag. |

## Acceptance gates

Production enablement should remain blocked until all P0 gates and the required P1 gates below have durable evidence.

### Gate A — claim and configuration safety

- Public status is Beta / conditional or Stable with explicit conditions; no document says “production-ready” for the repository as a whole.
- No mock, simulated, software-only, or placeholder path is reachable from a production configuration.
- Value-bearing signing and settlement fail closed when hardware, attestation, policy, network, or artifact evidence is missing.

### Gate B — hardware and attestation

- **Containment complete:** value-bearing callers require the typed provider-only signing path; the complete report verifier is reached before typed settlement authorization, with canonical nonce/digest, key, freshness, purpose, algorithm, policy, and process-local replay checks.
- **Open provider gate:** no authenticated real hardware/provider verifier or signer, vendor roots/collateral, or deployed hardware evidence is present in this repository. Software and simulated fixtures remain excluded from production support.
- **Open replay and artifact gates:** the current replay guard is process-local, not distributed deployment coordination; independent review, provider/runtime integration tests, and exact artifacts remain empty.
- Positive and negative fixture tests cover stale, replayed, malformed, wrong-root, wrong-purpose, software, raw-dispatch, and missing-evidence cases, but they are not vendor or production evidence.

### Gate C — protocol correctness

- BIP-322, BIP-340/BIP-341, Ethereum hashing/signing, FROST/RFC 9591, Fedimint threshold/DLEQ, Ark/BitVM2, CCTP, and ERC-7579 behavior is implemented or explicitly excluded.
- Official and independent test vectors pass, invalid inputs fail, and real testnet integration evidence is attached.
- An independent reviewer verifies the cryptographic and settlement-critical paths.

### Gate D — release and supply chain

- A single release workflow owns publication and release creation.
- Toolchain, MSRV, dependency graph, and lockfile are reproducible.
- The supported version has a matching tag, changelog entry, registry state, SBOM, provenance attestation, release notes, and retained CI results.
- Rollback and artifact-retention procedures are tested.

### Gate E — operations and privacy

- Monitoring, alerting, incident response, rollback, and support ownership are documented without exposing secrets.
- Telemetry is explicit, minimized, privacy-reviewed, and non-critical to signing.
- WASM/runtime/platform/hardware support is listed per artifact and verified in CI.
- Active asset addresses and chain metadata are sourced, validated, and blocked when incomplete.

## Implementation sequence

1. **Lock the claim boundary:** keep public status conditional, publish the matrix, and block production wording in agent/review guardrails.
2. **Complete the remaining P0-01/P0-02 evidence:** preserve the implemented containment, then integrate the real provider verifier/signer, distributed replay, vendor evidence, independent review, and exact artifacts before any production-support decision.
3. **Close P0-03/P0-04:** implement canonical BIP-322, BIP-340/BIP-341, and Ethereum vectors with negative tests and independent cross-checks.
4. **Close P0-05:** keep unsupported protocol boundaries fail-closed until each selected implementation passes the corresponding roadmap vectors, provider/network integration, independent review, and exact-artifact gates.
5. **Close P1 supply-chain and release gaps:** pin dependencies/toolchain, consolidate workflows, reconcile the 2.x release, and retain SBOM/provenance evidence.
6. **Close P1 operations gaps:** add test matrices, privacy controls, asset provenance, monitoring, rollback, and public-safe runbooks.
7. **Independent verification:** repeat the audit against a tagged candidate release, attach findings and evidence, then decide whether the 2.x line can move from Beta / conditional to Stable with conditions.

## Explicit unknowns

The repository does not establish:

- Which vendor hardware, firmware, certificate roots, or cloud attestation services are actually deployed.
- Whether any consumer application gates value-bearing operations outside this repository.
- Whether the visible `v2.0.11` release has evidence not committed or linked from the repository.
- Whether `2.0.12` was published to a registry or is only package metadata.
- What production monitoring, alerting, rollback, incident ownership, or artifact-retention controls exist outside the public repository.
- Whether any protocol adapters have been independently reviewed or exercised against live testnets/mainnet.

Unknowns are not positive evidence. They remain release-blocking until resolved with public-safe, durable artifacts or an explicit documented exclusion.

## Verification limits

- This is a source, test, documentation, and workflow audit; it is not a penetration test, cryptographic proof, vendor attestation validation, deployment review, or mainnet certification.
- The mandatory local build verification passed on the merged main checkout before this follow-up. The reconciled checkpoint is verified with Rust `1.97.1` (newer than the required `1.94.1` baseline); resolver/toolchain compatibility is recorded separately from provider and artifact evidence.
- Existing unit tests were not reclassified as integration or independent-review evidence.
- This follow-up does not modify workflows, generated issue/PR indexes, dependencies, or release artifacts; its runtime changes are limited to typed value-bearing containment and fail-closed provider boundaries.

## Research and standards references

These references inform the acceptance gates; they are not evidence that the repository currently satisfies them.

- [NIST SP 800-57 Part 1 Revision 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/projects/ssdf)
- [RFC 9334 — Remote ATtestation procedureS (RATS) Architecture](https://www.rfc-editor.org/rfc/rfc9334.html)
- [RFC 9711 — RATS Evidence](https://www.rfc-editor.org/rfc/rfc9711.html)
- [Android hardware-backed biometric keys](https://developer.android.com/identity/sign-in/biometric-auth#hardware-backed-key)
- [Android key attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
- [Apple Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)
- [AWS Nitro Enclaves attestation](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html)
- [AMD SEV-SNP attestation](https://www.amd.com/content/dam/amd/en/documents/developer/lss-snp-attestation.pdf)
- [RFC 9591 — The FROST Protocol](https://www.rfc-editor.org/rfc/rfc9591.html)
- [BIP-340 — Schnorr signatures](https://bips.dev/340/)
- [BIP-322 — Generic signed message format](https://bips.dev/322/)
- [BIP-110 — Reduced Data Temporary Softfork](https://bips.dev/110/)
- [WebAssembly security](https://webassembly.org/docs/security/)
- [SLSA provenance specification v1.2](https://slsa.dev/spec/v1.2/provenance)

## Structured knowledge digest

### Entities

- **The SDK / `conxius-enclave-sdk`:** public Rust package and repository under review.
- **`EnclaveManager`:** signing and key-management abstraction with software, cloud, and intended hardware-backed implementations.
- **`DeviceIntegrityReport`:** attestation data model and isolated verifier.
- **`RailProxy`:** trust-tier, replay, attestation, telemetry, and settlement handoff policy.
- **Protocol adapters:** Bitcoin/Taproot, BIP-322, Ethereum, FROST, Fedimint, Ark/BitVM2, CCTP, account abstraction, and asset registry.
- **Release controls:** CI, WASM, security, SBOM, provenance, and release workflows plus package metadata.

### Relationships

- `RailProxy` receives an attestation string alongside a signed intent and then calls a rail adapter.
- Rail policy should bind the signed intent to a verified hardware report before any value-bearing broadcast.
- Protocol adapters consume enclave signatures and therefore inherit the security status of the selected signer and policy path.
- Release claims depend on reproducible dependencies, CI results, artifacts, provenance, and independent review—not on a version string alone.

### Decisions

- Use **Beta / conditional** maturity language for the 2.x line.
- Do not enable value-bearing production signing or settlement from the audited tree.
- Treat simulations/placeholders as development-only and label them in public documentation and matrices.
- Keep public documentation ZSE-safe and use `conxius-enclave-sdk` as the stable technical identifier.

### Risks

- A consumer could mistake API presence or a successful structural test for cryptographic or settlement correctness.
- A permissive unlock or attestation bypass could move a software-generated signature into a value-bearing flow.
- Non-canonical hashing and placeholder protocol logic can produce signatures, IDs, or proofs that look valid but are not interoperable or secure.
- Duplicate release automation and unpinned dependencies can publish inconsistent artifacts.
