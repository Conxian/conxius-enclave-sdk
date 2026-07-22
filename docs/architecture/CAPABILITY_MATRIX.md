# Capability and Evidence Matrix

> **Canonical status:** Beta / conditional as of 2026-07-20.
>
> [`capability-evidence.json`](./capability-evidence.json) is the canonical machine-readable source. This Markdown table is generated from it and must not be edited inside the generated markers.

## Evidence model

Every capability is evaluated independently across five axes:

| Axis | Meaning |
| --- | --- |
| **API** | A public type, function, trait, or WASM binding exists. |
| **Implementation** | The declared semantics are implemented without simulated, structural-only, placeholder, mock, or development-only behavior being presented as the real path. |
| **Integration** | Evidence exists against real protocol vectors, vendor/platform boundaries, or a live testnet integration appropriate to the capability. Unit tests alone are insufficient. |
| **Independent review** | An external security, cryptographic, protocol, or release review is attached to the exact implementation and artifact under consideration. |
| **Production support** | The exact artifact, target, runtime, hardware, operational controls, rollback path, and support decision are evidenced. |

The controlled evidence vocabulary is `yes`, `partial`, `no`, and `not-evidenced`. Production support uses `unsupported`, `conditional`, and `production-supported`. `production-supported` is fail-closed: all prerequisite axes and every stage of the requirement → code → test → CI → artifact chain must be evidenced for the same scope. The current inventory intentionally contains no production-supported record.

Build or compilation evidence, including WASM compilation, is not runtime, provider, hardware, secret-boundary, integration, independent-review, or production-artifact evidence.

## Phase A proof-factor boundary

The SDK now exposes separate taxonomy and composition types for six exact proof mechanisms: server identity, user authorization, phone/device attestation, TEE attestation, FIDO2/WebAuthn assertion, and TPM quote. Each raw evidence item is independently verified through an exact-type registry and can enter a value-bearing authorization only through an explicit all-required proof-set policy bound to the operation, purpose, policy, issuer/trust identity, subject binding, freshness, nonce, and replay identity.

This is **composition support only**, not provider or production support. The production verifier registry is intentionally unavailable; test fixtures are compiled only for tests and cannot satisfy a production policy. `DeviceIntegrityReport` remains the current device/TEE adapter and is not silently converted into server, user, phone, FIDO2, or TPM proofs. No production claim is made for any of the six categories until provider roots/collateral, runtime integration, replay coordination, independent review, and exact release-artifact evidence are available.

The value-bearing settlement containment boundary now requires the canonical
`ProofBoundValueBearingAuthorization` from `src/enclave/proofs.rs`. It checks
the exact six-proof set, policy/envelope/context digests, operation/purpose/
audience/nonce binding, trusted-clock freshness, process-local replay
reservation, signer/key evidence, and manager replay before dispatch. The
legacy `src/enclave/proof.rs` types remain for compatibility only and cannot
authorize that boundary. `OpportunityDispatcher::execute_with_proofs` reaches
the canonical route but stops at the unavailable production verifier before
provider key lookup; this is containment evidence, not production hardware or
rail support.

## Generated capability inventory

Run the dependency-free validator from the repository root:

```bash
# Validate JSON and fail if the generated table drifts.
python3 scripts/validate_capability_evidence.py --check

# Explicitly regenerate only the marked table section, after reviewing JSON changes.
python3 scripts/validate_capability_evidence.py --write
```

The validator also checks the schema version, full reviewed commit, unique IDs, controlled statuses, repository paths with optional line suffixes, required WASM rows, blocker/exclusion coverage, and fail-closed production evidence ordering.

<!-- capability-evidence:generated:start -->
## Generated capability evidence

| ID | Capability | Family | API | Implementation | Integration | Independent review | Production support | Blocker / exclusion |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| account-abstraction | Account abstraction | account-and-policy | Yes | No | No | Not evidenced | No | [#198](https://github.com/Conxian/conxius-enclave-sdk/issues/198), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| zkml | Zero-knowledge machine learning | advanced-compute | Yes | Partial | No | Not evidenced | No | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| a2p | Application-to-protocol (A2P) | application-boundary | Yes | Partial | No | Not evidenced | No | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| amd-sev-snp | AMD SEV-SNP | attestation-research | No | No | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| arm-cca-realm-platform | ARM CCA Realm and Platform attestation | attestation-research | No | No | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| arm-psa | ARM PSA attestation | attestation-research | No | No | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| aws-nitro | AWS Nitro attestation | attestation-research | No | No | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| android-strongbox | Android StrongBox key operation | attestation-research | No | No | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| android-tee-key-attestation | Android TEE key attestation | attestation-research | No | No | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| apple-app-attest | Apple App Attest | attestation-research | No | No | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| apple-secure-enclave | Apple Secure Enclave key operation | attestation-research | No | No | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| collateral-revocation-verification | Attestation collateral and revocation verification | attestation-research | No | No | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#199](https://github.com/Conxian/conxius-enclave-sdk/issues/199), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| intel-sgx-dcap | Intel SGX DCAP | attestation-research | No | No | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| intel-tdx | Intel TDX | attestation-research | No | No | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| tpm-quote | TPM 2.0 quote verification | attestation-research | No | No | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| bitcoin-bip110 | BIP-110 reduced-data compliance | bitcoin | Yes | Partial | No | Not evidenced | Conditional | [#179](https://github.com/Conxian/conxius-enclave-sdk/issues/179), [#196](https://github.com/Conxian/conxius-enclave-sdk/issues/196), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| bitcoin-bip322 | BIP-322 message verification | bitcoin | Yes | Partial | Partial | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#196](https://github.com/Conxian/conxius-enclave-sdk/issues/196), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| bitcoin-ecdsa | Bitcoin ECDSA signing | bitcoin | Yes | Partial | Partial | Not evidenced | Conditional | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#196](https://github.com/Conxian/conxius-enclave-sdk/issues/196), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| bitcoin-taproot | Bitcoin Schnorr and Taproot | bitcoin | Yes | Partial | Partial | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#196](https://github.com/Conxian/conxius-enclave-sdk/issues/196), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| covenant | Bitcoin covenant and OP_CAT helpers | bitcoin | Yes | Partial | No | Not evidenced | No | [#196](https://github.com/Conxian/conxius-enclave-sdk/issues/196), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| ark | Ark vTXO and recovery orchestration | bitcoin-l2 | Yes | Partial | No | Not evidenced | No | [#197](https://github.com/Conxian/conxius-enclave-sdk/issues/197), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| bitvm | BitVM challenge primitives | bitcoin-l2 | Yes | Partial | No | Not evidenced | No | [#197](https://github.com/Conxian/conxius-enclave-sdk/issues/197), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| bitvm2 | BitVM2 challenge orchestration | bitcoin-l2 | Yes | Partial | No | Not evidenced | No | [#197](https://github.com/Conxian/conxius-enclave-sdk/issues/197), [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| business | Business registry and profiles | business | Yes | Partial | No | Not evidenced | No | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| opportunity | Opportunity discovery | business | Yes | Partial | No | Not evidenced | No | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| solver | Solver bid ranking | business | Yes | Partial | No | Not evidenced | No | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| swap-router | Swap router | business | Yes | Partial | No | Not evidenced | No | [#197](https://github.com/Conxian/conxius-enclave-sdk/issues/197), [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| asset-registry | Asset registry and chain metadata | chains | Yes | Partial | Partial | Not evidenced | No | [#198](https://github.com/Conxian/conxius-enclave-sdk/issues/198), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| ethereum | Ethereum address and signed-message handling | chains | Yes | Yes | Partial | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#196](https://github.com/Conxian/conxius-enclave-sdk/issues/196), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| chain-abstraction | Multi-chain intent and chain abstraction | chains | Yes | Partial | Partial | Not evidenced | Conditional | [#196](https://github.com/Conxian/conxius-enclave-sdk/issues/196), [#198](https://github.com/Conxian/conxius-enclave-sdk/issues/198), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| solana | Solana address and transfer preparation | chains | Yes | Partial | No | Not evidenced | Conditional | [#196](https://github.com/Conxian/conxius-enclave-sdk/issues/196), [#198](https://github.com/Conxian/conxius-enclave-sdk/issues/198), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| stacks | Stacks address and transaction handling | chains | Yes | Partial | No | Not evidenced | Conditional | [#196](https://github.com/Conxian/conxius-enclave-sdk/issues/196), [#198](https://github.com/Conxian/conxius-enclave-sdk/issues/198), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| cctp | CCTP transfer and attestation | cross-chain | Yes | No | No | Not evidenced | No | [#198](https://github.com/Conxian/conxius-enclave-sdk/issues/198), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| replay-protection | Attestation replay and freshness protection | enclave | Yes | Partial | Partial | Not evidenced | Conditional | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| enclave-attestation | Enclave hardware attestation | enclave | Yes | Partial | No | Not evidenced | Conditional | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| enclave-signing | Enclave signing | enclave | Yes | Partial | Partial | Not evidenced | Conditional | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| proof-composition | Typed proof-factor taxonomy and composition | enclave | Yes | Partial | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| fedimint-nexus | Fedimint and Nexus federation adapter | federation | Yes | No | No | Not evidenced | No | [#197](https://github.com/Conxian/conxius-enclave-sdk/issues/197), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| economy | Economy and incentive helpers | fiat-and-economy | Yes | Partial | No | Not evidenced | Conditional | [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| fiat | Fiat session preparation | fiat-and-economy | Yes | Partial | No | Not evidenced | Conditional | [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| sidl | SIDL governance and voting | governance | Yes | Partial | No | Not evidenced | Conditional | [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| credit | Credit and vouch intents | identity-and-risk | Yes | Partial | No | Not evidenced | Conditional | [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| identity | Identity profiles | identity-and-risk | Yes | Partial | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| fido-provenance | FIDO authenticator provenance | identity-research | No | No | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| tls-server-identity | TLS 1.3 server identity | identity-research | No | No | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| webauthn-authorization | WebAuthn user authorization | identity-research | No | No | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| telemetry | Telemetry and observability | operations | Yes | Yes | Partial | Not evidenced | No | [#201](https://github.com/Conxian/conxius-enclave-sdk/issues/201), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| rail-policy | Rail policy and attestation enforcement | rails | Yes | Partial | No | Not evidenced | No | [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| rail-adapters | Settlement rail adapters | rails | Yes | Partial | No | Not evidenced | No | [#197](https://github.com/Conxian/conxius-enclave-sdk/issues/197), [#198](https://github.com/Conxian/conxius-enclave-sdk/issues/198), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| ci-release-evidence | CI, release, SBOM, and provenance evidence | release | Yes | Partial | No | Not evidenced | No | [#199](https://github.com/Conxian/conxius-enclave-sdk/issues/199), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| dlc | Discreet Log Contracts | settlement | Yes | Partial | No | Not evidenced | No | [#197](https://github.com/Conxian/conxius-enclave-sdk/issues/197), [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| job-card-iso20022 | Job Card and ISO 20022 | settlement | Yes | Partial | No | Not evidenced | No | [#197](https://github.com/Conxian/conxius-enclave-sdk/issues/197), [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| lightning | Lightning payment intent | settlement | Yes | Partial | No | Not evidenced | No | [#197](https://github.com/Conxian/conxius-enclave-sdk/issues/197), [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| settlement-service | Settlement service orchestration | settlement | Yes | Partial | No | Not evidenced | No | [#197](https://github.com/Conxian/conxius-enclave-sdk/issues/197), [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| stablecoin | Stablecoin orchestration | settlement | Yes | Partial | No | Not evidenced | No | [#198](https://github.com/Conxian/conxius-enclave-sdk/issues/198), [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| mmr-state | MMR and state proofs | state | Yes | Partial | No | Not evidenced | No | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| frost | FROST threshold signing | threshold-cryptography | Yes | No | No | Not evidenced | No | [#197](https://github.com/Conxian/conxius-enclave-sdk/issues/197), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| musig2 | MuSig2 multi-signature aggregation | threshold-cryptography | Yes | Partial | No | Not evidenced | No | [#197](https://github.com/Conxian/conxius-enclave-sdk/issues/197), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| wasm-a2p | WASM A2P client | wasm | Yes | Partial | No | Not evidenced | Conditional | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| wasm-business | WASM Business client | wasm | Yes | Partial | No | Not evidenced | Conditional | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| wasm-dlc | WASM DLC client | wasm | Yes | Partial | No | Not evidenced | Conditional | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| wasm-job-card-iso20022 | WASM Job Card / ISO 20022 client | wasm | Yes | Partial | No | Not evidenced | Conditional | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| wasm-lightning | WASM Lightning client | wasm | Yes | Partial | No | Not evidenced | Conditional | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| wasm-mmr | WASM MMR client | wasm | Yes | Partial | No | Not evidenced | Conditional | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| wasm-opportunity | WASM Opportunity client | wasm | Yes | Partial | No | Not evidenced | Conditional | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| wasm-settlement-service | WASM Settlement Service client | wasm | Yes | Partial | No | Not evidenced | Conditional | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| wasm-solver | WASM Solver client | wasm | Yes | Partial | No | Not evidenced | Conditional | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| wasm-stablecoin | WASM Stablecoin client | wasm | Yes | Partial | No | Not evidenced | Conditional | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| wasm-swap-router | WASM Swap Router client | wasm | Yes | Partial | No | Not evidenced | Conditional | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |
| wasm-zkml | WASM ZKML client | wasm | Yes | Partial | No | Not evidenced | Conditional | [#200](https://github.com/Conxian/conxius-enclave-sdk/issues/200), [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202) |

<!-- capability-evidence:generated:end -->

## Promotion rules

1. A row cannot be marked **production-supported** unless all preceding evidence columns are `Yes` for the same artifact and deployment scope, with non-empty requirement, code, test, CI, and artifact references in that order.
2. `Simulation only`, `structural`, `placeholder`, `mock`, and `development-only` behavior must remain explicitly labeled and must not be used as production evidence.
3. A capability may be supported for one artifact/platform and unsupported for another; promotion must name the exact tag, target, runtime, hardware, and integration boundary.
4. Any unknown or missing evidence is a gate failure for value-bearing signing or settlement, not an implicit pass.
5. The open production-enablement backlog is already tracked by GitHub issues [#195](https://github.com/Conxian/conxius-enclave-sdk/issues/195) through [#202](https://github.com/Conxian/conxius-enclave-sdk/issues/202); this matrix does not create or duplicate those issues.
