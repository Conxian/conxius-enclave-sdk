# Conclave SDK Research Log

> External research findings, technology monitoring, and industry analysis
> **Version**: v1.2.0 | **Last Updated**: 2026-07-22

---

## Overview

This document captures external research findings relevant to the Conclave SDK's development trajectory. Each entry includes source links and applicability notes for future reference.

---

## Hardware and proof-claim research map (2026-07-22)

**Access date for every source in this section:** 2026-07-22. These findings
are research/design evidence only. They do not establish a provider verifier,
runtime integration, production support, independent review, or a release
artifact for this repository.

### 1. TLS 1.3 server identity is not TEE proof

- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) defines TLS 1.3
  authentication and certificate/`CertificateVerify` behavior.
- [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html) documents server
  identity considerations for TLS deployments.
- **Boundary:** TLS server identity authenticates an endpoint under a PKI
  contract. It does not prove a TEE, enclave measurement, device state, or
  hardware-backed key origin. The proof taxonomy keeps `ServerIdentity`
  separate from TEE/provider evidence.

### 2. WebAuthn authorization versus FIDO provenance

- [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) specifies the RP,
  origin, challenge, authenticator-data, user-presence, and user-verification
  relationships in a WebAuthn ceremony.
- [FIDO Metadata Service 3.1.1 RD02](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-rd02-20260105.pdf)
  and [The Truth About Attestation](https://fidoalliance.org/fido-technotes-the-truth-about-attestation/)
  describe authenticator provenance/metadata and the choices an RP makes
  about attestation.
- **Boundary:** an assertion can authorize an RP operation; provenance and
  metadata do not replace RP-origin, challenge, user-presence, or
  user-verification checks. The SDK keeps user authorization and FIDO
  provenance as distinct claims.

### 3. TPM 2.0 quotes, PCRs, and replay inputs

- The [TCG TPM Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
  and [Part 2: Structures, Version 1.85](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-2-Structures_Version-185_pub.pdf)
  define quote structures, PCR selections/digests, qualifying data, and key
  structures.
- A verifier must distinguish the Attestation Key (AK), any Endorsement Key
  (EK) provenance, selected PCR values, the event log, and a verifier-provided
  challenge/`qualifyingData`; freshness and replay are not inferred from a
  PCR digest alone.
- **Boundary:** `TpmQuote` is a typed category only. No TPM quote, AK/EK trust
  store, PCR policy, event-log parser, or production verifier is shipped.

### 4. Android Key Attestation, TEE, and StrongBox

- [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
  describes attestation certificates and security-relevant challenge, app,
  verified-boot, OS-version, and patch-level information.
- [Android attestation status](https://android.googleapis.com/attestation/status)
  is a provider status/revocation input, not a substitute for certificate
  chain and policy verification.
- The Android model distinguishes TEE-backed keys from StrongBox-backed keys;
  key origin, security level, challenge binding, application identity,
  verified-boot state, patch state, and status handling must be evaluated
  together.
- **Boundary:** the existing Android/TEE types and tests do not establish a
  live Android provider verifier, StrongBox runtime, root store, or status
  service. No generic `DeviceIntegrityReport` promotion is allowed.

### 5. Apple App Attest versus Secure Enclave isolation

- Apple documents [server validation for App Attest](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
  and [establishing app integrity](https://developer.apple.com/documentation/DeviceCheck/establishing-your-apps-integrity).
- [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/Security/protecting-keys-with-the-secure-enclave)
  describes device-local key isolation and supported key operations.
- **Boundary:** App Attest is an app-integrity protocol with a server
  validation flow; Secure Enclave documents key isolation. These sources do
  not justify a generic remote Secure Enclave attestation claim. The SDK keeps
  `Apple App Attest` and `Apple Secure Enclave key operation` separate and
  unsupported as providers.

### 6. Intel SGX DCAP and TDX

- [Intel SGX DCAP ECDSA Orientation 1.23](https://download.01.org/intel-sgx/sgx-dcap/1.23/linux/docs/DCAP_ECDSA_Orientation.pdf)
  describes quote verification inputs including QE/PCK certificates,
  collateral, TCB status, and revocation material.
- [Intel TDX documentation](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html)
  describes the TDX trust-domain measurement/report and quote ecosystem.
- **Boundary:** report data, measurements, QE/PCK chains, CRLs, collateral,
  TCB policy, and freshness must be verified for the exact platform. No SGX
  DCAP or TDX verifier/runtime/collateral integration is present.

### 7. AMD SEV-SNP

- The [AMD SEV-SNP guest-hypervisor interface specification](https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf)
  describes report data, policy, debug/migration controls, TCB values, and
  VCEK/VLEK certificate relationships.
- **Boundary:** `REPORT_DATA` is a verifier-bound input, not an independent
  claim. VCEK/VLEK provenance, platform TCB policy, certificate status, and
  runtime behavior are required. No SEV-SNP verifier/runtime is implemented.

### 8. AWS Nitro NSM and attestation documents

- AWS documents [Nitro root verification](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)
  and [obtaining an attestation document](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestation-get-doc.html).
- The attestation document model includes COSE protection and verifier-bound
  PCRs, nonce, user data, and public-key inputs; the AWS root/debug boundary
  must be checked rather than assumed.
- **Offline boundary added:** native-only `src/enclave/nitro.rs` now provides
  bounded tagged/untagged COSE and Nitro CBOR parsing, real P-384 COSE
  signature verification against the attestation leaf, exact local PCR and
  freshness policy, a domain-separated release binding, nonce/public-key
  binding checks, and a transport-neutral RSAES-OAEP-SHA-256 recipient
  contract. These are structural code/test references only.
- **Boundary:** the module has no NSM client, vsock or KMS transport, AWS root
  store, certificate-path/collateral/revocation verifier, EIF/PCR provenance,
  CloudTrail integration, distributed replay service, independent review, or
  production provider registration. `AttestationPolicy::production()` remains
  fail-closed with `ProviderVerifierStatus::Unavailable`; fixtures are
  test-only and do not establish AWS provenance.

### 9. ARM PSA and CCA/EAT/COSE

- [PSA Attestation API 1.0.2](https://developer.arm.com/-/media/Files/pdf/PlatformSecurityArchitecture/Implement/IHI0085-PSA_Attestation_API-1.0.2.pdf)
  defines challenge-driven attestation and lifecycle/implementation/platform
  claims.
- [RFC 9783](https://www.rfc-editor.org/rfc/rfc9783.html) specifies the PSA
  attestation token profile using EAT/COSE concepts; CCA deployments require
  the realm/platform distinction and their own implementation evidence.
- **Boundary:** PSA and CCA are not interchangeable generic TEE claims. No
  EAT/COSE verifier, lifecycle policy, realm/platform runtime, or vendor root
  integration is present.

### Research-to-code action

PR #237 records the research map as conservative capability rows only. The
implemented code change is limited to exact policy digest binding, all-required
composition, rail/final-dispatch mismatch rejection, and test-fixture lint
refactoring. Provider rows remain unsupported until the requirement → code →
test → CI → artifact chain exists for the exact provider and deployment.

---

## Protocol boundary research and quarantine (2026-07-21)

This session replaces historical implementation/completion wording with a
foundation-plus-quarantine boundary. The local SDK now carries typed public
metadata and idempotency contracts only; value-bearing protocol operations
remain unsupported until the requirement → code → test → CI → artifact chain
is complete. See [`PROTOCOL_IMPLEMENTATION_ROADMAP.md`](docs/architecture/PROTOCOL_IMPLEMENTATION_ROADMAP.md).

### FROST

- RFC 9591: <https://datatracker.ietf.org/doc/html/rfc9591>
- Zcash Foundation implementation: <https://github.com/ZcashFoundation/frost>
- Inspected `frost-secp256k1/v3.0.0` at commit
  `2016e44ba4a4757a996300350063b937a2ad33e8`.
- Future acceptance must cover DKG validation and authenticated encryption,
  one-use nonces, ciphersuite/serialization compatibility, zeroization,
  BIP340/provider/attestation binding, and official/independent vectors.
- The SDK boundary intentionally does not implement cryptography, keygen, DKG,
  signing, verification, or aggregation.

### Fedimint

- Source: <https://github.com/fedimint/fedimint>
- Documentation: <https://docs.fedimint.org/>
- Stable `v0.11.1`: `2620789610a2c65c1068de973ebb5657d08d549d`.
- Prerelease `v0.11.2-alpha.1`:
  `b934260695c3a15178df7ddd33db8f66e1c9a153`.
- Future acceptance must cover BLS12-381 TBS, client/config/API compatibility,
  database and operation-log durability, share verification, unblinding, note
  state, backup/restore, and provider ownership.
- **DLEQ qualification:** no evidence was found in the inspected current
  canonical Fedimint mint flow that DLEQ is inherently part of every current
  canonical issuance path. The SDK keeps only a typed DLEQ-shaped boundary and
  makes no issuance claim.

### Ark

- Protocol overview: <https://ark-protocol.org/>.
- Arkade daemon: <https://github.com/arkade-os/arkd>.
- Bitcoin implementations: <https://gitlab.com/ark-bitcoin>.
- Implementations are evolving. Inspected Arkade `v0.9.15` is Alpha and should
  not be used in production. A future milestone must choose and pin Arkade or
  Second before implementation work resumes.
- Required acceptance areas are rounds, VTXOs/outpoints, connectors, ASP,
  forfeits, transactions, expiry, persistence, recovery, and unilateral exit.

### BitVM2

- Overview: <https://bitvm.org/bitvm2>.
- Bridge paper: <https://bitvm.org/bitvm_bridge.pdf>.
- Implementation repository: <https://github.com/chainwayxyz/bitvm>.
- The inspected material is experimental/research-oriented, explicitly says
  not to use in production, and contains incomplete paths.
- Required acceptance areas are roles, bridge graph, templates, commitments,
  disprove scripts/proofs, timeouts, chain monitoring, durable idempotency, and
  provider/attestation boundaries.

### Research action

Keep FROST, Fedimint, Ark, and BitVM2 capability rows at `Production: No`.
Do not treat typed models, local tests, WASM compilation, historical issue
closure, or a passing structural check as protocol, integration, review, or
release evidence.

---

## Typed provider evidence boundary (2026-07-21)

- Simulated attestation, software-driver tests, and successful WASM compilation establish containment or build evidence only; they do not establish hardware, provider, runtime, deployment, or release support.
- Reviewed code checkpoint `57726f3e5fca29ec953b1f58445eae7530414924` keeps value-bearing signing behind a fail-closed typed provider verifier/signer boundary that binds the operation, key, algorithm, attestation, policy, and replay authorization. The rail boundary additionally requires `ValueBearingPurpose::Settlement`, the canonical `conxian/settlement/v1` domain, and the canonical intent digest as operation context; typed Opportunity preflight is validation-only while the legacy raw-signature shim remains rejected. The real provider verifier/signer remains unavailable, so production support is not claimed.
- The current replay authorization is process-local. Distributed replay coordination, provider-backed runtime tests, independent review, and exact artifacts remain required before promotion.

---

## Production-enablement evidence schema research (2026-07-20)

### Artifact provenance
- GitHub's [artifact attestation documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations) describes attestations as build-provenance evidence that establishes where and how software was built and supports offline verification.
- The [SLSA provenance specification](https://slsa.dev/spec/v1.1/provenance) defines provenance around the build definition, resolved inputs, builder, execution metadata, and produced subjects. The stable predicate URI is `https://slsa.dev/provenance/v1`.
- **Applicability**: A workflow definition or a passing local command is not an exact release artifact. The capability evidence record therefore keeps `artifact` as a separate stage and leaves it empty until a reviewed ref, artifact digest, provenance, SBOM, and release decision are durably attached.

### WASM runtime evidence
- The [wasm-bindgen-test usage guide](https://wasm-bindgen.github.io/wasm-bindgen/wasm-bindgen-test/usage.html) distinguishes writing Rust-side tests from executing them through `wasm-pack test`, including Node.js and headless-browser runners.
- **Applicability**: A successful `wasm32-unknown-unknown` build or generated binding demonstrates an API/build surface only. Browser, Node, bundler, worker, provider, hardware, lifecycle, and unsupported-platform behavior must be evidenced separately under #200.

### Deterministic evidence schemas
- [NIST SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) describes the SSDF as a common vocabulary for secure software development and includes provenance collection among its practices. The [NIST SSDF project](https://csrc.nist.gov/Projects/ssdf) emphasizes outcome-based, risk-aware evidence rather than an unqualified checklist.
- **Applicability**: `docs/architecture/capability-evidence.json` uses `schemaVersion`, a full `reviewedRef`, controlled status values, stable capability IDs, repository-path references, and an ordered requirement → code → test → CI → artifact chain. The dependency-free validator rejects duplicate IDs, missing paths, drift, incomplete blocker/exclusion coverage, and production claims without prerequisite evidence.

---

## TEE Hardware Attestation (2024-2025)

### Intel SGX
- **Technology**: DCAP (Data Center Attestation Primitives) with ECDSA quotes
- **Verification**: PCK (Provisioning Certification Key) certificates from Intel PCS
- **Key References**:
  - [Intel SGX DCAP API](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf)
- **Applicability**: Cloud TEE implementation in `src/enclave/cloud.rs`

### AMD SEV-SNP
- **Technology**: Confidential VMs with memory integrity protection
- **Key Feature**: 64-byte guest-data field for nonce/replay protection
- **Key References**:
  - [SEV-SNP Platform Attestation](https://www.amd.com/content/dam/amd/en/documents/developer/58217-epyc-9004-ug-platform-attestation-using-virtee-snp.pdf)
- **Note**: Guest-data field binds verifier nonce to prevent replay

### ARM PSA/CCA
- **Technology**: Platform Security Architecture with CCA tokens
- **Format**: EAT (Entity Attestation Token) serialized with COSE
- **Key References**:
  - [RFC 9783 - PSA Attestation Token](https://datatracker.ietf.org/doc/html/rfc9783)
- **Applicability**: Mobile StrongBox implementation in `src/enclave/android_strongbox.rs`

### Best Practices Summary
1. Nonce-driven remote attestation flow
2. Full certificate chain validation (PCK → Intel/AMD root)
3. Hardware RNG for key generation
4. Seal keys with platform-native sealing API
5. NIST SP 800-57 for key lifecycle governance

---

## BitVM2 Developments (Q4 2025)

### Architecture
- **Model**: Optimistic rollup treating Bitcoin as consensus layer
- **Security**: Permissionless challengers (existential honesty - 1-of-n)
- **Components**:
  - Data commitments (hashes of batch state roots) on Bitcoin
  - Optimistic SNARK verifier for fraud proofs
  - Script chunking for Bitcoin's 100KB block limit

### BitVM3 Evolution (2025-2026)
- **Garbled Circuits**: BitVM3 moves computation off-chain using garbled circuits
- **Assertion Size**: ~56 kB (vs 1GB for BitVM1, 2-4MB for BitVM2)
- **Disprove TX**: ~200 bytes (massive reduction)
- **Prover Cost**: One-time ~5TB setup, ZeroGC reduces to MBs
- **Deployment**: Clementine (Citrea testnet April 2025), Bitlayer mainnet beta

### Performance
- **Current**: ~$15k fees for challenged execution
- **Target**: <$50 fees via BitVM3 optimizations
- **Latency**: ~42 blocks (7h 36min) for settlement (optimistic: next block)
- **Throughput**: Shielded CSV claims ~100 TPS with 64-byte nullifiers

### Ecosystem Adoption
- **Citrea/Clementine**: ZK-rollup with collateral-efficient BitVM bridge
- **BOB**: Native BitVM bridge, ~87% cost reduction (~$10/assertion)
- **Bitlayer**: Mainnet beta with Finality Chain (PoS) coordination
- **Alpen Labs/Glock**: Designated-verifier SNARKs for lower on-chain cost
- **GOAT**: Audited Bitcoin-anchored zk-rollup

### Key References
- [BitVM3 Whitepaper](https://bitvm.org/bitvm3.pdf)
- [BitVM2 Whitepaper](https://bitvm.org/bitvm_bridge.pdf)
- [Clementine Design](https://citrea.xyz/clementine_whitepaper.pdf)
- [Glock ePrint](https://eprint.iacr.org/2025/1485)
- [BitVM GitHub](https://github.com/BitVM/BitVM)

### Applicability
- `src/protocol/bitvm.rs`: Challenge orchestration
- `src/protocol/ark.rs`: Forfeit transaction integration
- `src/protocol/bitvm2.rs`: Historical implementation note only; the current
  boundary retains typed forfeit/commitment models but keeps those operations
  unsupported.
- GAP item G-002: Ark BitVM2 Challenge Orchestration

---

## Fedimint eCash Evolution

### v0.4 Architecture (2024-2025)
- **Federation Formation**: Dealer-free Pedersen DKG produces threshold key shares
- **Consensus**: AlephBFT (async BFT), 3m+1 fault tolerance
- **Guardian Model**: Threshold BLS blind signatures, no single guardian holds full key
- **Key Generation**: DKG runs at federation setup, latency ~seconds

### Threshold BLS Blind Signatures
- Replaces single-key blind signing with threshold scheme
- Based on BLS12-381 pairings
- Quorum-based signing prevents single-guardian compromise
- Batch verification support
- **fedimint-tbs**: Production BLS threshold signing crate

### DLEQ Proofs
- Discrete-logarithm equality proofs in issuance flow
- Validates blinded token without exposing secret
- NUT-12 construction for privacy

### Lightning Gateway Integration
- **LN Gateways**: Untrusted economic actors (not guardians)
- **Threshold Point Encryption**: For Lightning preimages (atomic ecash↔LN swaps)
- **Multi-federation**: Gateways can serve multiple Fedimints
- **v0.4 Changes**: GatewayBuilder refactor, ILnRpc sync_wallet, LUD-21 hex encoding

### Performance Metrics
- **Latency**: <200ms intra-federation (with guardians offline)
- **Throughput**: 2-3x improvement over Chaumian-only
- **Gateway**: Multi-federation support, LNURL-pay in development

### Operational Considerations
- **Upgrade**: Lock-step session count requirement for pre-v0.4 upgrades
- **Recovery**: 12-word operator recovery for ecash and on-chain funds
- **Consensus Halt**: Federation halts if quorum not present

### Key References
- [Fedimint Official](https://fedimint.org)
- [Fedimint GitHub](https://github.com/fedimint/fedimint)
- [fedimint-tbs crate](https://crates.io/crates/fedimint-tbs)
- [v0.4 Release Notes](https://github.com/fedimint/fedimint/blob/master/docs/RELEASE_NOTES-v0.4.md)

### Applicability
- `src/protocol/nexus/fedimint.rs`: Federation adapter (updated with DLEQ proofs)
- GAP items G-001, G-003: Fedimint Wasm/Blinding integration

---

## WASM SDK Patterns

### Architecture Best Practices
```
workspace/
├── my_sdk_core/      # No wasm-bindgen, native tests
├── my_sdk_wasm/      # cdylib, wasm-bindgen wrapper
└── examples/         # Usage examples
```

### Build & Tooling
- **wasm-pack**: Primary orchestrator for builds
- **wasm-opt -Oz**: Size optimization (10-20% reduction)
- **wasm-slim**: Additional size reduction tool
- **rust-toolchain.toml**: Deterministic builds

### Async Patterns
- Use `wasm-bindgen-futures` for Promise-based JS integration
- Avoid Tokio in browser (no OS threads)
- Use `spawn_local` for fire-and-forget tasks
- Spawn Web Workers for CPU-intensive work

### Security Checklist
- Validate all input at JS boundary
- Never expose private keys to JavaScript
- Enable CSP `script-src 'wasm-unsafe-eval'` only when needed
- Use `application/wasm` MIME type
- Strip debug symbols in production (`-strip-debug`)

### Key References
- [MDN Rust to WASM Guide](https://developer.mozilla.org/en-US/docs/WebAssembly/Guides/Rust_to_Wasm)
- [wasm-bindgen Guide](https://rustwasm.github.io/docs/wasm-bindgen)
- [ethers-rs WASM Example](https://github.com/gakonst/ethers-rs/blob/master/examples/wasm/README.md)

---

## ZKML Developments

### Proof Systems
| System | Proof Size | Verification | Quantum-Resistant |
|--------|------------|--------------|------------------|
| SNARKs | ~192 bytes | ~3ms | No (pairing-based) |
| STARKs | 45-200KB | Slower | Yes (hash-based) |

### Bitcoin Integration
- **BitVM**: Groth16 SNARK verification on Bitcoin
- **Citrea**: RISC-Zero STARKs for batch proofs
- **zkBitcoin**: Threshold signature with zk-SNARK proofs

### Tooling Ecosystem
- **ezkl**: TensorFlow/Keras to SNARK circuits
- **Circom + snarkjs**: Circuit compiler and proof generator
- **RISC-V (Succinct SP1)**: General-purpose zkVM for Bitcoin
- **0k Framework**: ONNX graph to SNARK proofs

### Use Cases
1. Privacy-preserving oracles
2. Decentralized AI marketplaces
3. On-chain fraud detection
4. AI trading bots (RockyBot)

### Key References
- [ezkl GitHub](https://github.com/worldcoin/awesome-zkml)
- [Succinct SP1](https://blog.succinct.xyz/bitcoin-sp1)
- [ZKML Performance Paper](https://ddkang.github.io/papers/2024/zkml-eurosys.pdf)

### Applicability
- `src/protocol/zkml.rs`: ZKML module already exists
- Potential: Privacy oracles, fraud detection integration

---

## Rust Crypto Crate Updates

### Stable Release Monitoring

| Crate | Current | Status | Monitor |
|-------|---------|--------|---------|
| bitcoin | 0.33.0-beta | Awaiting stable | [crates.io](https://crates.io/crates/bitcoin) |
| secp256k1 | 0.32.0-beta.2 | Awaiting stable | [crates.io](https://crates.io/crates/secp256k1) |
| k256 | 0.14.0-rc.9 | Awaiting stable | [crates.io](https://crates.io/crates/k256) |

### DEP-001 Tracking
- Awaiting stable versions to update
- May need compatibility shims
- Breaking changes likely on stable release

---

## Technology Radar

### Adopt (Ready for Integration)
- **Threshold BLS Blind Signatures**: Fedimint federation security
- **wasm-bindgen-futures**: Async WASM patterns
- **wasm-opt -Oz**: Size optimization

### Trial (Evaluate for Future)
- **BitVM3 Garbled Circuits**: Next-gen bridge optimization (~56kB assertions)
- **BitVM2 Challenge Orchestration**: Ark integration
- **Succinct SP1**: ZK verification on Bitcoin
- **ezkl**: ML model verification
- **Glock/DV-SNARKs**: Lower on-chain verifier cost

### Assess (Monitor Developments)
- **Clementine Bridge**: Collateral-efficient BitVM deployment
- **Bitlayer Mainnet**: Full-stack BitVM bridge production
- **STARKs on Bitcoin**: Quantum-resistant verification
- **ARM CCA Attestation**: Next-gen mobile security

### Hold (Not Recommended)
- **Single-key Fedimint signing**: Security risk
- **OP_CAT without BIP-347**: Non-standard Bitcoin
- **RSA-based BitVM3**: Security break/retraction documented

---

## Research Sessions

| Date | Topic | Key Findings | Action Items |
|------|-------|--------------|--------------|
| 2026-07-15 | TEE Attestation | Intel SGX DCAP, AMD SEV-SNP, ARM PSA patterns | Update attestation module documentation |
| 2026-07-15 | BitVM2 | Q4 2025 roadmap, permissionless challengers | Track G-002 progress |
| 2026-07-15 | Fedimint | Threshold BLS, DLEQ proofs | Update fedimint.rs implementation |
| 2026-07-15 | WASM SDK | wasm-pack patterns, async best practices | Complete ARCH-001 audit |
| 2026-07-15 | ZKML | SNARK/STARK developments, ezkl | Evaluate zkml.rs enhancements |
| 2026-07-15 | BitVM3 | Garbled circuits, 56kB assertions, Clementine/BOB/Bitlayer | Consider BitVM3 integration path |
| 2026-07-15 | Fedimint v0.4 | DKG, AlephBFT consensus, LN gateway integration | Review v0.4 API changes |
| 2026-07-15 | BIP-110 | Reduced Data Softfork: 256B pushdata, 83B OP_RETURN, 34B ScriptPubKey | Implement bip110_compliant feature |
| 2026-07-20 | Artifact provenance | GitHub attestations and SLSA provenance separate build intent from exact artifact evidence | Keep artifact stage empty until exact release evidence exists |
| 2026-07-20 | WASM runtime evidence | wasm-bindgen-test uses wasm-pack runners for Node/headless-browser execution; build output is not runtime support | Track browser/Node/bundler/worker/provider/hardware evidence in #200 |
| 2026-07-20 | Evidence schemas | NIST SSDF provides a common secure-development vocabulary and provenance-oriented practices | Validate deterministic capability JSON and ordered evidence chain |

---

## BIP-110: Reduced Data Temporary Softfork (2026)

### Overview
BIP-110 is a temporary softfork that moves Bitcoin policy limits into consensus to discourage on-chain data storage while preserving monetary use cases.

### Key Limits
| Rule | Limit | Description |
|------|-------|-------------|
| Pushdata/Witness | 256 bytes | OP_PUSHDATA and witness items >256 bytes invalid |
| OP_RETURN | 83 bytes | Restores 83-byte OP_RETURN as consensus rule |
| ScriptPubKey | 34 bytes | New outputs >34 bytes invalid unless OP_RETURN |

### Activation & Grandfathering
- Versionbits deployment with 55% threshold
- Mandatory activation height: block 961,632
- UTXOs created before activation are grandfathered
- Automatic expiry after ~1 year

### SDK Impact Analysis
- **BIP-322 Signing**: Messages >256 bytes require chunking
- **Ark/BitVM2**: Large data commitments need segmentation
- **Transaction Builders**: Enforce stricter output limits

### References
- [BIP-110 Spec](https://bips.dev/110)
- [Bitcoin Optech #412](https://bitcoinops.org/en/newsletters/2026/07/03)
- [Test Vectors](https://github.com/bitcoin/bips/blob/master/bip-0110/test-vectors.py)

---

## Action Items from Research

### Immediate (v2.1.0)
- [ ] Implement bip110_compliant feature flag (Issue #179)
- [ ] Document Fedimint threshold BLS upgrade path
- [ ] Add BitVM2 forfeit transaction documentation

### Short-term (v2.2.0)
- [ ] Implement BitVM2 challenge orchestration (G-002)
- [ ] Evaluate ezkl integration for zkml.rs
- [ ] Monitor secp256k1/k256 stable releases

### Medium-term (v2.3.0+)
- [ ] Add STARK verification support
- [ ] Integrate Succinct SP1 for Bitcoin verification
- [ ] Evaluate ARM CCA attestation support

---

*Research log initiated: 2026-07-15*
*Updated: 2026-07-20 (Capability evidence follow-up)*
*Maintained by: SDK Team*
