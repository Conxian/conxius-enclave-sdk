# Conclave SDK Research Log

> External research findings, technology monitoring, and industry analysis
> **Version**: v1.1.0 | **Last Updated**: 2026-07-21

---

## Overview

This document captures external research findings relevant to the Conclave SDK's development trajectory. Each entry includes source links and applicability notes for future reference.

---

## Typed provider evidence boundary (2026-07-21)

- Simulated attestation, software-driver tests, and successful WASM compilation establish containment or build evidence only; they do not establish hardware, provider, runtime, deployment, or release support.
- The reviewed checkpoint keeps value-bearing signing behind a fail-closed typed provider verifier/signer boundary that binds the operation, key, algorithm, attestation, policy, and replay authorization. The real provider verifier/signer remains unavailable, so production support is not claimed.
- The current replay authorization is process-local. Distributed replay coordination, provider-backed runtime tests, independent review, and exact artifacts remain required before promotion.

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
- `src/protocol/bitvm2.rs`: Already implemented with forfeit/commitment methods
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
