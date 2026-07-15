# Conclave SDK Research Log

> External research findings, technology monitoring, and industry analysis
> **Version**: v1.0.0 | **Last Updated**: 2026-07-15

---

## Overview

This document captures external research findings relevant to the Conclave SDK's development trajectory. Each entry includes source links and applicability notes for future reference.

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

### Performance
- **Current**: ~$15k fees for challenged execution
- **Target**: <$50 fees via BitVM3 optimizations
- **Latency**: ~42 blocks (7h 36min) for settlement

### Ecosystem Adoption
- **Citrea**: ZK-rollup using BitVM2 for permissionless exits
- **BOB**: Native BitVM bridge for BTC-DeFi primitives
- **Bitlayer/Botanix**: EVM-compatible and optimistic rollup designs

### Key References
- [BitVM2 Whitepaper](https://bitvm.org/bitvm_bridge.pdf)
- [ePrint IACR Paper](https://eprint.iacr.org/2025/1158.pdf)
- [BitVM GitHub](https://github.com/BitVM/BitVM)

### Applicability
- `src/protocol/bitvm.rs`: Challenge orchestration
- `src/protocol/ark.rs`: Forfeit transaction integration
- GAP item G-002: Ark BitVM2 Challenge Orchestration

---

## Fedimint eCash Evolution

### Threshold BLS Blind Signatures
- Replaces single-key blind signing with threshold scheme
- Based on BLS12-381 pairings
- Quorum-based signing prevents single-guardian compromise
- Batch verification support

### DLEQ Proofs
- Discrete-logarithm equality proofs in issuance flow
- Validates blinded token without exposing secret
- NUT-12 construction for privacy

### Performance Metrics
- **Latency**: <200ms intra-federation (with guardians offline)
- **Throughput**: 2-3x improvement over Chaumian-only
- **Gateway**: Multi-federation support, LNURL-pay in development

### Key References
- [Fedimint Official](https://fedimint.org)
- [Fedimint GitHub](https://github.com/fedimint/fedimint)
- [fedimint-tbs crate](https://crates.io/crates/fedimint-tbs)

### Applicability
- `src/protocol/nexus/fedimint.rs`: Federation adapter
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
- **BitVM2 Challenge Orchestration**: Ark integration
- **Succinct SP1**: ZK verification on Bitcoin
- **ezkl**: ML model verification

### Assess (Monitor Developments)
- **BitVM3**: Transaction size optimizations
- **STARKs on Bitcoin**: Quantum-resistant verification
- **ARM CCA Attestation**: Next-gen mobile security

### Hold (Not Recommended)
- **Single-key Fedimint signing**: Security risk
- **OP_CAT without BIP-347**: Non-standard Bitcoin

---

## Research Sessions

| Date | Topic | Key Findings | Action Items |
|------|-------|--------------|--------------|
| 2026-07-15 | TEE Attestation | Intel SGX DCAP, AMD SEV-SNP, ARM PSA patterns | Update attestation module documentation |
| 2026-07-15 | BitVM2 | Q4 2025 roadmap, permissionless challengers | Track G-002 progress |
| 2026-07-15 | Fedimint | Threshold BLS, DLEQ proofs | Update fedimint.rs implementation |
| 2026-07-15 | WASM SDK | wasm-pack patterns, async best practices | Complete ARCH-001 audit |
| 2026-07-15 | ZKML | SNARK/STARK developments, ezkl | Evaluate zkml.rs enhancements |

---

## Action Items from Research

### Immediate (v2.1.0)
- [ ] Complete WASM bindings audit (ARCH-001)
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
*Maintained by: SDK Team*
