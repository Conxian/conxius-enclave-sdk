# Issue #196 Canonical Verification Evidence — 2026-07-21

Issue: https://github.com/Conxian/conxius-enclave-sdk/issues/196

## Identity and status

| Item | Identity |
| --- | --- |
| Base | `origin/main` at `e090e7582d9e7589c0fc89df12780763a8bfe524` |
| Bitcoin/Taproot code checkpoint | `01674b523f694a2e6fc61bfb22b593602ca670f8` |
| Ethereum code checkpoint | `3e2a10941a955885a959d928cefde003871329ab` |
| BIP-322 typed API checkpoint | `54c5139c5b3337e29daa2e08a65dc359b580bde4` |
| Final code checkpoint reviewed by the capability source | `1a33a6bf309a5c82f3fbebdf59f417a09710adb2` |

The repository remains **Beta / conditional**. This note records scoped canonical
verification and derivation evidence only; it does not authorize production use,
change the affected `productionSupport` values, or establish repository-wide
readiness. Independent review remains not evidenced. Issue #195 remains the
provider/hardware gate for production authorization paths, and issue #202 remains
the independent review and release-acceptance gate.

## Requirement → code → test evidence

### Bitcoin Schnorr and Taproot

- **Requirement:** Issue #196 requires canonical BIP-340 verification and
  BIP-341/Taproot derivation with deterministic rejection of malformed inputs.
- **Code:** `verify_bip340_signature` performs fixed-length parsing and canonical
  secp256k1 Schnorr verification (`src/protocol/bitcoin.rs:17-45`).
  `TaprootManager::derive_taproot_output_key` and `taproot_tweak_hash` use the
  rust-bitcoin BIP-341 tagged tweak (`src/protocol/bitcoin.rs:107-177`), while
  canonical BIP-86 path and scalar validation is enforced at
  `src/protocol/bitcoin.rs:179-240`. The software Schnorr path normalizes an
  odd-Y secret to the x-only internal key before adding TapTweak
  (`src/enclave/android_strongbox.rs:221-275`).
- **Tests:** BIP-86 output-key derivation and reference address
  (`src/protocol/bitcoin.rs:454-483`), BIP-341 wallet tweak/output-key vector
  (`src/protocol/bitcoin.rs:485-513`), BIP-340 valid/invalid/malformed vectors
  (`src/protocol/bitcoin.rs:515-608`), canonical path/key rejection
  (`src/protocol/bitcoin.rs:610-632`), and odd/even internal-secret behavior
  (`src/enclave/android_strongbox.rs:503-608`).
- **Official provenance:**
  [BIP-340 test vectors](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv),
  [BIP-341 wallet vectors](https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json),
  and the [BIP-86 reference](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki).
- **Recorded values:** BIP-86 tweak
  `2ca01ed85cf6b6526f73d39a1111cd80333bfdc00ce98992859848a90a6f0258` and
  reference output `bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr`;
  BIP-341 merkle root
  `c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b`, tweak
  `6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30`, and
  output key `e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e`;
  BIP-340 vector 0 uses public key
  `f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9`.

### Ethereum address and signed-message behavior

- **Requirement:** Issue #196 requires canonical Keccak/EIP behavior and
  deterministic rejection of malformed addresses, signatures, and recovery
  identifiers. The capability row is limited to address and signed-message
  behavior.
- **Code:** Public-key address derivation uses Keccak over the uncompressed key
  (`src/protocol/ethereum.rs:38-41,299-304`). EIP-191 text and binary hashing,
  compact/recoverable low-S validation, EIP-2098 decoding, and context-bound
  EIP-155 `v` decoding are implemented at
  `src/protocol/ethereum.rs:110-260`; strict address parsing is at
  `src/protocol/ethereum.rs:320-348`. `sign_transaction_hash` accepts a
  precomputed digest and explicitly does not serialize EIP-155/EIP-1559/EIP-712
  transactions (`src/protocol/ethereum.rs:43-48`).
- **Tests:** Canonical address and EIP-191/Keccak vectors, strict EIP-55 and
  negative address cases, low-S and recovery-parity cases, EIP-2098 official and
  negative vectors, EIP-155 `v` cases, and malformed-input cases are covered by
  `src/protocol/ethereum.rs:500-920`; address/API smoke coverage is in
  `src/protocol/universal_tests.rs:10-86`.
- **Official provenance:** [Keccak known answers](https://keccak.team/keccak.html),
  [EIP-191](https://eips.ethereum.org/EIPS/eip-191),
  [EIP-55 test cases](https://eips.ethereum.org/EIPS/eip-55#test-cases),
  [EIP-2098 test cases](https://eips.ethereum.org/EIPS/eip-2098#test-cases),
  and the [EIP-155 example](https://eips.ethereum.org/EIPS/eip-155#example).
- **Recorded values:** canonical address
  `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf`; Keccak-256 of the empty string
  `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` and
  `abc` `4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45`;
  EIP-191 `Hello World` hash
  `a1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2`.

### BIP-322 message verification

- **Requirement:** Issue #196 requires cryptographic BIP-322 verification rather
  than acceptance-only parsing, with explicit handling for unsupported forms.
- **Code:** The module documents the supported boundary and the absence of a
  Script interpreter (`src/protocol/bip322.rs:20-32`). Canonical tagged message
  hashing and virtual transaction construction are implemented at
  `src/protocol/bip322.rs:134-307`; Simple/Full/Proof-of-Funds decoding and typed
  unsupported errors are at `src/protocol/bip322.rs:570-628`. Native P2WPKH and
  native P2TR key-path verification use the relevant sighash and signature
  checks (`src/protocol/bip322.rs:667-746`), and the public network-aware API
  returns typed `Valid`, `Invalid`, or `Inconclusive` outcomes
  (`src/protocol/bip322.rs:756-898`).
- **Tests:** Official P2WPKH and P2TR Simple positives are covered at
  `src/protocol/bip322.rs:1000-1060`; network-aware behavior at
  `src/protocol/bip322.rs:1066-1154`; Full and Proof-of-Funds typed rejection at
  `src/protocol/bip322.rs:1159-1243`; mutation/negative and unsupported address
  tests at `src/protocol/bip322.rs:1356-1638`; and canonical virtual transaction
  construction at `src/protocol/bip322.rs:1641-1680`.
- **Official provenance:** [BIP-322 specification](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki),
  [basic vectors](https://github.com/bitcoin/bips/blob/master/bip-0322/basic-test-vectors.json),
  and [generated vectors](https://github.com/bitcoin/bips/blob/master/bip-0322/generated-test-vectors.json).
- **Recorded value:** the canonical `Hello World` BIP-322 message hash is
  `f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a`.

## Local verification

The mandatory session initialization completed before documentation changes:

- `./scripts/sync_issues.sh` returned success but emitted an HTTP 401 while
  fetching GitHub data; no fresh remote-sync claim is made from that command.
- `cargo fmt --all -- --check`, `cargo clippy --all-features -- -D warnings`,
  and `cargo test` passed: 250 library tests, 6 production-rail integration
  tests, and the documentation tests (1 passed, 1 ignored).

The final evidence-update verification is recorded by these exact commands:

```text
python3 scripts/validate_capability_evidence.py --write
python3 scripts/validate_capability_evidence.py --check
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
cargo fmt --all -- --check
cargo clippy --all-features -- -D warnings
cargo test
git diff --check
```

**Results:** the capability validator reported `54 capabilities; generated matrix
is current`; the script test suite reported `7 tests` and `OK`; formatting,
Clippy, and diff checks passed; Rust tests reported `250 passed`, `6 passed` in
`tests/production_rail_containment.rs`, and `1 passed, 1 ignored` doc tests.

## Explicit exclusions and gates

- BIP-322 Full and Proof-of-Funds forms remain unsupported; P2WSH and Taproot
  script-path/annex, legacy, P2SH, P2A, and future witness-version paths are
  inconclusive or unsupported.
- No Bitcoin Script/Tapscript interpreter or full script execution is included.
- No full Ethereum transaction encoding, EIP-1559, or EIP-712 implementation is
  evidenced.
- No hardware-backed signing, provider verifier, provider/runtime integration,
  vendor collateral, or deployed-hardware evidence is present.
- No external independent cryptographic/security review is present; internal
  branch work is not independent review.
- No release artifact, artifact digest, SBOM/provenance result, or release
  support decision is attached.
- A passing local test suite and canonical vectors do not establish production
  readiness or change the affected capability rows from `unsupported`.

Production authorization paths remain gated by issue #195. Independent review,
release acceptance, and exact artifact evidence remain gated by issue #202.
