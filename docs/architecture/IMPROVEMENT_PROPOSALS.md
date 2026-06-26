# Conclave SDK: Improvement Proposals (v2.0.1)

## 1. BIP-322 Universal Message Signing (Hardening)
**Context**: Current implementation in `src/protocol/bip322.rs` uses stubs for virtual transaction construction.
**Proposal**:
- Integrate `rust-bitcoin`'s `SighashCache` and `Transaction` builders to construct the mandatory `to_spend` and `to_sign` transactions.
- Implement full SegWit (v0 and v1) support for proof-of-ownership verification.
- Add support for "Full" BIP-322 verification (not just "Simple").

## 2. FROST DKG Integration
**Context**: `FrostManager` (`src/protocol/frost.rs`) currently lacks the Round 1 Distributed Key Generation (DKG) logic.
**Proposal**:
- Utilize `frost-dalek` or `musig2` (if applicable for Schnorr) to implement non-interactive DKG.
- Implement session state persistence in the `SettlementEngine` to track DKG rounds across multiple SDK instances.

## 3. Fedimint OPR (Oblivious Proof of Reserve)
**Context**: `FedimintAdapter` uses placeholders for e-cash proof generation.
**Proposal**:
- Integrate `fedimint-client-wasm` to perform real blinding and unblinding of e-cash notes.
- Implement a local-first `EcashWallet` that can sync with multiple federations for redundant liquidity.

## 4. Hardware-Bound Certificate Chain Verification
**Context**: `DeviceIntegrityReport` (`src/enclave/attestation.rs`) uses simulated string matching for root trust.
**Proposal**:
- Implement real X.509 certificate parsing for Google StrongBox and AWS Nitro enclaves.
- Add a mandatory `trusted_roots.pem` file to the SDK for production verification.
