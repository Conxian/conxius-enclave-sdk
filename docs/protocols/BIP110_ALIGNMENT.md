# BIP-110 Compliance and Alignment

This document outlines the consensus limits and implementation patterns utilized by the Conclave SDK to ensure strict compliance with the BIP-110 (Reduced Data Temporary Softfork) rules.

---

## 1. Overview of BIP-110 Rules

BIP-110 introduces temporary, strict limits on data embedded within Bitcoin transactions to discourage non-monetary data storage on-chain while keeping standard monetary transactions fully functional.

| Core Rule | Limit | Description |
|-----------|-------|-------------|
| **Pushdata & Witness** | `256 bytes` | Any OP_PUSHDATA push or witness stack item exceeding 256 bytes is invalid. |
| **OP_RETURN** | `83 bytes` | OP_RETURN scriptPubKeys are restricted to a maximum of 83 bytes. |
| **ScriptPubKey** | `34 bytes` | Standard non-OP_RETURN outputs cannot exceed 34 bytes in size. |

---

## 2. SDK Impact and Architectural Changes

### Feature Flag: `bip110_compliant`
The SDK exposes a `bip110_compliant` feature flag. When enabled:
- Stricter validation is enforced on data and inputs in Bitcoin transaction building.
- BIP-322 signing and verification check data limits.

### BIP-322 Message Signing
- **Issue**: Standard BIP-322 signatures on extremely long messages would require pushing the entire message payload onto the stack, easily violating the 256-byte consensus limit.
- **Alignment Solution**: The SDK includes a `Bip110Validator` inside `src/protocol/bip110.rs`. When `bip110_compliant` is active, messages larger than 252 bytes are identified as requiring segmentation/chunking. The SDK validates that each message chunk is strictly compliant (<= 256 bytes) to protect transactions from consensus rejection.

### Ark / BitVM2 Data Commitment Segmentation
- **Issue**: Under the Ark and BitVM2 optimistic challenge-response systems, state roots, Merkle paths, or fraud proof components (e.g., SNARK proofs or leaf scripts) may generate large byte payloads.
- **Alignment Solution**: The SDK provides utility functions (such as `chunk_for_bip110`) to segment these commitments and proof payloads into compliant chunks of up to 256 bytes. Each chunk remains safe for on-chain inclusion under BIP-110 consensus rules.

---

## 3. Developer Guidance

When building transactions or proving identity with BIP-322, developers should design for compliance:
1. Keep custom messages brief.
2. For any off-chain state commitments or proofs (Ark, BitVM2), segment the payload on the client side using the SDK's chunking utility.
3. Enable the `bip110_compliant` feature flag in `Cargo.toml` to catch violations locally during development and staging:

```toml
[dependencies]
conxius-enclave-sdk = { version = "2.0.12", features = ["bip110_compliant"] }
```
