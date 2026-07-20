# BIP-110 Alignment

The `bip110_compliant` feature provides fail-closed validation helpers for the
subset of [BIP-110](https://github.com/bitcoin/bips/blob/master/bip-0110.mediawiki)
that the SDK can model without a Bitcoin Script interpreter. It is not a claim
that every BIP-110 consensus rule is implemented by the SDK.

## Modeled limits

The limits are applied to the serialized object in the context where BIP-110
defines the rule:

| Context | Inclusive limit | SDK validation |
| --- | ---: | --- |
| OP_PUSHDATA payload | 256 bytes | `validate_pushdata` and `validate_script_pushdata` |
| Script-argument witness item | 256 bytes | `validate_script_argument_witness_item` |
| Non-OP_RETURN output `scriptPubKey` | 34 bytes | `validate_script_pubkey` |
| Output `scriptPubKey` whose first opcode is OP_RETURN | 83 bytes | `validate_script_pubkey` |
| Taproot control block | 257 bytes | `validate_taproot_control_block` |

The full-script boundaries are inclusive: a 34-byte non-OP_RETURN script is
accepted, as is an 83-byte script whose first opcode is OP_RETURN. The OP_RETURN
classification uses rust-bitcoin's script helpers and is based on the first
serialized opcode.

The generic 256-byte witness-item rule is deliberately not applied to witness
scripts, Tapleaf scripts, or Taproot key-path signatures. Witness scripts are
checked for serialized pushdata and their P2WSH hash, but their total script
size is not treated as a generic push. Tapleaf scripts and control blocks are
checked only in their modeled contexts.

Custom `Bip110Limits` values may be stricter than consensus. `with_limits`
clamps attempts to relax the `256/83/34` maxima; `try_with_limits` rejects such
attempts. The legacy `chunk_count` and `chunk_for_bip110` wrappers retain their
original infallible source signatures and return `0`/an empty result for a
zero-sized configuration without panicking. Use `try_chunk_count` and
`try_chunk_for_bip110` when configuration errors must be surfaced.

## BIP-322 message signing

[BIP-322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki) hashes
the original message as-is with the tagged hash
`SHA256(SHA256("BIP0322-signed-message") || SHA256("BIP0322-signed-message") || message)`.
The virtual `to_spend` transaction pushes only that 32-byte hash in
`OP_0 PUSH32[message_hash]`; it does not push the original message or use the
legacy `Bitcoin Signed Message` payload.

The bridge validates the complete canonical `to_spend` shape and binds every
message-aware `to_sign` constructor to the message hash in `to_spend.scriptSig`.
Messages may therefore be arbitrary length from the perspective of this bridge:
the virtual transaction contains a fixed 32-byte commitment.

Output creation and spend validation are separate. A future or undefined
witness-version `scriptPubKey` can be placed in `to_spend` when its output
limits are compliant. Constructing `to_sign` for that output is rejected in
`bip110_compliant` mode because the bridge does not support spending an
undefined witness version.

### Simple verification matrix

| Address/spend context | Result |
| --- | --- |
| Native P2WPKH, exactly two witness items, strict ECDSA, `SIGHASH_ALL`, matching compressed pubkey hash | Cryptographically verified; returns `Ok(true)` or `Ok(false)` |
| P2TR key-path, one 64/65-byte Taproot signature, `SIGHASH_DEFAULT` or `SIGHASH_ALL` | Cryptographically verified; returns `Ok(true)` or `Ok(false)` |
| P2WSH | Witness structure and script hash are checked where possible, then `Unsupported` because no Script interpreter is present |
| P2TR script-path | Witness structure and the typed control-block leaf version are checked where possible, then `Unsupported` because no Script interpreter is present |
| P2TR annex | The BIP-341 last-item annex rule is recognized and the spend is explicitly `Unsupported`; `bip110_compliant` rejects it during spend construction |
| P2PKH, P2SH, or other legacy output | `Unsupported`; structural BIP-110 compliance does not imply simple-signature support |
| P2A or future/undefined witness version | Output creation may be structurally checked, but spend construction and simple verification are `Unsupported`; never silently accepted |
| Malformed Base64, consensus witness encoding, key, signature, or script structure | `InvalidPayload` |

For supported P2WPKH and P2TR key-path witnesses, a wrong message, address
binding, allowed-signature binding, or cryptographic signature returns
`Ok(false)`. A valid but unsupported spend context never returns `Ok(true)`.

## Ark and BitVM2 segmentation scope

`try_chunk_for_bip110` is a client-side ordered segmentation helper. Feature-
gated regression tests in `src/protocol/ark.rs` and `src/protocol/bitvm2.rs`
verify boundary sizes and exact reassembly order.

The helper is not wired into Ark or BitVM2 production methods: those methods
expose hash/commitment lifecycle APIs rather than serialized Bitcoin
transaction or witness builders. Treating their byte arrays as already-formed
on-chain pushes would apply the wrong consensus context.

## Deliberate scope boundary

The SDK does not implement a complete BIP-110 or Bitcoin Script consensus
validator. It does not execute P2WSH or Tapscript, validate Taproot Merkle
proofs, or model `OP_SUCCESS*` or conditional rules. It recognizes and rejects
Taproot annex-bearing BIP-322 spends, but does not execute annex semantics,
validate UTXO grandfathering, or perform activation/expiry state transitions.
Callers building transactions remain responsible for using a consensus-valid
Bitcoin library or node for rules outside these helpers.

## Canonical references

- [BIP-110: Reduced Data Temporary Softfork](https://github.com/bitcoin/bips/blob/master/bip-0110.mediawiki)
- [BIP-322: Generic Signed Message Format](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki)
- [BIP-322 basic test vectors](https://github.com/bitcoin/bips/blob/master/bip-0322/basic-test-vectors.json)
