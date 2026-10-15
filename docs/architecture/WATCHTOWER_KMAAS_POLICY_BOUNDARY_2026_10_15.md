# Watchtower observations and KMaaS policy boundary

Status: design and acceptance requirements; no runtime enablement. Reconciles the proposals in SDK #544 against the current development implementation. Work remains under #509, #240 and #202.

## Preserved implementation

`src/protocol/bitvm2.rs` already provides versioned instance/commitment/observation identifiers, external chain-observation records, challenge-window validation and an idempotent observation ledger. Reusing an observation identifier for different bytes is rejected. `observe_chain_event` records externally supplied data; recording does not authenticate a chain event or prove broadcast, finality or challenge execution. Challenge submission, status, resolution and forfeit execution remain explicitly unsupported without a qualified provider.

`src/enclave/threshold.rs` retains its existing threshold-signing and share-report contracts. This change adds no spending-limit implementation, hardware policy or production authorization. Local cryptographic rehearsal does not establish independently administered participants or hardware custody.

## Spending-policy acceptance

A future spending-limit adapter must:

- Use a bounded, versioned, typed amount context with exact chain, network, asset/base-unit, operation and policy identity. Missing, malformed, unknown-version, trailing or mismatched data must fail closed whenever a limit is configured.
- Bind the amount to the actual transaction or settlement payload, signer/key identity, canonical request digest and attested policy. A caller-declared eight-byte integer does not establish the transaction amount.
- Reject out-of-range amounts before invoking any signing provider; cover zero, exact-limit, over-limit, overflow, wrong-asset/network and altered-context cases with negative tests.
- Describe SDK-side checks as software preflight. Hardware enforcement requires independently verifiable device/service policy evidence and an attested implementation enforcing the same policy.
- Preserve the existing proof, attestation, replay, key-binding and feature-disabled rejection boundaries; attach exact-artifact independent review before production support.

## Watchtower acceptance

A future watchtower adapter must:

- Keep local observation recording separate from execution and from verified chain status, with APIs and result types that state the evidence scope.
- Derive map keys from canonical typed commitment identifiers, or reject any disagreement with the embedded identifier. Validate instance, chain/network, transaction identifier and challenge-window bindings.
- Reject conflicting observations and unauthorized phase transitions; define durable replay, restart recovery and participant/provider failure behavior.
- Require a qualified runtime provider to construct and broadcast a challenge, then authenticate chain observation/finality before reporting execution success. SDK library code must not acquire network or custody authority merely to satisfy this proposal.

## Reconciliation

The earlier PR also carried stale documentation deletions and policy/PKCS#11 reversions. The reconciled candidate retains the current development source, workflows, policy digests, provider classification, support inventories and research. Earlier commits remain in the branch history. These design requirements preserve the proposed work without treating its unverified behavior as shipped functionality.
