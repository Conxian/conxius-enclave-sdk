# FROST Treasury Integration Guide

> **Status: design and operations runbook only — not a production implementation.**
>
> This guide defines the target integration for a SAB 3-of-5 treasury using
> Conxius as the signing mechanism and contract principals as the custody
> layer. It does **not** make the current SDK production-ready for FROST.
>
> In `v2.0.12`, [`src/protocol/frost.rs`](../../src/protocol/frost.rs) is a
> structural/hash placeholder. It does not implement production FROST
> cryptography, RFC 9591-compatible DKG, secure share encryption, real share
> verification, nonce management, or real signature-share aggregation. The
> current `EnclaveManager` surface also lacks secure FROST share storage and
> attestation-bound FROST signing APIs. The
> current [`FrostManager`](../../src/protocol/frost.rs) APIs must not be used
> for treasury key generation or signing. Similarly,
> [`src/protocol/musig2.rs`](../../src/protocol/musig2.rs) wraps an n-of-n
> MuSig2 flow; it is not a 3-of-5 threshold implementation. No production
> treasury should be launched from the APIs described in this repository
> until the acceptance criteria in this guide are implemented and independently
> audited.

## Contents

1. [Scope and non-goals](#scope-and-non-goals)
2. [Authority and custody architecture](#authority-and-custody-architecture)
3. [FROST versus MuSig2](#frost-versus-musig2)
4. [Prerequisites and participant onboarding](#prerequisites-and-participant-onboarding)
5. [Four-stage DKG application ceremony](#four-stage-dkg-application-ceremony)
6. [Safe signing workflow](#safe-signing-workflow)
7. [TEE storage and attestation](#tee-storage-and-attestation)
8. [Key rotation, replacement, and recovery](#key-rotation-replacement-and-recovery)
9. [Proposed future Rust API](#proposed-future-rust-api)
10. [Integration pseudocode](#integration-pseudocode)
11. [Error taxonomy and fail-closed handling](#error-taxonomy-and-fail-closed-handling)
12. [Security considerations](#security-considerations)
13. [Testing and verification matrix](#testing-and-verification-matrix)
14. [Operator checklists](#operator-checklists)
15. [Canonical references](#canonical-references)

## Scope and non-goals

### In scope

This document is the implementation and operations contract for:

- a five-participant, three-signature threshold policy;
- FROST-style distributed key generation and Schnorr signing at the signer
  enclave boundary;
- authenticated, encrypted communication between signer enclaves and an
  untrusted coordinator;
- contract-controlled treasury custody and SAB authority separation;
- signer onboarding, ceremony checkpoints, complaints, aborts, recovery, and
  post-incident evidence; and
- the acceptance tests required before production use.

### Non-goals

This document does not:

- implement FROST, a DKG protocol, a secp256k1 ciphersuite, or a secure key
  store;
- select a universal four-round DKG protocol on behalf of the implementation
  team;
- define contract code, spending caps, DAO policy, or chain-specific fee
  policy;
- authorize a software, simulated, or developer backend in production;
- make the coordinator trusted with key packages, secret shares, or plaintext
  transaction authorization; or
- treat the current `FrostManager` or `MuSig2Session` APIs as an integration
  surface for a treasury.

The selected DKG protocol, ciphersuite, transport profile, hardware platform,
and contract policy must each have an owner, a versioned specification, test
vectors, and an independent review before a production ceremony.

## Authority and custody architecture

### Governing rule

**Conxius is the signing mechanism. Contract principals and vaults are the
custody layer.** The wallet or enclave must not become the sole holder of
treasury authority merely because it can produce a signature. Treasury assets
belong in the appropriate contract-controlled vault or policy principal, and
the signer set authorizes only the actions allowed by that policy.

The treasury wire is therefore:

```text
contract principals / vaults
        │  policy-controlled action
        ▼
untrusted coordinator ── authenticated encrypted messages ── signer enclaves
                                                               │
                                                               └─ sealed FROST share handles
```

The coordinator may route messages, assemble public signing packages, verify
public evidence, and submit a final transaction. It must not receive a
plaintext share, a key package, an enclave export, or enough material to
reconstruct the group secret.

### SAB policy mapping

The canonical operational identifiers come from the SAB wallet control model.
Use the exact identifier in policy manifests and audit evidence.

| Authority / wallet | Quorum | Custody or authority role | Allowed actions | Explicit boundary |
| --- | ---: | --- | --- | --- |
| `TREASURY-VAULT` / `PROTOCOL_VAULTS` | Contract-controlled | Passive custody and fee capture | Inbound collection and rules-based custody | No signer key is the custody authority by itself. |
| `SAB-TREASURY-MS` | 3 of 5 | SAB operational treasury | Approved operational funding and conversion within the configured medium tier | Not the DAO reserve and not the emergency recovery authority. |
| `DAO-TREASURY-MS` | 5 of 7 | Long-term reserve custody | Reserve rebalancing and high-value spends | Separate policy, signer set, and approval path from SAB operations. |
| `BOUNTY-PAYOUT-MS` | 2 of 3 | Contributor and bounty payouts | Capped payout actions | Must not be silently reused as treasury or recovery authority. |
| `PROTOCOL-PAUSE-MS` / `SAB_EMERGENCY_PAUSE_MULTISIG` | 2 of 3 | Emergency guardian | Pause, isolate, and enable-only circuit breakers | Veto-only: it **cannot** unpause, resume, rotate authority, or transfer value. |
| `SAB_EMERGENCY_RECOVERY_MULTISIG` | 3 of 5 or the approved higher recovery quorum | Recovery authority | Unpause, key rotation, role revocation, rollback, and recovery migration | This is the canonical recovery authority. Do not make a single administrator the fallback. |
| `DAO_TIMELOCK` | Contract policy | Root governance and policy control | Policy changes and long-term governance actions | Does not participate in routine execution. |

The shorter name `SAB_EMERGENCY_RECOVERY_MS` may be used in operator prose, but
the canonical policy identifier is `SAB_EMERGENCY_RECOVERY_MULTISIG`.

### Separation requirements

Keep the following separate in policy, code, UI, and audit records:

1. operational treasury spending;
2. DAO reserve management;
3. emergency pause and isolation; and
4. emergency recovery, including unpause and key rotation.

Participant overlap may be approved as a risk decision, but an operational
treasury key package must never implicitly grant pause or recovery powers.
Every action must carry an explicit authority identifier, quorum, spending
tier, contract principal, chain/network, and policy version.

### SAB 3-of-5 participant model

The target operational policy is:

```text
policy_id: SAB-TREASURY-MS
threshold: 3
participants: 5 unique signer identities
signer backend: hardware-backed enclave only
custody: contract principal / vault
coordinator: untrusted message router and aggregator
```

The policy must be enforced at both the coordinator and each signer enclave.
A coordinator check is advisory; an enclave must independently reject a
request that has the wrong policy, participant set, quorum, transaction digest,
chain, contract principal, spending tier, or authority.

## FROST versus MuSig2

FROST and MuSig2 both produce Schnorr-style aggregate signatures, but they
solve different authorization problems.

| Property | FROST | MuSig2 | Treasury consequence |
| --- | --- | --- | --- |
| Authorization model | `t`-of-`n` threshold | All configured participants (`n`-of-`n`) | A 3-of-5 policy requires FROST or another true threshold protocol. |
| Key setup | DKG or an approved distributed key-generation/resharing protocol | Key aggregation over participant public keys plus MuSig2 session state | MuSig2 does not turn five keys into a three-signature policy. |
| Signing state | Per-signer share, per-session binding factors, and one-time nonces | Per-signer secret/public nonces and partial signatures | Both require nonce uniqueness and strict transcript binding. |
| Failure tolerance | Can sign when at least `t` qualified participants are available | Cannot complete if any required participant is unavailable | Do not advertise MuSig2 as a substitute for threshold availability. |
| Current repository status | Structural/hash placeholder only | Existing wrapper is n-of-n | Neither current API is a production SAB treasury implementation. |
| Appropriate use here | Future SAB 3-of-5 signing layer | Only an explicitly approved n-of-n policy or a different use case | Select by policy, not by the fact that both use Schnorr signatures. |

### Bitcoin BIP340/BIP341 compatibility caveat

RFC 9591 specifies FROST signing abstractions and ciphersuite interfaces; it
does not automatically define a Bitcoin-compatible secp256k1 profile or a
universal four-round DKG. Bitcoin integration must be specified and tested as
an explicit profile:

- use an approved secp256k1 FROST ciphersuite with a versioned identifier and
  published test vectors;
- produce the exact BIP340 x-only public key and 64-byte Schnorr signature
  encoding expected by Bitcoin verification;
- bind the FROST group key, participant set, policy, message, and transcript to
  the BIP340 challenge calculation; and
- for a Taproot key-path spend, bind the signing package to the exact BIP341
  output key, optional merkle root, taproot tweak, network, transaction, input,
  and sighash. The signer must verify the resulting signature against the
  output key that will appear on-chain.

An RFC 9591 signature that is valid for another ciphersuite is not evidence of
BIP340 compatibility. A locally produced 64-byte value is not a Bitcoin
signature until an independent BIP340 verifier accepts it for the exact
transaction digest and x-only key. No ad hoc XOR, hash, or string-concatenation
operation is an acceptable substitute for the field arithmetic and challenge
rules of the selected protocol.

## Prerequisites and participant onboarding

Do not schedule the ceremony until all of the following are complete.

### Policy and custody prerequisites

- [ ] The SAB policy manifest names `SAB-TREASURY-MS`, threshold `3`, exactly
      five participant identifiers, the supported chain/network, contract
      principal, spending limits, and policy version.
- [ ] The custody system of record names the vault or contract principal; no
      personal wallet is the source of custody authority.
- [ ] `DAO-TREASURY-MS`, pause, payout, and
      `SAB_EMERGENCY_RECOVERY_MULTISIG` policies are separately documented.
- [ ] The selected FROST ciphersuite, DKG/resharing protocol, wire format,
      transport profile, and BIP340/BIP341 integration profile have immutable
      version identifiers.
- [ ] An independent reviewer has approved the threat model, quorum rules,
      spending limits, and recovery authority.

### Participant requirements

Every participant must have:

1. a unique, non-reassignable signer identity and an approved role;
2. a supported hardware-backed enclave or TEE with a known measurement,
   firmware policy, and secure clock behavior;
3. a locally generated device key and an attestation identity;
4. an authenticated operator channel that does not expose the share or key
   package to the application UI;
5. a secure path to receive ceremony metadata and encrypted share ciphertexts;
6. a recovery contact and a documented lost-device process; and
7. two-person verification of the participant identity, device fingerprint,
   policy manifest, and ceremony session identifier.

The operator may approve a public fingerprint, attestation report, or status
receipt. The operator must never approve a plaintext share, export a key
package, or copy an enclave secret into a ticket, terminal, clipboard, or
backup file.

### Environment and dry-run requirements

- Use a dedicated ceremony session and a clean, version-pinned coordinator.
- Verify all five participants can independently validate the policy manifest
  and the selected ciphersuite.
- Run a testnet or offline vector dry run with the same message and transcript
  framing used in production.
- Exercise an abort, a complaint, a stale-attestation rejection, a lost
  participant, and a coordinator restart before the production ceremony.
- Confirm that production mode rejects software and simulated backends. Test
  doubles may be used only in isolated test builds and must be visibly marked.
- Record the ceremony operator, reviewer, build identifier, attestation policy,
  and evidence destination before Stage 1 begins.

## Four-stage DKG application ceremony

### Protocol note

The four stages below are an **application ceremony** for this integration. They
are not a claim that RFC 9591 defines a universal four-round DKG. RFC 9591
defines FROST signing; the implementation team must select and audit a concrete
DKG protocol. The selected protocol may require additional messages, complaint
rounds, retries, or aborts. This runbook groups the user-visible lifecycle into
four stages:

1. commitments and participant registration;
2. encrypted share delivery;
3. verification and qualification; and
4. local key-package finalization.

Complaint and abort handling is part of every stage. A UI that shows four
green steps while the underlying DKG has unresolved complaints is unsafe.

### Transcript and message invariants

Every ceremony message must be authenticated and bound to:

```text
ceremony_id
policy_id and policy_version
participant_set and signer_id
selected DKG protocol and FROST ciphersuite
chain/network and custody principal
stage and monotonic sequence number
previous transcript hash and current transcript hash
message expiry and attestation freshness window
```

The transcript is an append-only, hash-chained record. Signer enclaves must
verify the transcript hash before accepting a message. The coordinator may
store message envelopes, ciphertexts, and hashes, but it must not store
plaintext shares or exportable key packages. Any equivocation, missing
sequence, stale message, unexpected participant, or transcript fork is an
abort condition until independently resolved.

### Stage 1 — commitments and participant registration

**Purpose:** establish the session, participant set, public commitments, proof
of knowledge, transport identities, and attestation baseline.

#### Signer-enclave actions

1. Verify the signed policy manifest and exact five-member participant set.
2. Verify the coordinator's fresh attestation or authenticated identity if the
   coordinator is required by the deployment profile; do not grant it secret
   access merely because it is attested.
3. Generate DKG secret polynomial material and any required ephemeral
   transport state inside the enclave using an approved CSPRNG.
4. Produce only the public commitment package, proof-of-knowledge material,
   signer identity, attestation evidence, and transcript-bound metadata.
5. Seal or retain the secret ceremony state locally; it must not enter the
   application process or coordinator memory.

#### UI checkpoint

The operator should see:

- the ceremony ID and policy fingerprint;
- the five expected participant identities and their attestation status;
- the ciphersuite/DKG versions;
- the commitment receipt and transcript hash; and
- an explicit **Continue / Abort** decision.

The UI must not show a secret polynomial, a share, a key package, or a
copyable private value. A participant is not qualified merely because its
commitment arrived; the commitment and proof must verify against the session.

#### Abort conditions

Abort on a duplicate or unknown signer, invalid proof of knowledge, stale or
wrong-device attestation, policy mismatch, transcript mismatch, unsupported
ciphersuite, missing commitment, or any attempt to export secret ceremony
state.

### Stage 2 — encrypted share delivery

**Purpose:** deliver each participant's encrypted share to its intended
recipient without giving the coordinator plaintext access.

#### Transport requirements

- Use authenticated encrypted transport with mutual participant identity
  binding and an approved AEAD profile.
- Bind ciphertext metadata to the ceremony, sender, recipient, stage,
  sequence, transcript hash, and expiry.
- Route ciphertexts through the coordinator only as opaque envelopes, or use a
  direct authenticated channel where the deployment requires it.
- Keep delivery acknowledgements separate from share plaintext. An
  acknowledgement proves receipt, not validity.

#### Signer-enclave actions

1. Evaluate the selected DKG polynomial for each other participant as required
   by the selected protocol.
2. Encrypt the recipient-specific share inside the sender enclave using the
   approved recipient-bound transport/encryption profile.
3. Sign the envelope metadata and send it to the recipient through the
   coordinator or direct channel.
4. Zeroize transient plaintext share material after encryption and retain only
   the minimum sealed state required by the DKG protocol.

#### UI checkpoint

Show per-participant delivery state (`created`, `authenticated`, `delivered`,
`acknowledged`) and the envelope hash. Do not show or allow download of the
plaintext share. A missing delivery, duplicate envelope, wrong recipient, or
expired message pauses the ceremony; it does not trigger an unreviewed resend.

#### Abort and complaint handling

A recipient may file a complaint when decryption fails, the sender identity is
wrong, the envelope is malformed, the share does not match the commitment, or
the sender equivocates. The complaint must include an evidence hash and
transcript position, never the plaintext share. The selected DKG protocol
determines whether the sender can correct the message, whether the participant
is disqualified, or whether the entire ceremony must abort.

### Stage 3 — verification and qualification

**Purpose:** have each recipient enclave verify received material and produce a
deterministic qualified set.

#### Recipient verification

The recipient enclave must verify, as applicable to the selected DKG protocol:

- authenticated sender and recipient identities;
- the commitment proof of knowledge;
- ciphertext integrity and decryption result;
- share evaluation against the sender's public commitments;
- participant, policy, ciphersuite, chain, and transcript binding;
- sequence, freshness, and anti-replay state; and
- any consistency, zero-knowledge, or complaint proof required by the DKG.

The coordinator may collect signed verification receipts and evidence hashes,
but it must not replace recipient-side cryptographic verification.

#### Qualification rule

The implementation must define a deterministic qualification algorithm before
the ceremony. At minimum:

- every included signer has a valid commitment and required proof;
- every included signer has passed attestation and policy checks;
- every required share relation has verified or been resolved under the
  selected DKG complaint rules; and
- the qualified set is large enough for the configured threshold and any
  protocol-specific requirements.

For `SAB-TREASURY-MS`, fewer than three qualified participants is a failed
ceremony. A coordinator cannot silently drop a participant to make an
inconsistent result appear successful.

#### UI checkpoint

The operator sees a signed qualification report containing:

- qualified and disqualified signer IDs;
- reason codes and evidence hashes for each complaint;
- the final participant set and threshold;
- the transcript root;
- attestation freshness and build measurements; and
- a required independent reviewer approval.

The report must clearly say **Abort**, **Continue to finalization**, or
**Protocol-specific remediation required**. Never display “ready” while a
complaint is unresolved.

### Stage 4 — local key-package finalization

**Purpose:** derive and seal each participant's local share/key package and
publish only public group information.

#### Signer-enclave actions

1. Re-verify the final transcript root, qualified set, policy, and ciphersuite.
2. Derive the participant's FROST key package using the selected protocol.
3. Derive or verify the group public key and its Bitcoin x-only/taproot form,
   if Bitcoin is the target chain.
4. Seal the secret share and key package behind an opaque local handle bound to
   the device, policy, signer identity, and attestation measurement.
5. Zeroize transient DKG material and reject any API that attempts to export
   the plaintext key package.
6. Return a signed finalization receipt containing only public fingerprints,
   handle ID, transcript root, policy version, attestation evidence, and
   status.

#### Completion checkpoint

The ceremony is complete only when all required participants have locally
finalized, the group public key is independently verified, the custody
principal is configured, the recovery authority is recorded, and the evidence
package is sealed. The coordinator must not receive `Vec<KeyPackage>` or any
equivalent collection of secret key material.

If any signer cannot finalize, the result is an abort or a protocol-approved
reshare—not a coordinator-side reconstruction or manual copy of its package.

## Safe signing workflow

The signing flow below applies after a successful ceremony and a verified
policy manifest. It assumes the coordinator is untrusted.

### 1. Admit and canonicalize the request

The policy engine canonicalizes the exact action before any signer generates a
nonce:

- transaction or contract-call bytes;
- chain and network;
- input/output set, fee, and amount limits;
- contract principal and authority identifier;
- BIP340 message digest and, for Taproot, BIP341 sighash and output key;
- policy ID/version, signer set, threshold, and expiry;
- session ID and request ID; and
- current pause/recovery state.

Every signer must independently recompute or verify the canonical digest. A
human-readable transaction summary is useful for approval but is never the
cryptographic message.

### 2. Select qualified signers

The coordinator requests at least three distinct, currently qualified signer
enclaves. Each enclave verifies:

- the signer is in the approved policy set;
- the request has not expired or been replayed;
- the attestation is fresh and matches the approved identity/build;
- the action is allowed for the authority and spending tier; and
- the exact transcript and request hash are the ones displayed to the
  operator.

The coordinator may choose a subset, but it may not change the threshold,
policy, or message to make an otherwise invalid request pass.

### 3. Generate one-time nonce commitments

Each selected signer generates the FROST signing nonce inside its enclave with
an approved CSPRNG and returns only the public nonce commitment. The nonce is
bound to the session, request, signer, transcript, and message. The enclave
must record a spent/committed state so that a nonce cannot be reused or
associated with another message.

Never:

- generate a signing nonce in application memory;
- derive a nonce from a predictable timestamp, request counter, or reused seed;
- accept a caller-provided secret nonce; or
- retry a failed signing operation with the same nonce unless the selected
  protocol explicitly proves that the retry is safe.

Nonce reuse is a key-compromise event and must fail closed.

### 4. Build and approve the signing package

The coordinator combines public nonce commitments and constructs a signing
package containing:

```text
session_id and request_id
policy_id, version, threshold, and qualified signer IDs
FROST ciphersuite and protocol version
group public key and Bitcoin/taproot output key, if applicable
canonical message digest / transaction sighash
nonce commitments and protocol binding factors
transcript root and package hash
expiry, chain/network, authority, and spending tier
```

Each signer enclave verifies the package from scratch. A package with a
duplicate signer, missing commitment, changed message, changed output key,
wrong policy, stale transcript, or unknown ciphersuite is rejected.

### 5. Produce local signature shares

Each signer calls a local enclave operation with an opaque key-package handle
and the verified signing package. The enclave:

1. checks policy, attestation, freshness, anti-replay state, and nonce state;
2. computes the FROST signature share using the sealed share and one-time
   nonce;
3. marks the nonce as consumed before returning success; and
4. returns a signature share plus public verification metadata.

The output is not a key package, secret share, or exportable private key. The
coordinator must not be able to ask a signer to “sign this arbitrary share”
outside a verified package.

### 6. Verify and aggregate at the coordinator

The coordinator verifies each share against the public commitments, signer
identity, package, and group public key. It rejects invalid, duplicate,
replayed, or out-of-policy shares. It may aggregate only after at least three
valid, distinct shares are present.

The coordinator is not trusted to skip verification. A production deployment
should provide an independent verifier or an independently reproducible
verification service for the aggregate result. The coordinator never receives
or aggregates `Vec<KeyPackage>`; it handles public packages, opaque signer
responses, and signature shares only.

### 7. Verify the final Bitcoin signature

Before broadcast, an independent BIP340 verifier must verify the final
signature against the exact x-only group/output key and message digest. For a
Taproot transaction, independently verify the BIP341 transaction, output key,
merkle-root/tweak inputs, script-path/key-path choice, and sighash. A successful
FROST aggregation without a successful Bitcoin verification is a failure.

### 8. Broadcast handoff and evidence

Only after final verification may the transaction be handed to a broadcast
service. Record public evidence:

- request and transaction IDs;
- policy and authority identifiers;
- group public key/address fingerprint;
- selected signer IDs and attestation evidence references;
- transcript, package, and final signature hashes;
- verification results and timestamps; and
- broadcast result and on-chain transaction ID.

Do not record secret shares, key packages, plaintext DKG messages, secret
nonces, or sensitive enclave memory. If encrypted envelopes are retained for
audit, protect them as sensitive material and retain only the minimum required
by the approved evidence policy.

## TEE storage and attestation

### Share and key-package storage

The production implementation must provide a signer-local storage boundary:

- secret shares and key packages are generated and used inside the enclave;
- application code receives opaque handles, not secret bytes;
- sealed storage is bound to signer identity, policy ID/version, ciphersuite,
  device state, and an anti-rollback counter;
- unseal requires a fresh, policy-bound attestation and local authorization;
- memory containing secret material is zeroized on all success, failure, abort,
  and process-shutdown paths where the platform permits; and
- backup is encrypted, access-controlled, and never a plaintext share export.

The implementation must fail closed if sealing, unsealing, anti-rollback, or
zeroization guarantees are unavailable. A database row containing a serialized
`KeyPackage` is not an acceptable secure store.

### Attestation requirements

For ceremony and signing, attestation must prove at least:

1. hardware-backed execution at the required trust tier;
2. approved signer identity and device binding;
3. approved enclave measurement and build provenance;
4. policy/ciphersuite support;
5. freshness through a verifier challenge and expiry window; and
6. no revoked, rolled-back, or unsupported state.

The challenge must bind the ceremony or signing session, policy, transcript or
package hash, and request expiry. Attestation is evidence about the enclave;
it does not make an untrusted coordinator trusted and does not replace share
verification.

### Production backend gating

Production treasury signing must reject software, simulated, mock, and
development backends. Those backends may support deterministic unit tests only
when the build and test output make the substitution explicit. A “valid” test
attestation generated from a software seed is not production evidence.

### Audit evidence without secret egress

An acceptable evidence record includes hashes, signed receipts, public keys,
attestation reports, policy decisions, version identifiers, and pass/fail
reason codes. It must not include:

- plaintext shares or key packages;
- secret nonces or DKG polynomial coefficients;
- private transport keys;
- clipboard/export files from the enclave; or
- logs that reveal enough correlated material to reconstruct a secret.

Auditors need reproducible verification and an evidence manifest, not access
to the group secret.

## Key rotation, replacement, and recovery

### Planned rotation

Rotate when a policy, ciphersuite, device fleet, signer role, or compromise
assessment requires it. A rotation plan must state whether it is:

- **refresh/resharing:** retain the approved group public key while changing
  participant shares using an audited protocol; or
- **new key generation:** create a new group key and update the contract
  principal, address, policy, and downstream integrations.

The current SDK does not implement either production flow. Do not simulate
rotation by serializing or copying a full secret into a coordinator. The
selected resharing protocol must have its own complaint, qualification,
attestation, and recovery tests.

### Participant replacement

For a planned replacement:

1. pause or restrict the affected authority according to policy;
2. revoke the old signer identity and device attestations;
3. run the approved reshare or new-key ceremony with the replacement;
4. verify the new qualified set and group key/address;
5. update contract and policy principals through the recovery authority or
   `DAO_TIMELOCK` as required; and
6. verify that the removed participant cannot sign under the old or new policy.

Do not add a participant by handing it an existing share. That bypasses the
DKG/resharing security model and creates untracked authority.

### Lost or unavailable share

If one or two operational participants are unavailable but at least three
qualified shares remain, follow the approved continuity policy and document the
event. If fewer than three remain, the operational policy cannot sign. The
correct response is an approved reshare, recovery migration, or contract-level
fallback—not reconstructing the full secret in one place.

A lost device is not proof that its share was destroyed. Revoke its identity,
attestation, transport keys, and policy membership before reshare. Treat
possible exfiltration as compromise and use the recovery plan immediately.

### Emergency recovery drill

The recovery runbook must be exercised before launch and at the defined review
interval:

1. a guardian quorum uses `SAB_EMERGENCY_PAUSE_MULTISIG` only to pause or
   isolate the affected path;
2. the pause authority cannot unpause or transfer value;
3. `SAB_EMERGENCY_RECOVERY_MULTISIG` authenticates the recovery decision;
4. the recovery authority rotates, revokes, or migrates the affected signer
   policy without reconstructing a full secret;
5. `DAO_TIMELOCK` is used where policy or long-term governance changes require
   it; and
6. independent reviewers verify the before/after principals, permissions,
   public keys, contract events, and evidence manifest.

No single administrator, developer key, or coordinator may unpause, move
value, or restore signer authority as an undocumented emergency shortcut.

### Authority-separation drill assertions

The recovery test must prove that:

- pause quorum cannot unpause;
- pause quorum cannot transfer value;
- operational treasury quorum cannot rotate recovery authority unless the
  contract policy explicitly grants it;
- recovery quorum cannot silently change DAO policy;
- a revoked signer cannot participate in a new session; and
- all recovery actions have a signed, replay-protected evidence trail.

## Proposed future Rust API

> **Not implemented.** The following is an API design sketch for a future
> production implementation. It is intentionally not compatible with the
> current structural `FrostManager` APIs and must not be copied into a caller
> expecting it to compile against `v2.0.12`.

### Design rules

- Secret shares and key packages are signer-local opaque handles.
- The coordinator sees public ceremony packages and signature shares only.
- No coordinator method accepts `Vec<KeyPackage>` or any equivalent secret
  collection.
- Every operation carries policy, session, transcript, ciphersuite, and
  attestation context.
- Error results are fail-closed and distinguish retry-safe transport failures
  from cryptographic or policy failures.

```rust,ignore
// Proposed/future API — illustrative only; not implemented in v2.0.12.

pub struct CeremonyHandle([u8; 32]);
pub struct KeyPackageHandle([u8; 32]); // valid only inside one signer enclave
pub struct SigningSessionHandle([u8; 32]);
pub struct PolicyId([u8; 32]);

pub struct FrostPolicy {
    pub policy_id: PolicyId,
    pub threshold: u16,       // 3
    pub participant_ids: Vec<SignerId>, // exactly 5
    pub ciphersuite: CiphersuiteId,
    pub chain: ChainId,
    pub custody_principal: PrincipalId,
}

pub trait EnclaveFrostSigner {
    fn begin_ceremony(
        &self,
        policy: FrostPolicy,
        attestation_challenge: &[u8],
    ) -> Result<(CeremonyHandle, PublicCommitmentPackage), FrostError>;

    fn accept_encrypted_share(
        &self,
        ceremony: &CeremonyHandle,
        envelope: EncryptedShareEnvelope,
    ) -> Result<VerificationReceipt, FrostError>;

    fn finalize_key_package(
        &self,
        ceremony: CeremonyHandle,
        qualification: QualificationReport,
    ) -> Result<(KeyPackageHandle, PublicKeyReceipt), FrostError>;

    fn begin_signing(
        &self,
        key_package: &KeyPackageHandle,
        request: CanonicalSigningRequest,
        attestation_challenge: &[u8],
    ) -> Result<(SigningSessionHandle, PublicNonceCommitment), FrostError>;

    fn sign_share(
        &self,
        session: SigningSessionHandle,
        package: VerifiedSigningPackage,
    ) -> Result<SignatureShareReceipt, FrostError>;
}

pub trait UntrustedCoordinator {
    fn collect_commitments(
        &self,
        packages: Vec<PublicCommitmentPackage>,
    ) -> Result<CommitmentManifest, CoordinatorError>;

    fn route_encrypted_shares(
        &self,
        envelopes: Vec<EncryptedShareEnvelope>,
    ) -> Result<DeliveryManifest, CoordinatorError>;

    fn aggregate_signature_shares(
        &self,
        package: VerifiedSigningPackage,
        shares: Vec<SignatureShareReceipt>,
    ) -> Result<AggregatedSignature, CoordinatorError>;
}
```

The `UntrustedCoordinator` sketch intentionally accepts public packages and
signature-share receipts, not `KeyPackageHandle` values or serialized secret
material. A real implementation must define serialization, memory ownership,
zeroization, attestation verification, ciphersuite arithmetic, transport
authentication, and protocol-specific DKG/complaint behavior before exposing
an API.

## Integration pseudocode

> **Pseudocode only.** This example cannot be compiled against the current
> repository and must not be mistaken for a supported API.

```text
// Coordinator: public metadata and opaque envelopes only.
policy = load_signed_policy("SAB-TREASURY-MS", threshold=3, participants=5)
ceremony = coordinator.open_ceremony(policy, ciphersuite, dkg_protocol)

for signer in policy.participants:
    commitment = signer_enclave.begin_ceremony(
        ceremony.id,
        policy,
        fresh_attestation_challenge(ceremony.transcript_hash),
    )
    coordinator.record_public_commitment(commitment)

for sender in policy.participants:
    for recipient in policy.participants excluding sender:
        envelope = sender_enclave.create_recipient_bound_ciphertext(
            ceremony,
            recipient.transport_identity,
        )
        coordinator.route_opaque(envelope)

for recipient in policy.participants:
    receipt = recipient_enclave.verify_received_messages(ceremony)
    coordinator.record_verification_receipt(receipt)

qualification = coordinator.build_deterministic_qualification_report()
require independent_reviewer_approval(qualification)

for signer in qualification.qualified_signers:
    // The returned handle remains inside this signer enclave.
    signer_enclave.finalize_key_package(ceremony, qualification)

request = canonicalize_transaction(
    transaction,
    chain,
    custody_principal,
    authority="SAB-TREASURY-MS",
)
require policy_engine.allows(request)

selected = coordinator.select_at_least_three_fresh_attested_signers(request)
for signer in selected:
    signer_enclave.begin_signing(
        local_key_package_handle,
        request,
        fresh_attestation_challenge(request.hash),
    ) // returns public nonce commitment only

package = coordinator.build_signing_package(
    request,
    public_nonce_commitments,
    transcript_root,
)

for signer in selected:
    share = signer_enclave.sign_share(local_session_handle, package)
    coordinator.verify_share(share, package)

signature = coordinator.aggregate_verified_shares(package, valid_shares)
require independent_bip340_verify(signature, request.x_only_output_key, request.sighash)
require independent_bip341_transaction_verify(transaction, signature)
broadcast_service.submit(transaction)
```

## Error taxonomy and fail-closed handling

The implementation should expose stable, non-secret reason codes. Error text
must not include key material, plaintext shares, secret nonces, or sensitive
transport details.

| Error class | Examples | Required handling |
| --- | --- | --- |
| `PolicyMismatch` | Wrong threshold, participant set, authority, principal, chain, or spending tier | Reject; do not retry without a new approved request. |
| `SessionBindingFailure` | Wrong ceremony/signing session, transcript fork, request hash, or ciphersuite | Abort the session and preserve evidence. |
| `AuthenticationFailure` | Unknown signer, invalid transport identity, bad envelope signature | Reject and alert; never fall back to unauthenticated transport. |
| `AttestationFailure` | Stale, revoked, wrong measurement, software backend, or wrong signer identity | Fail closed; revoke or quarantine the signer as policy requires. |
| `CommitmentFailure` | Missing, duplicate, malformed, or invalid commitment/PoK | Abort or apply the selected DKG complaint rule; no silent substitution. |
| `ShareVerificationFailure` | Decryption failure, invalid evaluation, bad proof, wrong recipient | File an evidence-only complaint and abort or disqualify per protocol. |
| `QualificationFailure` | Fewer than three qualified participants or unresolved complaint | Abort; do not lower the threshold. |
| `ReplayFailure` | Reused message, package, attestation, nonce commitment, or request ID | Reject and mark the session as suspicious. |
| `NonceStateFailure` | Nonce unavailable, already committed, already spent, or rollback detected | Fail closed; never reuse or regenerate from the same secret state. |
| `SigningPolicyFailure` | Local signer rejects value, pause state, expiry, or operator approval | Reject; coordinator cannot override local policy. |
| `SignatureShareFailure` | Invalid, duplicate, or mismatched signature share | Exclude and investigate; aggregate only valid distinct shares. |
| `AggregationFailure` | Threshold not met, bad binding factors, unsupported ciphersuite | Reject final signature; no broadcast. |
| `BitcoinVerificationFailure` | BIP340/BIP341 verification, key, tweak, or sighash mismatch | Reject and do not broadcast. |
| `StorageFailure` | Seal, unseal, anti-rollback, or zeroization failure | Disable signer; require recovery procedure. |
| `RecoveryAuthorityFailure` | Pause authority attempts unpause/value transfer or wrong recovery quorum | Reject and alert; preserve the separation boundary. |
| `TransportFailure` | Timeout, duplicate delivery, coordinator restart, unavailable peer | Retry only if the protocol marks the operation retry-safe and nonce-safe. |

### Retry rules

Only transport operations that have not consumed a nonce or changed protocol
state may be retried automatically. A signing or DKG operation with uncertain
nonce state must be quarantined and resolved by the signer enclave. Never “try
again” by replaying a signing package or generating a second response from an
unknown nonce state.

## Security considerations

| Threat | Mitigation | Required evidence / test |
| --- | --- | --- |
| Malicious coordinator changes the message or signer set | Every signer recomputes policy, transcript, package, and message binding locally | Coordinator-equivocation and altered-package tests. |
| Rogue participant contributes an invalid key | Proofs of knowledge, commitment/share verification, deterministic qualification, and complaint handling | Invalid proof/share and disqualification vectors. |
| Coordinator or network reads a share | Recipient-bound authenticated encryption; enclave-local decryption; no plaintext logging | Transport inspection and secret-egress test. |
| Replay of DKG or signing messages | Session IDs, sequence numbers, transcript hashes, expiry, attestation freshness, and replay cache | Replay, stale-message, and coordinator-restart tests. |
| FROST nonce reuse leaks a share | CSPRNG, signer-local nonce state, spent markers, anti-rollback, and fail-closed uncertainty handling | Deliberate nonce-reuse and rollback tests. |
| One enclave is compromised | Threshold policy, attestation/revocation, participant diversity, key rotation, and no single-admin recovery | Compromised-signer and replacement drill. |
| Software backend is used in production | Build-time and runtime backend gating; attestation must prove hardware tier | Software/simulated backend rejection test. |
| Stale or forged attestation | Fresh challenge bound to policy/session/package, identity and measurement allowlist | Freshness, identity, revocation, and wrong-measurement tests. |
| Sealed share rollback or backup cloning | Device-bound sealing, monotonic state, anti-rollback, and signer identity binding | Rollback and cloned-backup tests. |
| Secret leakage through logs, UI, or telemetry | Opaque handles, redaction, no plaintext export, secret-scanning review, and memory hygiene | Log/UI/telemetry inspection and secret-egress audit. |
| MuSig2 is incorrectly presented as 3-of-5 | Policy-to-protocol mapping rejects n-of-n for threshold policy | Policy selection and 2-of-5/3-of-5 boundary tests. |
| Aggregate signature is not a Bitcoin signature | Independent BIP340 and BIP341 verification against exact transaction data | Mainnet-compatible and negative Bitcoin vectors. |
| Pause guardian abuses recovery powers | Pause is veto-only; recovery and unpause belong to `SAB_EMERGENCY_RECOVERY_MULTISIG` | Authority separation and contract permission tests. |
| Single administrator recovers a treasury | Separate recovery quorum, contract principals, and no full-secret reconstruction | Lost-share and emergency recovery drill. |
| Signer availability is censored | Three qualified signers can complete; coordinator can be replaced; public transcript enables handoff | Coordinator replacement and 3/5 availability tests. |
| Supply-chain or build substitution | Pinned dependencies, reproducible build evidence, approved measurements, and independent audit | Build provenance and attestation measurement review. |

The security posture is fail closed. A degraded mode may preserve public
read-only status and evidence collection, but it must not weaken quorum,
attestation, message binding, nonce safety, or custody authority.

## Testing and verification matrix

The current repository does not satisfy the production rows below. Existing
structural tests in `src/protocol/frost.rs` demonstrate input-shape and hash
placeholder behavior only; they are not evidence of FROST cryptographic
correctness, secure DKG, or Bitcoin-compatible signing.

| Issue requirement / acceptance area | Current status in `v2.0.12` | Production acceptance criteria |
| --- | --- | --- |
| Signer onboarding guide | ✅ Documented here | Five participants, identity and hardware enrollment, attestation, operator approval, and lost-device flow are executable and reviewed. |
| Key ceremony step-by-step | ✅ Design documented here | Four application stages, UI checkpoints, authenticated transcript, complaint/abort behavior, and local finalization are implemented and demonstrated. |
| Signing workflow | ✅ Design documented here | Three qualified enclaves produce valid shares without key-package egress; coordinator remains replaceable and untrusted. |
| Emergency recovery procedures | ✅ Runbook documented here | Pause, recovery, rotation, unpause, and evidence paths are exercised with the canonical authority identifiers. |
| Developer API reference | ⚠️ Proposed only | Opaque-handle production API exists, is versioned, documented, audited, and rejects secret material at the coordinator boundary. |
| Integration example | ⚠️ Pseudocode only | A non-production example is clearly marked until a compiling, audited implementation exists; production examples must use the future API, not current placeholders. |
| Error handling | ✅ Taxonomy documented; implementation missing | Stable reason codes, fail-closed behavior, safe retry rules, redaction, and negative tests cover every listed class. |
| Security considerations | ✅ Threat model documented here | Independent review confirms no secret egress, no software production backend, no single-admin recovery, and no full-secret reconstruction. |
| FROST DKG functional test | ❌ Not implemented | RFC/ciphersuite vectors, DKG qualification, encrypted delivery, complaint/abort, transcript binding, and local finalization pass on five independent signers. |
| MuSig2 signing test | ⚠️ Existing wrapper is n-of-n only | Test the supported n-of-n MuSig2 path separately; explicitly prove it is not accepted for `SAB-TREASURY-MS` 3-of-5. |
| TEE key storage verification | ❌ No FROST share-storage API | Share/key-package handles remain enclave-local; sealing, anti-rollback, attestation binding, zeroization, and software-backend rejection pass. |
| Emergency recovery drill | ❌ Not implemented | Pause is veto-only; recovery quorum rotates/revokes/unpauses through the canonical recovery authority; no single admin can move value or reconstruct the secret. |
| Independent security audit | ❌ Required before production | Audit covers DKG, ciphersuite arithmetic, nonce state, transport, attestation, storage, authority separation, Bitcoin integration, and recovery. |
| RFC and ciphersuite vectors | ❌ Not implemented | Published vectors pass exactly, including invalid encodings, identity handling, binding factors, and negative cases for the selected secp256k1/BIP340 profile. |
| Threshold boundaries | ❌ Not implemented | 2 valid shares fail; 3 valid distinct shares succeed; 4 and 5 succeed; duplicates and unknown IDs fail; fewer than 3 qualified participants abort. |
| Invalid share and complaint handling | ❌ Not implemented | Invalid share, proof, commitment, recipient, and equivocation cases produce evidence-only complaints and deterministic abort/disqualification. |
| Replay and nonce reuse | ❌ Not implemented | Replayed transcript/package/attestation/nonce is rejected; uncertain nonce state disables signing rather than retrying unsafely. |
| Attestation | ⚠️ Generic SDK tests only | Fresh identity- and measurement-bound hardware attestation is required for ceremony and signing; stale, revoked, wrong-device, and software reports fail. |
| Bitcoin verification | ❌ Not implemented for FROST | Independent BIP340 verification succeeds for the exact x-only key and digest; BIP341 key-path/tweak/sighash and negative transaction cases pass. |
| Recovery and participant replacement | ❌ Not implemented | Audited refresh/reshare or new-key flow handles lost, revoked, and replaced participants without full-secret reconstruction. |

### Minimum 3-of-5 acceptance set

Before enabling value-bearing production actions, the implementation must
demonstrate all of the following in an isolated environment and in a reviewed
hardware deployment:

- exactly five enrolled participants and threshold three;
- successful signing with every valid 3-of-5 subset;
- successful signing with 4-of-5 and 5-of-5 subsets;
- rejection with every 2-of-5 subset, duplicate shares, unknown IDs, and
  malformed packages;
- invalid commitment, proof, encrypted share, signature share, transcript,
  attestation, and Bitcoin transaction cases;
- replay and nonce-reuse rejection across restart, retry, and coordinator
  replacement;
- software/simulated backend rejection and fresh hardware attestation;
- emergency pause/recovery authority separation;
- lost-share, revocation, reshare, and recovery evidence; and
- independent verification of the final BIP340/BIP341 result.

## Operator checklists

### Ceremony checklist

- [ ] Confirm the signed `SAB-TREASURY-MS` policy, threshold `3`, five signer
      IDs, contract principal, chain/network, and spending tier.
- [ ] Confirm the recovery authority is
      `SAB_EMERGENCY_RECOVERY_MULTISIG` and pause is veto-only.
- [ ] Confirm ciphersuite, DKG protocol, transport profile, build, and
      attestation allowlist versions.
- [ ] Verify each device identity, operator identity, hardware tier, and fresh
      attestation.
- [ ] Open a unique ceremony ID and record the initial transcript hash.
- [ ] Review every Stage 1 commitment and proof receipt.
- [ ] Review encrypted delivery state without requesting plaintext shares.
- [ ] Resolve or abort every complaint; never waive an unresolved complaint.
- [ ] Obtain independent approval of the qualification report.
- [ ] Confirm every qualified signer locally finalized an opaque key handle.
- [ ] Independently verify the group public key and Bitcoin address/output key.
- [ ] Seal the evidence manifest and record the recovery drill date.

### Signing checklist

- [ ] Confirm the request is canonical, unexpired, and allowed by the correct
      authority and spending tier.
- [ ] Confirm pause/recovery state and contract principal.
- [ ] Display the transaction summary and independently compare the digest,
      output key, and amount limits.
- [ ] Select at least three distinct fresh-attested qualified signers.
- [ ] Verify all nonce commitments are session- and message-bound.
- [ ] Verify the complete signing package before local signing.
- [ ] Confirm each signer returns a signature share, never a key package.
- [ ] Verify all shares independently and reject duplicates or unknown IDs.
- [ ] Verify the aggregate with BIP340 and, where applicable, BIP341.
- [ ] Record public evidence and broadcast only the verified transaction.

### Recovery checklist

- [ ] Declare the incident and preserve the current transcript/evidence hashes.
- [ ] Use `SAB_EMERGENCY_PAUSE_MULTISIG` only for pause/isolation.
- [ ] Confirm the pause authority is not attempting unpause or value transfer.
- [ ] Convene `SAB_EMERGENCY_RECOVERY_MULTISIG` and record the recovery policy
      decision.
- [ ] Revoke affected signer/device/transport identities and attestations.
- [ ] Select the approved refresh/reshare or new-key procedure.
- [ ] Run the full qualification and attestation checks for the replacement
      set.
- [ ] Update contract principals and policy manifests through the authorized
      recovery/DAO path.
- [ ] Verify old signers cannot sign and new signers cannot exceed policy.
- [ ] Unpause only through the recovery authority after independent review.
- [ ] Record the final public state and schedule an independent audit review.

### Post-incident evidence checklist

- [ ] Preserve request, ceremony, transcript, package, and transaction hashes.
- [ ] Preserve signed policy versions, attestation reports, measurements, and
      revocation decisions.
- [ ] Preserve signer IDs, quorum decisions, reason codes, and timestamps.
- [ ] Preserve contract events and on-chain transaction IDs.
- [ ] Confirm no plaintext share, key package, secret nonce, or private key was
      included in logs, tickets, telemetry, or attachments.
- [ ] Record whether any nonce state was uncertain and whether the signer was
      quarantined.
- [ ] Document the root cause, authority used, recovery steps, and remaining
      risk.
- [ ] Obtain independent reviewer sign-off before restoring normal operations.

## Canonical references

### Conxian references

- [Wallet Treasury Feasibility](https://github.com/Conxian/conxian_market/blob/main/docs/research/WALLET_TREASURY_FEASIBILITY.md)
- [SAB Wallet Architecture and Control Matrix](https://github.com/Conxian/conxian-business/blob/main/docs/SAB_WALLET_ARCHITECTURE_AND_CONTROL_MATRIX.md)
- [Current structural FROST module](../../src/protocol/frost.rs)
- [Current n-of-n MuSig2 wrapper](../../src/protocol/musig2.rs)
- [Production readiness checklist](../../PRODUCTION_READINESS.md)

### Protocol and Bitcoin references

- [RFC 9591 — The Flexible Round-Optimized Schnorr Threshold Signature (FROST) Protocol](https://www.rfc-editor.org/rfc/rfc9591)
- [BIP340 — Schnorr signatures for secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [BIP341 — Taproot: SegWit version 1 spending rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)

The implementation team must add the selected DKG protocol specification,
secp256k1 ciphersuite specification, transport profile, test-vector source,
and independent audit report to this reference list before marking the
production acceptance rows complete.
