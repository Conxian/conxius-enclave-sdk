# ISSUE-726: Independent review of the release-signing design and ceremony invite (2026-11-10)

Challenge: [Conxian/conxius-enclave-sdk#726](https://github.com/Conxian/conxius-enclave-sdk/issues/726) -
adversarial independent review of the 2-of-3 release-signing design and the
open co-signer invite, against `docs/operations/JOIN_THE_CEREMONY.md`,
`docs/operations/THRESHOLD_DKG_CEREMONY.md`, `ceremony/README.md`,
`src/enclave/threshold.rs`, and `src/protocol/frost_crypto.rs`.

## Method (reproducible, not prose)

- Read-only review; the pinned dependency is the source of truth for protocol
  semantics: `frost-secp256k1-tr` git tag `frost-secp256k1-tr/v3.0.0`, locked in
  `Cargo.lock` to commit `2016e44ba4a4757a996300350063b937a2ad33e8`.
- Every finding below is pinned by a **characterization test** added in this PR:
  the tests assert what the code *currently does* (not what the docs claim), so
  they pass today and become regression guards when a finding is fixed.
- Reproduce all findings:

```bash
cargo test --locked --features frost-crypto dkg_round2_publication_leaks
cargo test --locked --features frost-crypto forged_round1_proof_of_knowledge
cargo test --locked --features frost-crypto custom_dkg_identifiers_construct
cargo test --locked --features frost-crypto threshold_composition_accepts_cloned
cargo test --locked --features frost-crypto threshold_signing_halts_when_any_operator
cargo test --locked --features frost-crypto value_bearing_response_replays_across
```

(Rust 1.98.1, `--features frost-crypto`. Non-goals honored: no production
secret extraction, no real value-bearing signing run.)

## Findings

### F1 (critical): the "public" round-2 publication step leaks the full group secret

**Claim under review.** `ceremony/README.md:19` - operators "publish only the
**public** round packages"; `:22` - "`dkg_round2(...)` -> publish
`round2/pN.pkg`"; identically `JOIN_THE_CEREMONY.md:21-25` ("You never share a
secret ... publish only **public** round packages").

**Why it is wrong.** A FROST round-2 package is not a public artifact. In the
pinned frost-core (`frost-core/src/keys/dkg.rs`, rev `2016e44`), the round-2
`Package` struct doc says verbatim: *"The package must be sent on an
\*confidential\* and \*authenticated\* channel."* The struct carries exactly one
payload field, `signing_share` - the raw per-recipient scalar `f_i(j)`, not a
blinded or PoP-wrapped value (compare round-1, which is broadcast-public by
design).

At t=2, n=3 each operator's polynomial `f_i` is linear. If every operator
publishes their round-2 packages as the docs instruct, then from the public
files alone an observer holds `f_i(2)` and `f_i(3)` for every operator `i`,
interpolates `s_i = f_i(0)` (two points, one line), and computes the group
secret `s = s_1 + s_2 + s_3`. With the published round-1 commitments
(`round1/pN.pkg`) the observer also derives each operator's public key
`G^{s_i}` and the BIP-341 taproot tweak applied by `post_dkg`, i.e. the
complete signing secret of the `conxian-release` key. The ceremony is then
worthless against a passive eavesdropper on the public PR/branch.

**Schema mismatch in the same step.** `dkg_round2` returns
`BTreeMap<Vec<u8>, Vec<u8>>` - **n-1 distinct per-recipient packages per
operator** (`src/protocol/frost_crypto.rs:178-208`) — while README/runbook
specify one file `round2/pN.pkg` per operator (`THRESHOLD_DKG_CEREMONY.md:47-50`
says "publish round2_package", singular). As written the runbook is
unimplementable: publishing all n-1 packages leaks (above); publishing a single
one starves the other operators of their own confidential share at `dkg_round3`.

**Reproduction.** `dkg_round2_publication_leaks_every_participant_secret_coefficient`
runs the ceremony exactly as documented through the SDK byte-level API, then
recovers every operator's secret coefficient from the published round-2 bytes
alone (each package's trailing 32-byte big-endian scalar) and verifies the
interpolated line against both published shares.

**Minimal fix direction.** Deliver round-2 packages point-to-point over an
authenticated confidential channel (one package per recipient, never committed);
CI pickup validates round-1 packages only; update `ceremony/README.md` step 2,
`JOIN_THE_CEREMONY.md:25`, and `THRESHOLD_DKG_CEREMONY.md:47-56`.

### F2 (high): CI "package(s) valid" does not check the proof of knowledge it claims to

**Claim.** `ceremony/README.md:25-27`: CI "validates each `*.pkg` with
`verify_dkg_round1_package`"; the pickup line reads "X/Y package(s) **valid**".
Until this PR, `verify_dkg_round1_package`'s own docstring promised it
"passes proof-of-knowledge checks".

**Reality.** The function only deserializes
(`src/protocol/frost_crypto.rs:247-256`); the embedded PoP `sigma_i = (R_i, mu_i)`
is verified only later, inside `dkg_part2` (upstream `part2` calls
`verify_proof_of_knowledge` per sender and fails with
`Error::InvalidProofOfKnowledge`). A round-1 package with a forged PoP counts
as "valid" in the recorded pickup line and is rejected only when an honest
operator consumes it - after the PR/commit is already public.

**Reproduction.** `forged_round1_proof_of_knowledge_passes_verify_but_fails_part2`:
flips one bit of the trailing PoP scalar; `verify_dkg_round1_package` still
returns `true`, and `dkg_part2` fails with `InvalidProofOfKnowledge`.

**Fix included.** This PR corrects the docstring to state structural-check-only
semantics. Rename the pickup field (e.g. "parseable") or add a PoP-aware
verify if "valid" must keep its current meaning.

### F3 (high): composed threshold attestation has no participant/device distinctness binding

**Where.** `src/enclave/attestation.rs:982-1028` (`verify_threshold_composition`),
composed by `src/enclave/threshold.rs:143-157`
(`compose_value_bearing_response`).

**Why it is wrong.** The M-of-N numbers are **self-declared JSON fields** on
the composite report (`threshold_min_signers`, `threshold_shares`, set by the
provider itself at `threshold.rs:146-147`). The verifier counts share reports
that individually pass the single-mechanism policy - it never checks they came
from distinct participants, distinct devices, or distinct keys. There is no
participant list in the schema, and the composite report itself carries an
**empty `signature` and empty `certificate_chain`** (`threshold.rs:150,153`) -
the composition is self-asserted. One device signing the same share report M
times satisfies "M-of-N". The repo's own happy-path test already attests all
three shares with a single test key (`test_signing_key`).

**Consequence.** The runbook's per-share hardware binding
(`THRESHOLD_DKG_CEREMONY.md:66-74`) and the invite's "no shared single point of
control" requirement (`JOIN_THE_CEREMONY.md:38-41`) are not enforced by the
verifier the value-bearing consumer trusts.

**Reproduction.** `threshold_composition_accepts_cloned_reports_from_one_device`:
three byte-identical share reports from one device key verify as a healthy
2-of-3; the test additionally asserts the composite's empty signature/chain and
that all three shares present the same device certificate.

**Minimal fix direction.** Bind participant identity + device key per share
report, require pairwise-distinct signer keys / certificate chains among the
counted shares, and cap `threshold_shares.len()` at the ceremony's N.

### F4 (high): coordinator assembly holds every secret share, and signing needs all n operators

**Contradiction.** `THRESHOLD_DKG_CEREMONY.md:22-23`: "**no party may ever
reconstruct the full secret key**"; `:31`: "the coordinator never holds a
secret share". But **Provider assembly** (`:76-90`) has the coordinator build
the provider from "the operators' `key_package`s" - and a FROST `KeyPackage`
*contains that operator's secret signing share*. A coordinator holding 2 of 3
`key_package`s can run `frost::keys::reconstruct` (public API) and hold the
full key; that is exactly what `ThresholdEnclaveManager` stores
(`src/enclave/threshold.rs:33` `key_packages: Vec<Vec<u8>>`). The runbook's
"No-full-key invariant" box (`:61-64`) is true of the *ceremony* but false of
the documented post-ceremony assembly.

**Availability.** `threshold_sign` drives **every** stored key package
(`threshold.rs:89-110`, no M-of-N subset selection): with min_signers=2, n=3 a
single offline operator halts release signing, contradicting the "2-of-3 so no
single signer is critical" framing (`JOIN_THE_CEREMONY.md:9-11`).

**Reproduction.** `threshold_signing_halts_when_any_operator_is_offline`:
one of three operators fails to produce nonces and `sign` errors, despite 2 of
3 signers being available.

**Minimal fix direction.** The coordinator/provider should hold only the
published `public_key_package`; each operator runs the two signing rounds on
their own `key_package` locally; the aggregator accepts any `min_signers`
signature shares (FROST supports this natively - `create_signing_package` just
needs the participating subset's commitments).

### F5 (medium): the invite's "Proof schema ... CI validates it" is not implemented

**Claim.** `JOIN_THE_CEREMONY.md:55-59`: the co-signer proof is "an attestation
document (Nitro COSE + Nitro root-CA chain) verifying PCR0/1/2, a nonce bound
to the round, the recipient key, and your identity claim. CI validates it;
nothing is trusted on faith."

**Reality.** `.github/workflows/dkg-ceremony.yml` has no attestation step at
all: its only substantive step (`:49-57`) runs `examples/dkg_ceremony.rs`
(rehearsal + pickup), which does structural package parsing via
`verify_dkg_round{1,2}_package` (see F2 - not even PoP) and records the pickup
line. No COSE signature check, no Nitro root-CA chain verification, no PCR
comparison, and no nonce binding to the round exists anywhere in the workflow
or the pickup example. Today the schema is aspirational; "CI validates it"
overstates what an outside reviewer can rely on.

**Evidence.** Prose finding (no code change to point at); grep of
`.github/workflows/dkg-ceremony.yml` for COSE/PCR/root/nonce returns only the
rehearsal/pickup/evidence plumbing. This is exactly the gap independent audit
#202 must close; the invite should say so until it does.

### F6 (medium): a captured value-bearing response replays across operation contexts

**Where.** `SignerKeyBindingEvidence` (`src/enclave/attestation.rs:363-428`)
hashes key id, derivation path, expected/returned public keys, the operation
digest, the purpose token, the attestation purpose and algorithm - but **not**
the `OperationContext` domain or context payload. The composite report's
`challenge_nonce` is set to `message_digest` itself
(`src/enclave/threshold.rs:149`), so digest equality doubles as nonce freshness,
and reports are accepted for `MAX_ATTESTATION_AGE_SECS = 300`
with `MAX_ATTESTATION_CLOCK_SKEW_SECS = 30` (`attestation.rs:12-19`).

**Consequence.** Within the freshness window, a provider response captured for
one operation context verifies verbatim against a different request whose
domain and context payload differ, as long as the message digest is unchanged
(e.g. the same tx bytes re-presented under a different service domain/purpose
payload). The binding evidence cannot tell the two operations apart.

**Reproduction.** `value_bearing_response_replays_across_operation_contexts`:
signs request A, then verifies A's response against request B (different
domain + context payload, same digest) via
`ValueBearingSignResponse::from_provider_at_time` - accepted.

**Minimal fix direction.** Hash the domain and context payload into
`SignerKeyBindingEvidence` (add `operation_context_hash`), and bind a fresh
per-request nonce distinct from the message digest.

### F7 (low): positional identifier coupling + doc/API drift

- `create_signing_package` assigns participant identifiers **positionally**
  (`frost_crypto.rs:80`, `(i + 1)`), and `threshold_sign` labels shares with
  `(i + 1)` (`threshold.rs:106`). A ceremony run with custom `participant_id`s
  - which the invite explicitly advertises, `dkg_round1(participant_id, 3, 2)`
  (`JOIN_THE_CEREMONY.md:24`) - constructs through all three DKG rounds but
  fails at the first signing attempt. Reproduction:
  `custom_dkg_identifiers_construct_but_positional_signing_breaks` (DKG with
  identifiers 10/11/12 succeeds; `create_signature_share` errors because the
  signing package is keyed 1..m).
- Round-2 package cardinality: singular in docs, a map of n-1 in the API (F1).
- Test-count drift: `THRESHOLD_DKG_CEREMONY.md:32` claims "627 pass" while
  `AGENTS.md` records 661 total; pick one authority.
- Pickup path layout (`ceremony/round1/pN.pkg` vs the non-recursive top-level
  `*.pkg` scan) is already covered by ISSUE-721 finding 5 - not re-litigated here.

## Verdict

The invite's core promise survives for **round-1** publication and the final
public key package (they are public by protocol design, and #721 separately
showed the rehearsal proof is BIP340-recomputable). It does **not** survive as
written at the round-2 step: the documented publication of "public" round-2
packages contradicts the pinned library's confidentiality requirement and
leaks the group secret to any reader of the ceremony branch (F1). The recorded
"valid" pickup overstates validation (F2, F5), the composed threshold
attestation does not enforce the distinctness it advertises (F3), and the
documented coordinator assembly both breaks the no-full-key invariant and
requires all-n operator liveness (F4). Context replay (F6) and positional-id
signing (F7) are exploitable/annoying but secondary.

Six characterization tests in this PR pin each executable finding on the current
code; one doc fix (`verify_dkg_round1_package` docstring) is included. No
design rewrite is proposed - each finding lists a minimal direction consistent
with the existing architecture.
