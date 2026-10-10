# Independent Security Review — Engagement Scope & RFP (2026-10-10)

| Metadata | Value |
|---|---|
| Authority | [`conxius-enclave-sdk#202`](https://github.com/Conxian/conxius-enclave-sdk/issues/202) (P0 — independent review & release acceptance) |
| Candidate | `conxius-enclave-sdk` `v2.1.0` (exact tagged candidate, `Cargo.lock` pinned) |
| Evidence model | `docs/architecture/capability-evidence.json` + `docs/architecture/CAPABILITY_MATRIX.md` |
| Classification | Public-safe; no secrets, custody procedures, or privileged identifiers |

## 1. Purpose

Implementation and documentation do not, by themselves, prove production enablement. The
single empty cell in the capability matrix is `independentReview` (currently `not-evidenced`).
This document turns that gate into a commissionable engagement: it defines the exact review
scope, maps every in-scope primitive to already-published in-repo evidence (so the reviewer
**verifies** rather than re-derives, reducing cost), names candidate reviewers aligned with the
non-US / global-south business posture, and states acceptance criteria that map 1:1 to #202.

## 2. Assets and threat model

The review is scoped to the **value-bearing signing boundary**. Non-signing surfaces are
already `Stable (conditional)` and are out of scope.

In-scope assets (secret-bearing, highest impact):

1. **Enclave signing orchestration** — `src/enclave/mod.rs`, `src/enclave/cloud.rs`,
   `src/enclave/android_strongbox.rs`. Zero-secret-egress signing across AWS Nitro TEE,
   Android StrongBox/KeyMint, and Apple Secure Enclave.
2. **Threshold signing (FROST 2-of-3 / MuSig2)** — distributed key generation, round
   serialization, and signature aggregation. Exercised continuously by the
   `dkg-ceremony.yml` 2-of-3 FROST rehearsal.
3. **Attestation verification** — COSE / Nitro PCR0-2 root-of-trust, chain-length checks,
   nonce/challenge binding, recipient-key and release binding (`src/enclave/nitro.rs`).
4. **Trust & collateral contract** — provider-neutral trust normalization, digest-only
   collateral metadata, root-set/schema/verifier/revocation validation (`G240-TC`).
5. **Replay guard & durable replay contract** — secret-free replay binding and the atomic
   durable-replay store contract (`G240-RP`).
6. **Secret boundary** — WASM runtime secret isolation and platform evidence (`G200-WASM`).

Threat model assumptions (to be confirmed by the reviewer):

- Attacker controls the host OS and network; the TEE/secure element is trusted only up to the
  verified attestation root.
- Private key material must never leave the attested trust boundary in any serialization,
  log, error message, or core dump.
- A value-bearing operation requires fully verified attestation; any missing evidence must
  fail closed.

## 3. Review scope (primitive-by-primitive) and existing evidence

The reviewer verifies each primitive against the requirement → code → test → CI → artifact
chain already published in-repo. The right-hand column is where the evidence lives; this is
the cost-reduction map.

| # | Primitive | Evidence the reviewer verifies |
|---|---|---|
| 1 | Threshold FROST/MuSig2 keygen + signing | `src/enclave/threshold/**`; `dkg-ceremony.yml`; 2-of-3 DKG rehearsal artifacts (`ceremony/round1|round2/*.pkg`) |
| 2 | Nitro attestation (PCR0-2, COSE, root-CA, nonce, release binding) | `src/enclave/nitro.rs`; offline verification evidence in `docs/audits/` |
| 3 | Android KeyMint/StrongBox + Play Integrity authorization | `src/enclave/android_strongbox.rs`; hardware-attestation test suite (`src/enclave/hardware_attestation_tests.rs`) |
| 4 | Trust/collateral contract | `docs/architecture/TRUST_REPLAY_RELEASE_CONTRACTS.md`; `G240-TC` conformance tests |
| 5 | Replay contract + durable replay | `G240-RP`; `FileBackedDurableReplayStore` + `DurableFileReplayStore` conformance |
| 6 | Secret boundary (WASM) | `G200-WASM` secret-boundary error-stability tests |
| 7 | Reproducible release + SBOM + provenance | `release-strict.yml` (cargo package --locked → checksum → SPDX/CycloneDX SBOM → SLSA `actions/attest-build-provenance` → `gh attestation verify`); `sbom.yml` |
| 8 | Gap ledger integrity | `docs/architecture/GAP_SCORECARD.md`, `capability-evidence.json`, `CAPABILITY_MATRIX.md` |

## 4. Out of scope (explicitly conditional — do not sign off)

- Any capability whose `productionSupport` is `conditional` and whose evidence is not
  attached to the exact tagged candidate.
- Live-device hardware evidence not reproducible in CI (`G-live-AP`) — recorded as a
  conditional/residual item, not silently promoted.
- Historical `Production: No` protocol lanes (FROST/Fedimint/Ark/BitVM2 as documented in
  `PROTOCOL_IMPLEMENTATION_ROADMAP.md`).

## 5. Candidate reviewers (non-US / global-south aligned)

| Firm | HQ | Strength |
|---|---|---|
| Cure53 | Berlin, DE | Cryptographic primitives, TEE, web3 |
| Least Authority | Berlin, DE | Decentralized systems, threshold crypto, TEE |
| NCC Group (Crypto Services) | Manchester/London, UK | Enclaves, hardware roots-of-trust, ISO |
| Kudelski Security | Lausanne, CH | Crypto, HSM/enclave, payment rails |
| Quarkslab | Paris, FR | Enclave/TEE reverse-engineering, attestation |
| HALBORN | Brazil (BRICS) | Smart contracts + applied cryptography |

US-first firms are deliberately de-prioritized to match the org's global-south / BRICS /
Africa-trade posture.

## 6. Deliverables and acceptance criteria

The reviewer must produce a **capability-by-capability decision for the exact tagged
candidate**, each row citing the evidence used. Acceptance maps directly to #202:

- [ ] Every in-scope primitive has a traceable requirement → code → test → CI → artifact chain.
- [ ] `independentReview` flips to `yes` **only** for the exact `v2.1.0` candidate reviewed.
- [ ] Reviewed tag, crate version, registry artifact, changelog, checksums, SBOM, provenance,
      and support matrix match exactly.
- [ ] All residual gaps remain explicitly `conditional`; no repository-wide production claim.
- [ ] A remediation list with severity, for any finding that is not a blocker.

## 7. Funding model (self-funding, not out-of-pocket)

The review is funded from the **non-signing revenue surfaces already code-complete** rather
than from operating cash:

- `conxian-gateway` managed ISO-20022 bridge retainer: **$2,500–$7,500/mo** (Rank 1 outreach).
- `conxian-nexus` sovereign Node-as-a-Service: **$15,000–$40,000/mo**.
- These surfaces require **no value-bearing signing** (blocked only on owner secrets in
  `conxian-gateway#466`), so they can begin earning before the audit completes.

Post-review, the audited signing path becomes the premium product (Key Management as a
Service), priced *because* it carries an independent-review decision.
