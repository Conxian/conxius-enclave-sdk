# Conxian Org-Wide Phased Plan

> Generated 2026-08-30 by an AI agent (OpenHands) during the Session 63
> org-wide sweep. This is a living map of the 15-repo Conxian org: inventory,
> dependency chain, open work, phased execution order, costs, and the repos each
> phase touches. Canonical home should eventually be `.github-private` (the
> central "Map and Guide"); this copy lives in the SDK so it can travel with the
> dependency-chain work.

## 1. Org inventory (15 repos)

| Repo | Lang | Role | Open issues | Open PRs | Last push |
| --- | --- | --- | ---: | ---: | --- |
| `conxius-enclave-sdk` | Rust | TEE/hardware signing SDK (source of truth for crypto) | 6 | 0 | 2026-08-30 |
| `lib-conxian-core` | Rust | Shared protocol primitives | 0 | 1 | 2026-08-29 |
| `conxian-nexus` | Rust | Postgres/Redis delivery runtime (`sqlx`+`redis`) | 2 | 0 | 2026-08-29 |
| `conxian-gateway` | Rust | Redis middleware, ISO 20022 bridge | 1 | 3 | 2026-08-30 |
| `Conxian` | Clarity | Stacks-native automated monetary protocol | 9 | 1 | 2026-08-29 |
| `conxian-business` | Python | Control plane / "Central Nervous System" | 7 | 0 | 2026-08-29 |
| `conxius-wallet` | TS | Android-first, offline-first sovereign wallet | 3 | 0 | 2026-08-29 |
| `conxius-platform` | TS | Dev/ops + org-wide rulesets | 7 | 0 | 2026-08-29 |
| `conxian_market` | TS | Discovery / deployment / settlement / escrow | 1 | 0 | 2026-08-29 |
| `conxian_ui` | TS | UI | 1 | 0 | 2026-08-29 |
| `conxian.github.io` | HTML | GitHub Pages | 1 | 0 | 2026-08-29 |
| `conxian-labs-site` | HTML | Marketing site | 0 | 0 | 2026-08-27 |
| `.github` | Python | Public defaults / doc guidance | 4 | 0 | 2026-08-16 |
| `.github-private` | Python | Central "Map and Guide" (private) | 0* | 0 | 2026-08-29 |
| `conxius-orbit` | Python | Stacks deployment toolkit | — archived — | — | 2026-08-06 |

\* `.github-private` counts may be under-reported depending on token membership scope.

**Totals (excluding archived): 42 open issues, 6 open PRs.**

## 2. Dependency chain (already wired)

```
conxian-nexus  ──►  lib-conxian-core (full-sdk)  ──►  conxius-enclave-sdk (optional `enclave`)
```

`ReplayStore`/`IdempotencyStore` traits live in the SDK; production backends belong
in `conxian-nexus`, not in the SDK library.

## 3. Cross-repo state just changed (Session 63)

- **SDK #321 merged** (`bitcoin 0.32.102` + `secp256k1 0.33.1`, yanked crate removed).
  This was the blocker for downstream lockfile resolution.
- **conxian-nexus PR #250 merged** — `IdempotencyStore` is now in nexus `main`.
  The earlier note ("ready-for-review; blocked by #320") is resolved.
- **`lib-conxian-core` PR #280** is open: "align enclave-sdk references and
  re-export metadata" — this is the downstream re-alignment for #321.
- **AWS KMS release key created + verified** (see §6): `kms:CreateKey`/`Encrypt`
  (`RSAES_OAEP_SHA_256`) and `ec2:RunInstances` confirmed on the `botshelo` IAM user.

## 4. Phased execution order

### Phase 0 — DONE this session
- SDK: dependency convergence (#321), Fedimint DLEQ crypto (#323), docs/gap sync + research (#322), governance (branch protection `SEC-005`), CodeQL triage.

### Phase 1 — Immediate, unblocked (cross-repo, Rust)
1. **`conxian-nexus` #251** — wire `IdempotencyStore` to Neon `Conxian Nexus` (`DATABASE_URL` + migration) + live-DB conformance suite mirroring `tests/durable_replay_conformance.rs`.
2. **`lib-conxian-core` PR #280** — review/merge the #321 re-alignment.
3. **SDK #242 (KMS half)** — bind the newly created KMS key into the Nitro release boundary (local qualification; key already exists).
4. **SDK** — record AWS capability evidence (connectivity + permission map + KMS key hash).

### Phase 2 — Provider/runtime evidence (external-heavy)
- **SDK #242** — AWS Nitro live attestation: `ec2:RunInstances` confirmed; launch `m5.xlarge` w/ enclave, build EIF from `enclave-poc/`, run `nitro-cli run-enclave`.
- **SDK #241** — Android KeyMint/StrongBox + Play Integrity (device required).
- **SDK #200** — WASM runtime evidence (headless Chromium/Node lanes; build already verified).

### Phase 3 — Product / market / business (org-wide)
- **`Conxian`** #532 (partnership security/legal), #530 (partnership gateway + Stacks.js SDK), #529 (partner usage ledger).
- **`conxian-business`** #938 (BOS-001 Gate 6 mainnet handoff), #989 (position research), #940 (FIBO ontology provenance).
- **`conxian-gateway`** #189 (BitVM3 garbled-circuit adapter) + 3 dependabot PRs (#348/#349/#350).
- **`conxius-wallet`** #444 (P0 value-op gate), #357 (tech debt), #356 (CI/CD baseline).
- **`conxius-platform`** #1223 (org-wide rulesets), #1212 (stale branch review), #1168 (Founder Rights research).
- **`conxian_market`** #8 (Treasury Dashboard) · **`conxian_ui`** #161 (preview) · **`conxian.github.io`** #3 (Pages deploy).
- **`.github`** #60 (license portfolio), #53 (repo presentation), #47 (security boundary).

## 5. Costs & "zero-to-cash" alignment

| Item | Cost | State |
| --- | --- | --- |
| AWS KMS key (`alias/conxian-nitro-release`, RSA_2048) | ~$1/mo + API | ✅ created & verified |
| AWS EC2 Nitro (`m5.xlarge`, eu-central-1) | ~$0.19/hr while running | not launched (needs consent) |
| Neon `Conxian Nexus` (pg17) | existing | already provisioned |
| All other work | software-only | no new spend |

Zero-to-cash note: the value path is **SDK (sign/attest) → lib-core → nexus
(idempotent settlement) → gateway (ISO 20022) → business (control plane) →
wallet/market (product)**. Phases 1–2 unblock the crypto/settlement spine; Phase 3
is where the business/market surfaces monetize it. Nothing in Phase 1 requires new
spend beyond the already-created KMS key.

## 6. AWS capability evidence (Session 63)

- Identity: `arn:aws:iam::692112933743:user/botshelo` (account `692112933743`).
- `ec2:RunInstances` ✅ (dry-run) · `ec2:DescribeImages/DescribeInstanceTypes` ✅.
- `kms:CreateKey/CreateAlias/DescribeKey/Encrypt(RSAES_OAEP_SHA_256)/GetPublicKey` ✅ (exercised).
- `kms:ListKeys/ListAliases` ✅ (read).
- `iam:SimulatePrincipalPolicy` / `ListAttachedUserPolicies` / `ListGroups` ❌ (cannot self-enumerate policy).
- KMS key: `RSA_2048`, `ENCRYPT_DECRYPT`, region `eu-central-1`, alias `alias/conxian-nitro-release`.
- `kms_key_identifier_hash` (SHA-256 of key ARN — matches the SDK's hash-only binding convention):
  `3023bd69185b63a2d3e28853def2a77f50fc11cf0ab7698c546716fbc86771e7`

## 7. Repos affected by Phase 1 (alignment)

- **Rust spine**: `conxius-enclave-sdk` → `lib-conxian-core` → `conxian-nexus` → `conxian-gateway` (all pinned through the #321 dependency line).
- **Downstream**: any repo consuming `lib-conxian-core`/`conxian-nexus` (gateway, business) picks up the idempotency + dependency changes transitively.
