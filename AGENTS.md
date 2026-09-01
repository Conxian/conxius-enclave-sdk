# Conxius Enclave SDK: Agent Directives (Session 61, Aug 2026)

> **Archive**: `docs/archive/AGENTS_archive_session_58.md` (full session + Phase tracking)
> **Version**: v2.0.17 — published to crates.io

## Core Ethos
- **Hardware-backed**: Every signing path requires attestation. No TEE-bypass code paths.
- **Protocol-first**: Type-safe protocol boundaries with explicit capability negotiation.
- **Fail-closed**: Default reject. Never approve a code path that degrades signing security.
- **Auditable**: Release Strict workflow enforces SBOM, provenance, and artifact integrity.

## Standing Directives (Session 63)
- **Scope-covered (always)**: Every issue discovered during a session is automatically in-scope and must be *resolved or formally tracked in-repo* — never merely reported and left open. Prefer fixing/documenting in `DEBT_INVENTORY.md`, `ISSUES_INDEX.md`, or `docs/architecture/` over deferring.
- **Code-scanning false positives**: CodeQL `hard-coded cryptographic value` and `cleartext logging` findings are expected false positives in this crypto SDK (test vectors, synthetic replay-nonce fixtures, `#[derive(Debug)]` on public cert chains). Dismiss as `false positive`; do **not** rewrite test vectors to satisfy a scanner. Recurrence is suppressed by `.github/codeql/codeql-config.yml` (`paths-ignore: tests/**`).

## Coding Standards
- Rust 2021 edition, MSRV 1.97.1. `cargo clippy --all-targets --all-features -- -D warnings` before every push.
- No `unsafe` without documented justification. No hardcoded secrets (use `secrets.template`).
- All new protocol modules implement `EnclaveManager::initialize()` (and `UniversalChainSigner::initialize()` for signing surfaces) for runtime state setup.
- Value-bearing crypto is feature-gated and fails closed without the feature: `groth16` (BLS12-381 pairings), `frost-crypto` (ZF FROST v3), `cryptoki` (PKCS#11), `webauthn` (FIDO2), `fedimint-crypto` (BLS12-381 e-cash blinding + DLEQ).

## Protocol Module Catalog — 43 Modules (25 blockchain + 18 infrastructure)

### Blockchain Protocols
`bitcoin`, `bip322`, `bitvm`, `bitvm2`, `dlc`, `frost` (real ZF v3.0.0 backend), `frost_crypto`, `lightning` (BOLT 12/BIP-353), `lightning_channel`, `musig2`, `stacks` (Nakamoto), `covenant` (OP_CAT), `ark`, `cctp`, `mmr`, `ethereum` (EIP-1559), `solana`, `statechain` (Spark), `sidl`, `credit`, `fiat`, `asset` (42 chains), `bip110`, `babylon` (SDK-005), `rgb` (SDK-006)

### Infrastructure & Integration
`economy`, `intent`, `swap_router`, `solver`, `stablecoin_orchestrator`, `settlement`, `settlement_service`, `chain_abstraction`, `account_abstraction`, `control_model_adapter`, `job_card`, `a2p`, `opportunity`, `business`, `identity`, `rails` (Bisq/Boltz/Changelly/NTT/Wormhole/x402), `nexus` (Fedimint/ROAST/`fedimint_crypto` BLS12-381 DLEQ), `zkml`

### SDK-level (non-protocol modules, outside `src/protocol/`)
`wasm_bindings` (`src/`), `android_strongbox` + `cloud` (`src/enclave/`)

> Full module paths and status in archive.

## Directory Map
- `src/protocol/` — 43 protocol modules (source of truth)
- `src/signing/` — UCS trait, algorithm registry, BIP-110 preflight
- `src/enclave/` — EnclaveManager, attestation, Nitro integration
- `src/lib.rs` — Public re-export surface (`pub mod` + per-module `pub use`)

## Testing
```bash
cargo test --locked                    # All 629 tests
```

## CI & Build Conventions
- **Release Strict**: Tag push → verify build/clippy/test → generate SBOM → crate publish → provenance attestation → GitHub Release
- **Main CI**: PR/push → format/clippy/test/audit → cargo publish --dry-run
- **Publish**: Requires clean `git status`. `release-evidence/` must be in `.gitignore`.
- **Crates.io verification**: `cargo search conxius-enclave-sdk --limit 1` — version must match tag.

## Org Map & Cross-Repo State (Session 64)

### Conxian org (15 repos: 14 public + 1 private)
- **SDK layer**: `conxius-enclave-sdk` (this repo — TEE/hardware signing), `lib-conxian-core` (shared primitives).
- **Infra/services**: `conxian-nexus` (Postgres/Redis "delivery runtime", Rust `sqlx`+`redis`), `conxian-gateway` (Redis middleware, ISO20022), `conxian-business` (control plane).
- **Product**: `conxius-wallet` (Android wallet), `Conxian` (Stacks/Clarity), `conxian_ui`, `conxian_market`, `conxius-platform` (dev/ops), `conxius-orbit` (archived).
- **Web/sites**: `conxian-labs-site`, `conxian.github.io`.
- **Org governance**: `.github` (public defaults/guidance), `.github-private` (central "Map and Guide", private).

Full inventory + phased plan: `docs/ORG_WIDE_PHASED_PLAN.md`.

### Dependency chain (already wired)
`conxian-nexus` → `lib-conxian-core` (`full-sdk`) → `conxius-enclave-sdk` (optional `enclave` feature). The `ReplayStore` trait is in this repo; production backends belong in services, NOT this library.

### Neon projects (6) → repos
`Conxian Nexus` (orange-paper, eu-central-1, pg17) = nexus · `conxian-core` (sparkling-sunset) = lib-conxian-core · `Software dev kit` = SDK · `Gateway` = gateway · `Business Operating System` = business · `market` = conxian_market. Managed via `NEON_API_KEY` (`https://console.neon.tech/api/v2/...`).

### Cross-repo work state (Session 64 — post-audit)
- **This repo (Session 64)**: KB→code→CI audit + remediation **PR #329 merged**. Live verification (Rust 1.97.1): `cargo test --locked` 629 passed / `--all-features` 645 passed; `clippy -D warnings` + `fmt` clean; `cargo audit` 0 vulns + `cargo deny` ok. crates.io cleanup: yanked `lib-conclave-sdk@2.0.8` (DEP-003 resolved) + `anya-core@1.2.0`. Dep-scan config: added `RUSTSEC-2023-0089` (atomic-polyfill) to `.cargo/audit.toml`, removed orphaned root `audit.toml`.
- **This repo**: #240 (trait + `DurableFileReplayStore` + conformance suite) and #271 (route-finding + channel state machine) code-complete; ark VTXO fail-open/panic fix; #320 P0 yanked `secp256k1 0.32.0-beta.2` → **RESOLVED**: `bitcoin 0.32.102` + `secp256k1 0.33.1`. **v2.0.17 released** (tag + crates.io) — the first tag free of the yanked crate. PRs #322 (docs/gap/research), #323 (Fedimint DLEQ), #324 (org plan), #325 (release bump), #326 (release verify User-Agent 403 fix), #327 (release recovery tag-gate), #328 (KB audit session 63) — **all merged**. GitHub Release recovery for v2.0.16 + v2.0.17 (were missing because the release verify `curl` lacked a `User-Agent` → crates.io 403).
- **conxian-nexus**: `IdempotencyStore` PR #250 **merged** (2026-08-29, in nexus `main`) and dependency fix #255 **merged** (re-pinned `lib-conxian-core` to yanked-crate-free revision). Follow-up issue #251 (wire to Neon `Conxian Nexus` + live-DB conformance suite) **open** — next feature target.
- **lib-conxian-core**: #281 (converge on SDK v2.0.17) + #280 (align refs + `sdk-signing` feature gate + `nitro` wasm32 gate) **merged**. Yanked crate now absent from its lockfile.
- **conxian-gateway**: dependabot 12-crate Rust group bump #350 **closed** (breaks Build/Clippy/Test/MSRV — `str`→`[u8;N]` API break). Needs a curated migration before those deps can bump.
- **Conxian**: dependabot `@types/node` #700 **closed** (npm lock drift — `mime-db@1.52.0` missing). Needs `npm install` lockfile regen.
- **AWS (KMS/Nitro)**: `botshelo` IAM user in account `692112933743`; `ec2:RunInstances` + `kms:CreateKey`/`Encrypt(RSAES_OAEP_SHA_256)` confirmed; KMS release key `alias/conxian-nitro-release` (RSA_2048) created. See `docs/ORG_WIDE_PHASED_PLAN.md` §6.
- **Neon**: `corelibs` renamed → `conxian-core` (done).
- **Decisions**: #271 keep open (expand research + mainnet proofing); #240 item 6 / #202 independent review (external).

### Known remaining debt (in-scope, tracked)
- **ARCH-002**: 4 coexisting `secp256k1` versions (`0.29.1`/`0.30.0`/`0.31.1`/`0.33.1`) across the Rust spine.
- **Provider evidence**: #242 (Nitro live attestation — needs EC2), #241 (Android — needs device), #200 (WASM runtime).
- **Product/market**: wallet #444, market #8, business #938, Conxian #529/530/532.
