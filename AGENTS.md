# Conxius Enclave SDK: Agent Directives (Session 61, Aug 2026)

> **Archive**: `docs/archive/AGENTS_archive_session_58.md` (full session + Phase tracking)
> **Version**: v2.0.16 — published to crates.io

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
- All new protocol modules require `SystemState::initialize()` integration.
- Value-bearing crypto is feature-gated and fails closed without the feature: `groth16` (BLS12-381 pairings), `frost-crypto` (ZF FROST v3), `cryptoki` (PKCS#11), `webauthn` (FIDO2).

## Protocol Module Catalog — 52 Modules (24 blockchain + 28 infrastructure)

### Blockchain Protocols
`bitcoin`, `bip322`, `bitvm`, `bitvm2`, `dlc`, `frost` (real ZF v3.0.0 backend), `lightning` (BOLT 12/BIP-353), `musig2`, `stacks` (Nakamoto), `covenant` (OP_CAT), `ark`, `cctp`, `mmr`, `ethereum` (EIP-1559), `solana`, `statechain` (Spark), `sidl`, `credit`, `fiat`, `asset` (42 chains), `bip110`, `babylon` (SDK-005), `rgb` (SDK-006)

### Infrastructure & Integration
`economy`, `intent`, `swap_router`, `solver`, `stablecoin`, `settlement`, `chain_abstraction`, `account_abstraction`, `control_model`, `job_card`, `a2p`, `rails` (Bisq/Boltz/Changelly/NTT/Wormhole/x402), `nexus` (Fedimint), `zkml`, `wasm_bindings`, `android_strongbox`, `cloud`

> Full module paths and status in archive.

## Directory Map
- `src/protocol/` — 52 protocol modules (source of truth)
- `src/signing/` — UCS trait, algorithm registry, BIP-110 preflight
- `src/enclave/` — EnclaveManager, attestation, Nitro integration
- `src/re_exports.rs` — Public re-export surface (70+ modules)
- `enclave-poc/` — AWS Nitro Enclave signing demo

## Testing
```bash
cargo test --locked                    # All 227 tests
cargo test -p enclave-poc -- --test-threads=1  # Nitro POC (requires AWS)
```

## CI & Build Conventions
- **Release Strict**: Tag push → verify build/clippy/test → generate SBOM → crate publish → provenance attestation → GitHub Release
- **Main CI**: PR/push → format/clippy/test/audit → cargo publish --dry-run
- **Publish**: Requires clean `git status`. `release-evidence/` must be in `.gitignore`.
- **Crates.io verification**: `cargo search conxius-enclave-sdk --limit 1` — version must match tag.

## Org Map & Cross-Repo State (Session 62)

### Conxian org (14 public + 1 private repo)
- **SDK layer**: `conxius-enclave-sdk` (this repo — TEE/hardware signing), `lib-conxian-core` (shared primitives).
- **Infra/services**: `conxian-nexus` (Postgres/Redis "delivery runtime", Rust `sqlx`+`redis`), `conxian-gateway` (Redis middleware, ISO20022), `conxian-business` (control plane).
- **Product**: `conxius-wallet` (Android wallet), `Conxian` (Stacks/Clarity), `Conxian_UI`, `conxian_market`, `conxius-orbit` (archived).

### Dependency chain (already wired)
`conxian-nexus` → `lib-conxian-core` (`full-sdk`) → `conxius-enclave-sdk` (optional `enclave` feature). The `ReplayStore` trait is in this repo; production backends belong in services, NOT this library.

### Neon projects (6) → repos
`Conxian Nexus` (orange-paper, eu-central-1, pg17) = nexus · `conxian-core` (sparkling-sunset) = lib-conxian-core · `Software dev kit` = SDK · `Gateway` = gateway · `Business Operating System` = business · `market` = conxian_market. Managed via `NEON_API_KEY` (`https://console.neon.tech/api/v2/...`).

### Cross-repo work state
- **This repo**: #240 (trait + `DurableFileReplayStore` + conformance suite) and #271 (route-finding + channel state machine) code-complete; ark VTXO fail-open/panic fix in `8b447a7`; #320 P0 yanked `secp256k1 0.32.0-beta.2` → **RESOLVED (PR #321)**: `bitcoin 0.32.102` + `secp256k1 0.33.1`, yanked crate removed, 634 tests green.
- **conxian-nexus**: `IdempotencyStore` PR #250 (ready-for-review; merge blocked by #320) + follow-up issue #251 (wire to Neon + live-DB conformance suite).
- **Neon**: `corelibs` renamed → `conxian-core` (done).
- **Decisions**: #271 keep open (expand research + mainnet proofing); #240 item 6 / #202 independent review (external).
