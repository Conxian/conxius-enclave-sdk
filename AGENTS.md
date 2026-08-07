# Conxius Enclave SDK: Agent Directives (Session 58, Aug 2026)

> **Archive**: `docs/archive/AGENTS_archive_session_58.md` (full session + Phase tracking)
> **Version**: v2.0.16 — published to crates.io

## Core Ethos
- **Hardware-backed**: Every signing path requires attestation. No TEE-bypass code paths.
- **Protocol-first**: Type-safe protocol boundaries with explicit capability negotiation.
- **Fail-closed**: Default reject. Never approve a code path that degrades signing security.
- **Auditable**: Release Strict workflow enforces SBOM, provenance, and artifact integrity.

## Coding Standards
- Rust 2021 edition, MSRV 1.97.1. `cargo clippy -- -D warnings` before every push.
- No `unsafe` without documented justification. No hardcoded secrets (use `secrets.template`).
- All new protocol modules require `SystemState::initialize()` integration.

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
