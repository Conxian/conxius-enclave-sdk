# Audit Notes - Mainnet Readiness & Hygiene Alignment

## Task
Standardize repository hygiene, release discipline, and architectural boundaries for `lib-conclave-sdk`.

## Evidence
- **Hygiene**: Added `.github/workflows/hygiene.yml` to enforce forbidden file and testnet principal checks.
- **Architecture**: Updated `GOVERNANCE.md` to define boundaries between `lib-conclave-sdk` (enclave/signing) and `lib-conxian-core` (primitives).
- **Security**: Locked `sha2` to `0.10.9` and `pbkdf2` to `0.12.2` to resolve `digest` trait version conflicts while remediating RUSTSEC-2025-0055.
- **Clarity**: Polished `README.md` and `CHANGELOG.md` for public visibility.

## Validation
- `cargo test` passed with 26 tests.
- Manual verification of hygiene check logic.
- Linear issues CON-516, CON-555, and CON-547 resolved.
