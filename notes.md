# Audit Notes - Mainnet Readiness & SDK Pivot

## Task
Standardize repository hygiene, align company positioning with the "Unified Vault SDK Pivot", and perform a Mainnet Readiness audit for fail-open logic (CON-627, CON-632, CON-633, CON-625).

## Evidence
- **SDK Audit (CON-627)**: Conducted a formal viability audit for SDK extraction. Findings documented in `docs/CON-627_AUDIT_FINDINGS.md`. Verified high modularity and zero UI coupling.
- **Positioning (CON-632)**: Rewrote `README.md` and `docs/ETHOS.md` to focus on "Native Bitcoin Application Infrastructure". Demoted legacy retail dapp framing.
- **SDK Primitives (CON-633)**: Defined the GTM V1 primitive: Hardware-Backed Bitcoin Signing & Policy. Documented in `docs/SDK_PRIMITIVES.md`.
- **Mainnet Audit (CON-625)**: Audited protocol and enclave libraries for fail-open/simulated behavior. Findings documented in `docs/CON-625_MAINNET_AUDIT.md`.
- **Hygiene**: Cleaned up merged local branches. Pinning `getrandom` and resolving `digest` trait version conflicts in `Cargo.toml`.

## Validation
- `cargo test` passed with 33 tests.
- Verified functional inclusion proof generation for MMR.
- Manual verification of attestation serialization in SignResponse.
