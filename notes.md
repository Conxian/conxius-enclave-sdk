# Audit Notes - Mainnet Readiness & SDK Pivot (Final)

## Task
Complete the "Unified Vault SDK Pivot" alignment across documentation, boundary definitions, and repository portfolio classification (CON-628, CON-634, CON-635, CON-636).

## Evidence
- **SDK Boundary (CON-628)**: Created `docs/SDK_BOUNDARY_CONTRACT.md` defining strict module boundaries for signing, routing, and protocol layers.
- **Portfolio (CON-634)**: Created `docs/REPO_CLASSIFICATION.md` categorizing all Conxian repositories (Core, Demote, Separate).
- **Demotion (CON-635, CON-636)**: Updated `README.md` and `docs/ETHOS.md` to demote `conxius-wallet` to a Reference Application and `conxian-gateway` to Supporting Infrastructure.
- **SDK Audit (CON-627)**: (Previously completed) Documented high extraction viability in `docs/CON-627_AUDIT_FINDINGS.md`.
- **Positioning (CON-632)**: (Previously completed) Aligned all docs with "Native Bitcoin Application Infrastructure" narrative.
- **Mainnet Audit (CON-625)**: (Previously completed) Documented fail-closed security posture in `docs/CON-625_MAINNET_AUDIT.md`.
- **Billing Warning**: Noted that CI failures are currently due to account-level billing issues, not code errors.

## Validation
- `cargo test` passed with 33 tests.
- Verified doc consistency and terminology alignment across all 4 new/updated files.
