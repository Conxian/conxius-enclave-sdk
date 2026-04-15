## Description
Please include a summary of the change and which issue is fixed. Please also include relevant motivation and context.

Fixes # (issue)

## Type of change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement

## Security & Integrity Checklist
- [ ] **Zero Secret Egress**: I have verified that private keys and seeds never leave the secure hardware boundary.
- [ ] **No Panics**: I have avoided `unwrap()`, `expect()`, and `panic!()`. All errors are handled via `ConclaveError`.
- [ ] **Zeroization**: Sensitive material is zeroized after use using the `zeroize` crate.
- [ ] **Hardware Attestation**: If applicable, this change respects mandatory device integrity checks for high-value operations.
- [ ] **ISO 20022 Compliance**: If modifying financial messaging, I have verified the schema alignment.

## Verification Checklist
- [ ] `cargo test` passes locally.
- [ ] `cargo fmt --all -- --check` passes.
- [ ] `cargo clippy -- -D warnings` passes.
- [ ] `wasm-pack build` passes (if changes affect the WASM surface).
- [ ] I have added tests that prove my fix is effective or that my feature works.

## Screenshots (if applicable)
Add any relevant screenshots of the change.
