# Code Review Request

> Use this template when requesting code review for a PR.

## Summary of Changes
<!-- Brief description of what this PR changes and why -->

## Verification
<!-- How have you verified this PR? -->

- [ ] `cargo test --locked --all-features` passes
- [ ] `cargo clippy --locked --all-targets --all-features -- -D warnings` clean
- [ ] `cargo fmt` clean
- [ ] WASM build (`wasm-pack build --release --target bundler`) succeeds
- [ ] `cargo deny check` clean

## Review Checklist
- [ ] Code follows project conventions (fail-closed, ConclaveResult, no unwrap/expect in production paths)
- [ ] Security-sensitive paths are gated behind appropriate features
- [ ] KB artifacts updated (CHANGELOG, SESSION_HISTORY, etc.) if applicable
