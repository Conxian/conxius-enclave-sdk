# Contributing to lib-conclave-sdk

## Getting Started

1. Ensure you have Rust 1.81+ installed.
2. Clone the repository.
3. Run `cargo test` to ensure the baseline is stable.

## Bounty Workflow

We use a community-driven bounty model for many features and bug fixes.

1. Find an issue in Linear labeled as a "Bounty".
2. Claim the issue by commenting `/claim` on the corresponding GitHub issue (if automation is enabled) or by requesting assignment in Linear.
3. Follow the "Zero Secret Egress" and "Hardware Attestation" principles in your implementation.
4. Submit a Pull Request with a clear description and unit tests.

## Coding Standards

- **No Panics**: Avoid `unwrap()`, `expect()`, or `panic!()` in non-test code. Return a `ConclaveError` instead.
- **Constant Time**: Use the `subtle` crate for sensitive comparisons.
- **Zeroization**: Ensure sensitive material is zeroized after use using the `zeroize` crate.
