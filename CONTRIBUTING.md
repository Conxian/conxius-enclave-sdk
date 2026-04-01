# Contributing to lib-conclave-sdk

## Getting Started

1. Ensure you have **Rust 1.94+** installed (Edition 2024).
2. For WebAssembly (WASM) development, install [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/).
3. Clone the repository.
4. Run `cargo test` to ensure the baseline is stable.

## Development Workflow

### Building the SDK
To build the core Rust SDK:
```bash
cargo build
```

### Running Tests
Run `cargo test` to execute the unit test suite:
```bash
cargo test
```

### WASM Bindings
To build the WASM package for web environments:
```bash
wasm-pack build
```

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
- **Async Traits**: Prefer plain traits and synchronous methods where possible. Use `#[async_trait]` only when you need async methods in trait interfaces on stable Rust and accept the extra overhead it can introduce.
