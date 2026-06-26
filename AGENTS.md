# Conclave SDK: Contributor & Agent Directives (v0.2.8)

This document provides architectural guidance for human contributors and AI agents working on the Conclave SDK.

## Core Ethos
The Conclave SDK is the definitive **Sovereign Rails** infrastructure for native Bitcoin applications. We prioritize hardware-backed security (TEE, StrongBox), non-custodial orchestration, and universal asset support.

## Coding Standards
- **SDK-First**: Prioritize modularity and clear boundaries between enclave, protocol, and bindings.
- **Fail-Closed**: Always ensure a 'fail-closed' security posture for high-value operations. Hardware attestation must be mandatory in production.
- **No-Panic**: Avoid \`panic!\`, \`unwrap()\`, and \`expect()\` in production paths. Use \`ConclaveResult\` for error handling.
- **Zeroization**: Sensitive data must be zeroed out when no longer needed.

## Architecture Map
- \`src/enclave/\`: Hardware attestation and secure signing (TEE/StrongBox).
- \`src/protocol/\`: Core Bitcoin/Multi-chain orchestration logic.
- \`src/protocol/rails/\`: Modular settlement rails (x402, Wormhole, etc.).
- \`src/wasm_bindings.rs\`: Modular WASM sub-clients for web integration.

## Testing & Verification
- Use \`cargo test\` to verify all protocol changes.
- Ensure all 30+ chains in the \`AssetRegistry\` are correctly handled.
- Hardware-backed logic should be tested with both simulated and software attestation in CI, but must be blocked for production-level Trust Tiers.
- Feature Flag: \`--features mock_enclave\` is provided for local/CI development but is strictly prohibited in release builds.

## Documentation Policy
- Public documentation resides in \`README.md\` and the \`docs/\` directory.
- Internal audit findings and strategic roadmap items are tracked in restricted-access repositories or sanitized before inclusion here.
