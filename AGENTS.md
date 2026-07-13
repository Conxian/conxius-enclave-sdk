# Conclave SDK: Agent Directives (v0.2.8)

## Production Status

**✅ PRODUCTION READY** - v2.0.7

See [PRODUCTION_READINESS.md](./PRODUCTION_READINESS.md) for full checklist.

## Repository Tracking

For comprehensive tracking of issues, pull requests, and branches:
- **TRACKING.md** - Main tracking overview
- **ISSUES_INDEX.md** - GitHub issues (synced locally)
- **PRS_INDEX.md** - Pull requests (synced locally)
- **BRANCHES_INDEX.md** - Branch overview
- **REPOSITORY_ANALYSIS.md** - Capabilities, gaps, and roadmap
- **DEBT_INVENTORY.md** - Technical debt tracking

### Syncing from GitHub
```bash
./scripts/sync_issues.sh
```

## Core Ethos
The Conclave SDK is the definitive **Sovereign Rails** infrastructure for native Bitcoin applications. We prioritize hardware-backed security (TEE, StrongBox), non-custodial orchestration, and universal asset support.

## Coding Standards
- **SDK-First**: Prioritize modularity and clear boundaries between enclave, protocol, and bindings.
- **Fail-Closed**: Always ensure a 'fail-closed' security posture for high-value operations. Hardware attestation must be mandatory in production.
- **No-Panic**: Avoid `panic!`, `unwrap()`, and `expect()` in production paths. Use `ConclaveResult` for error handling.
- **Zeroization**: Sensitive data must be zeroed out when no longer needed.

## Directory Map
- `src/enclave/`: Hardware attestation and secure signing (TEE/StrongBox).
- `src/protocol/`: Core Bitcoin/Multi-chain orchestration logic.
- `src/protocol/rails/`: Modular settlement rails (x402, Wormhole, etc.).
- `src/wasm_bindings.rs`: Modular WASM sub-clients for web integration.
- `docs/architecture/`: Active architectural standards and research.
- `docs/audits/`: Mainnet readiness and security audit artifacts.

## Testing
- Use `cargo test` to verify all protocol changes.
- Ensure all 30+ chains in the `AssetRegistry` are correctly handled.
- Hardware-backed logic should be tested with both simulated and software attestation (for CI) but blocked for production-level Trust Tiers.
