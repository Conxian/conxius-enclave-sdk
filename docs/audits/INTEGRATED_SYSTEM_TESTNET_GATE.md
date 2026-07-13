# Integrated System Testnet Gate

Verification requirements for the final integrated system testnet cycle.

## Test Areas
1. **Sovereign Handshake**: Verified across all 5 core rails (Changelly, Bisq, Wormhole, Boltz, NTT).
2. **Fail-Closed Logic**: Emergency pause and oracle staleness checks.
3. **Shared Services**: Identity Profile generation and MMR proof fetching.

## Acceptance Criteria
- All tests in `lib-conclave-sdk` pass.
- Latency for 10k transactions < 50ms (Job Card Benchmark).
- Successful cross-chain swap simulation on testnet rails.
