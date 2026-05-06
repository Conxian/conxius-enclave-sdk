# SAB Migration Readiness Gates

Canonical gates for migrating from testnet-oriented operation to mainnet Sovereign Autonomous Business (SAB) status.

## Gate 1: Security & Integrity
- [x] Zero Secret Egress verified.
- [x] Hardware attestation enforced.
- [x] No-Panic standard met.
- [x] Cryptographic attribution for partners enforced.

## Gate 2: Operational Readiness
- [x] Managed lane orchestration complete.
- [x] Telemetry and observability active.
- [x] Enterprise Custody Baseline documented.
- [x] Settlement reconciliation logic implemented (CON-462).
- [ ] Enterprise settlement validation pilots (Active).

## Gate 3: Governance & Compliance
- [x] Asset Registry standardized.
- [x] Business Registry active.
- [x] Fail-closed ownership gates signed off.
- [ ] Legal review for institutional rollout.

## SAB Migration Timeline & Rollback Plan (CON-332)

### Wave 1: Managed Lane Cutover (Current - April 2026)
- **Focus**: Retail-ready Bitcoin L1 and Lightning signing.
- **Dependencies**:
    - Hardware-backed signing core (src/enclave).
    - Asset Registry baseline.
- **Readiness Gate**: All "Gate 1" items 100% verified in CI.
- **Rollback**: Instant fallback to simulated enclave if hardware reports failure (only for low-value test buckets).

### Wave 2: Enterprise Lane Pilot (May - June 2026)
- **Focus**: Institutional settlement and ISO 20022 reconciliation.
- **Dependencies**:
    - Successful reconciliation tests (SettlementService).
    - Partner identity validation (BusinessManager).
- **Readiness Gate**: Successful completion of settlement validation pilots (Milestone: "Enterprise and fintech validation").
- **Rollback**: Mandatory 144-block timelock provides a "veto" window for manual intervention.

### Wave 3: Full Sovereign Autonomy (July 2026+)
- **Focus**: Removal of Conxian-Labs managed orchestration dependencies.
- **Dependencies**:
    - Operator lane attestation verified.
    - MMR-based state proofs for self-healing.
- **Readiness Gate**: Milestone: "Pilot-ready deployment baseline".
- **Rollback**: State restoration via MMR inclusion proofs.
