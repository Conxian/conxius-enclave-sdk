# Deployment Verification Matrix

This matrix tracks the verification status across different deployment environments and lanes.

| Component | Managed (Verified) | Enterprise (Verified) | Operator (Planned) |
| -- | -- | -- | -- |
| Enclave (StrongBox) | ✅ | ✅ | ⏳ |
| Rail Proxy | ✅ | ✅ (Reconciliation) | ❌ |
| Asset Registry | ✅ | ✅ | ⏳ |
| MMR State | ✅ | ⏳ | ❌ |

## Verification Status
- **Managed Lane**: 100% Verified for Bitcoin L1/Lightning.
- **Enterprise Lane**: Core reconciliation logic implemented. Pilot phase active.
- **Operator Lane**: Planned for Q3 2026.

## Gaps
- Operator-level node attestation.
- Real-time yield-split verification for productive streaming.
