# Deployment Verification Matrix

This matrix tracks repository/control-plane verification across deployment
environments and lanes. **Verified** means that the named repository evidence
or control was checked at the recorded scope; it does not imply a live
provider, hardware-backed attestation, production deployment, release
acceptance, or independent review.

| Component | Managed (Repository evidence) | Enterprise (Repository evidence) | Operator (Planned) |
| -- | -- | -- | -- |
| Enclave (StrongBox) | Conditional evidence only | Conditional evidence only | ⏳ |
| Rail Proxy | Containment evidence only | Reconciliation code evidence only | ❌ |
| Asset Registry | Repository tests only | Repository tests only | ⏳ |
| MMR State | Repository tests only | Not evidenced | ❌ |

## Verification Status
- **Managed Lane**: Repository/control-plane checks are recorded; this is not
  live Bitcoin/Lightning, hardware, provider, or production evidence.
- **Enterprise Lane**: Core reconciliation logic is implemented in the
  repository; deployment, provider, operator, and pilot acceptance remain
  separate gates.
- **Operator Lane**: Planned; no support claim is made.

## Gaps
- Operator-level node attestation.
- Real-time yield-split verification for productive streaming.
