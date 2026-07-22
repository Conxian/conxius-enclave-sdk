# Trust, Governance & Proof (CON-300)

Conxian is committed to providing high-integrity, hardware-secure infrastructure for the Bitcoin ecosystem. Our trust model is built on transparency, cryptographic proof, and strict architectural boundaries.

## 1. Security Posture
- **Zero Secret Egress**: We enforce a strict policy where private keys never leave the hardware enclave. Signing and key generation are isolated from the application layer.
- **Hardware Attestation**: Every high-value operation requires a verified hardware integrity report, ensuring that the execution environment has not been tampered with.
- **Fail-Closed Logic**: Our protocols are designed to fail closed. In the event of an infrastructure or network failure, no funds or secrets are exposed.

## 2. Governance Standards
- **Architectural Boundaries**: We maintain clear separations between core security logic (SDK), shared protocols (Core), and application-level implementations (Wallet/Gateway).
- **Code Ownership**: All critical repositories have defined owners and require mandatory peer reviews for any changes to production paths.
- **Public/Private Boundary**: We strictly sanitize all public repositories to ensure no non-public strategic, legal, or operational material is exposed.

## 3. Release Discipline (target architecture, not current status)
- **Protected-branch intent**: The project targets a reviewed `main` branch for releasable changes; branch protection and review records are not evidence that every current checkout is mainnet-ready.
- **Continuous Hygiene**: We perform regular audits for secret exposure, dependency drift, and simulated/mock residue in production paths.
- **Versioning**: We follow Semantic Versioning (SemVer) and maintain a consistent `CHANGELOG.md` across all core repositories.

The SDK is currently **Beta / conditional**. Passing local tests, a merged
change, a workflow definition, or a package version does not establish
mainnet-ready code, provider support, hardware evidence, independent review,
or a verified release artifact. See `PRODUCTION_READINESS.md` and the
capability evidence matrix for the current decision boundary.

## 4. Cryptographic Proof
- **Sovereign Handshake**: Users retain full control over their assets. Transaction intents are signed locally within the user's hardware enclave before being broadcast to liquidity rails.
- **State Attestation**: We use Merkle Mountain Ranges (MMR) for institutional state attestation, providing cryptographic proof of inclusion for system state.
