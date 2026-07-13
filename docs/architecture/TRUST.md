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

## 3. Release Discipline
- **Mainnet-Only Standard**: The `main` branch contains only mainnet-ready, production-quality code. All testnet or validation work is isolated to `dev` or `staged` branches.
- **Continuous Hygiene**: We perform regular audits for secret exposure, dependency drift, and simulated/mock residue in production paths.
- **Versioning**: We follow Semantic Versioning (SemVer) and maintain a consistent `CHANGELOG.md` across all core repositories.

## 4. Cryptographic Proof
- **Sovereign Handshake**: Users retain full control over their assets. Transaction intents are signed locally within the user's hardware enclave before being broadcast to liquidity rails.
- **State Attestation**: We use Merkle Mountain Ranges (MMR) for institutional state attestation, providing cryptographic proof of inclusion for system state.
