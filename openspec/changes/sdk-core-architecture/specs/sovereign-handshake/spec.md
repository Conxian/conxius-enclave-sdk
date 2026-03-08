## MODIFIED Requirements

### Requirement: Multi-Phase Signing Intent
The system SHALL implement a multi-phase signing workflow (Prepare, Verify, Sign, Broadcast) where each phase is cryptographically linked.

#### Scenario: Successful Sovereign Handshake
- **WHEN** the Gateway pushes a `SwapIntent` to the Enclave
- **THEN** the Enclave verifies the intent hash, signs it if the user approves, and returns the signature with a hardware attestation report
