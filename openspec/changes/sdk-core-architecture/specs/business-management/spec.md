## ADDED Requirements

### Requirement: Business Identity
The system SHALL provide a unique, cryptographically-verifiable identity for any business or affiliate (partner). This identity SHALL be based on a public key generated within the enclave.

#### Scenario: Registering a new business
- **WHEN** a new partner requests onboarding
- **THEN** the Enclave generates a new business key-pair and returns the public identity

### Requirement: Attribution Signing
The system SHALL support signing attribution proofs for transactions that include the business identity and a nonce to prevent replay attacks.

#### Scenario: User clicks an affiliate link
- **WHEN** the user initiates a swap with a business ID
- **THEN** the SDK generates a signed proof linking the user session to that business

### Requirement: Attribution Verification
The system SHALL verify the cryptographic signature of attribution proofs against the partner's registered public key before executing high-value operations.

#### Scenario: Verify attribution during swap
- **WHEN** a swap intent is broadcasted with business attribution
- **THEN** the RailProxy verifies the attribution signature and expiration before proceeding
