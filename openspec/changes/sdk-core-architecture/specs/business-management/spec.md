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
