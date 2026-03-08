## ADDED Requirements

### Requirement: Pluggable Enclave Trait
The SDK SHALL define a core trait (`EnclaveManager`) that abstracts all hardware-specific operations, allowing different implementations (StrongBox, Secure Enclave, HSM, WebKMS) to be swapped at runtime.

#### Scenario: Switching from Headless to Android StrongBox
- **WHEN** the SDK is initialized on an Android device
- **THEN** the Android-specific Enclave module is loaded without changing the protocol code

### Requirement: Protocol Extensions
The system SHALL support an extension mechanism to add new cross-chain "Rails" or "Protocols" (e.g., adding a new bridge) by implementing a standardized interface.

#### Scenario: Adding a new bridge protocol
- **WHEN** a developer implements the `Rail` trait for a new bridge
- **THEN** the `RailProxy` can immediately dispatch transactions to it
