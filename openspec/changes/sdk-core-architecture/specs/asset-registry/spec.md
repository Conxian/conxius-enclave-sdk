## ADDED Requirements

### Requirement: Asset Metadata
The system SHALL maintain a registry of assets, where each entry MUST include: name, symbol, decimals, and the chain identifier it resides on.

#### Scenario: Validating an asset for a swap
- **WHEN** a swap is requested with an asset symbol
- **THEN** the system resolves the metadata and ensures it is active on the source/destination chain

### Requirement: Custom Asset Registration
The system SHALL allow developers to register custom or new assets locally within their SDK instance to support new tokens or chains before they are added to the global registry.

#### Scenario: Adding a new token to the SDK
- **WHEN** a developer registers a new asset with its properties
- **THEN** that asset becomes available for use in the `SwapRequest` validation
