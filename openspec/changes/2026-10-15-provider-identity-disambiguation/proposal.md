# Disambiguate provider identities without changing trust

Work: SDK #558/#240/#202 and Business #1390. Reconciles the remaining classification changes in SDK #557 against current dev.

Retain the existing provider vocabulary and provider-bound policy digest v2. Reject names for different technologies or unspecified implementations instead of mapping TDX to SGX, CCA to TrustZone, generic SEV to SEV-SNP, KeyMint to StrongBox, or ambiguous Keystone/Secure Enclave/HSM labels to a specific implementation.

Expose a report's single declared provider as an explicitly unverified claim for diagnostic consumers. Missing, duplicate or contradictory provider extensions produce no claim. Declaring a provider never establishes provenance, signing algorithms, custody, hardware backing or production qualification.

Preserve all verification, replay, policy, disabled-feature and public-proof safeguards. Validate canonical identifiers, safe aliases, ambiguous-token rejection, conflicting declarations and the production verification boundary, then run the all-feature suite, strict Clippy and inventory/proof validators. No cloud resources or signing settings change.
