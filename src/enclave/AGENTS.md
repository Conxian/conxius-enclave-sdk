# Provider and policy evidence

Read `docs/architecture/ATTESTATION_POLICY_V2.md` before changing policy encoding or PKCS#11 discovery. Provider selection is part of policy digest v2; do not restore a v1 label, accept legacy digests as aliases, discard replay history, or migrate release authority implicitly.

PKCS#11 key classes do not identify a curve or RSA size. Read exact public parameters and leave unavailable/unsupported parameters Unknown. Metadata, named curves and mechanism discovery do not prove hardware custody, non-exportability or production support. Keep missing-feature operations fail closed.

Conxian remains universal-chain and Bitcoin-rooted. Classification must preserve supported algorithms accurately without inventing Bitcoin signing or hardware qualification. Validate all-feature and feature-disabled paths, strict Clippy, format, capability inventories and public conformance proof before publication.
