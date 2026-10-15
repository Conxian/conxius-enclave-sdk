# Provider-bound policy digest v2

Work: SDK #558/#240/#202. The attestation-policy digest now uses `CONXIAN-ATTESTATION-POLICY/v2` and big-endian version 2. Provider identity remains bound. This is separate from the signed report envelope version and value-bearing binding version.

The production-policy known vector is `a70ee922a269eebb7b4aea95199c0f5b2ddfbe83d7014d425f178b53a33c252a`. The prior provider-bound bytes labelled v1 produced `b40365a05a2a11c791c57ff78deddf7565456f820c45ea73f1839257529e1465`. The default fixture encodes levels [2,3], age 300, future skew 30, signing purpose, Ed25519, PurposeSign extension, no selected provider and unavailable provider verifier. The test pins the independent digest rather than accepting a silent format transition.

Consumers must rebuild policy-bound requests and reject obsolete digests; there is no v1 fallback. Never reset or discard consumed nonce/replay records during migration. Retain prior records for their entire replay lifetime, drain outstanding reservations and reauthorize pending requests under v2 before transition. Do not translate an existing release authorization into the new digest automatically. Independent review and operation-specific release acceptance remain required.

PKCS#11 discovery reads exact DER `CKA_EC_PARAMS` for EC keys and actual public `CKA_MODULUS` bit length for RSA private-key objects. Unsupported, unavailable and malformed parameters are Unknown. RSA-3072 is not silently advertised as RSA-2048. Named key parameters are inventory only: mechanism availability, non-exportability, module provenance, hardware attestation and operational qualification remain separate gates.

Sources: [OASIS PKCS#11 current mechanisms](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html), [cryptoki attributes](https://docs.rs/cryptoki/0.12.1/cryptoki/object/enum.Attribute.html). Generic metadata cannot establish hardware backing.

## Residual qualification work

The current process-wide PKCS#11 context caches the first initialized module. Separate module instances must not be assumed isolated without a module-bound context design and real module tests; SDK #240 remains the owner. Public algorithm parameters alone do not qualify signers or resolve that provider-isolation work.
