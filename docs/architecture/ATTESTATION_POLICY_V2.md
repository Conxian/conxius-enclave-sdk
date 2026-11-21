# Provider-bound policy digest v2

Work: SDK #558/#240/#202. The attestation-policy digest now uses `CONXIAN-ATTESTATION-POLICY/v2` and big-endian version 2. Provider identity remains bound. This is separate from the signed report envelope version and value-bearing binding version.

The production-policy known vector is `a70ee922a269eebb7b4aea95199c0f5b2ddfbe83d7014d425f178b53a33c252a`. The prior provider-bound bytes labelled v1 produced `b40365a05a2a11c791c57ff78deddf7565456f820c45ea73f1839257529e1465`. The default fixture encodes levels [2,3], age 300, future skew 30, signing purpose, Ed25519, PurposeSign extension, no selected provider and unavailable provider verifier. The test pins the independent digest rather than accepting a silent format transition.

Consumers must rebuild policy-bound requests and reject obsolete digests; there is no v1 fallback. Never reset or discard consumed nonce/replay records during migration. Retain prior records for their entire replay lifetime, drain outstanding reservations and reauthorize pending requests under v2 before transition. Do not translate an existing release authorization into the new digest automatically. Independent review and operation-specific release acceptance remain required.

PKCS#11 discovery reads exact DER `CKA_EC_PARAMS` for EC keys and actual public `CKA_MODULUS` bit length for RSA private-key objects. Unsupported, unavailable and malformed parameters are Unknown. RSA-3072 is not silently advertised as RSA-2048. Named key parameters are inventory only: mechanism availability, non-exportability, module provenance, hardware attestation and operational qualification remain separate gates.

Sources: [OASIS PKCS#11 current mechanisms](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html), [cryptoki attributes](https://docs.rs/cryptoki/0.12.1/cryptoki/object/enum.Attribute.html). Generic metadata cannot establish hardware backing.

## Residual qualification work

The current process-wide PKCS#11 context caches the first initialized module. Separate module instances must not be assumed isolated without a module-bound context design and real module tests; SDK #240 remains the owner. Public algorithm parameters alone do not qualify signers or resolve that provider-isolation work.

## v3 — threshold operator-set binding (finding F3, #744)

The attestation-policy digest moved to `CONXIAN-ATTESTATION-POLICY/v3` and big-endian version 3, and the signed report envelope to `ATTESTATION_ENVELOPE_VERSION = 3`. v3 adds two inputs that v2 could not express:

- The **policy digest** now encodes an optional pinned ceremony operator set (`threshold_operator_ids`). When a policy pins the set, a composed threshold report's declared participants must be a subset of it with `shares.len() <= N`.
- The **signed envelope** now carries `threshold_participants` for composed reports: one `{ participant_id, device_public_key }` per share. The verifier requires pairwise-distinct participant ids, pairwise-distinct device keys, and each `device_public_key` to equal the leaf key that signed its share report. A single device can no longer satisfy an M-of-N quorum by replaying its own report M times.

v2 composites are rejected: a v2 report has `report_version = 2` and no participant list, so `verify_threshold_composition` fails closed. The production-policy known vector for v3 is `99689c577b290a4d01554d9405e1959dec840bd5e2688353c547ef7ac01daea4` (independently recomputed from the documented encoding, not copied from the implementation). The v2 vector `a70ee922…` and legacy v1 `b40365a0…` are retained above as historical evidence and are asserted *not* to alias the v3 digest.
