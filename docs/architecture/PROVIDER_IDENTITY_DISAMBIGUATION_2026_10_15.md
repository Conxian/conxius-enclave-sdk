# Provider identity and unverified claims

SDK #557's useful typed vocabulary is already present in dev via #560 and #565. This follow-up preserves that vocabulary, exact PKCS#11 parameter discovery, policy digest v2, public signing proof and fail-closed provider verification. Provider-wide curve claims, token metadata as hardware provenance, and attestation-format-to-chipset inference are not accepted.

`HardwareProviderType::from_str_token` now rejects TDX, ARM_CCA, AMD_SEV/SEV, KEYMINT, KEYSTONE, SECURE_ENCLAVE and HSM. These previously mapped different technologies or generic names into a specific provider. Configure the actual canonical identity after reviewing its evidence; do not automatically translate these rejected values. The existing canonical provider tokens and unambiguous aliases remain supported. This input tightening does not change enum encoding, report envelope version or policy digest v2, and does not add a verifier for an unsupported technology.

`DeviceIntegrityReport::claimed_hardware_provider` returns one declared provider for diagnostics, or None when absent, duplicated or contradictory. The method does not verify a signature, provider identity, hardware backing, algorithm, key custody or operational qualification. Authorization must still use the full independently configured verifier and policy.

Primary references reviewed on 2026-10-15:

- [Intel TDX scope versus application-level SGX](https://www.intel.com/content/www/us/en/support/articles/000097227/processors/intel-xeon-processors.html).
- [Android Key/ID attestation and distinct KeyMint security levels](https://source.android.com/docs/security/features/keystore/attestation).
- [Arm CCA adds Realm and Root worlds to the TrustZone model](https://learn.arm.com/learning-paths/cross-platform/cca_rme/cca/).
- [AMD SEV-SNP isolation and attestation differ from SEV/SEV-ES](https://docs.amd.com/api/khub/documents/~uAtQszeypAVVEk_B91Ojg/content).
- [Existing driver qualification boundaries, including Keystone wallet versus RISC-V TEE](HARDWARE_DRIVER_QUALIFICATION_2026_10_14.md).

Acceptance remains operation-specific. Neither a provider name nor this diagnostic method upgrades any production support status.
