# Conxius Enclave SDK architecture

Bitcoin L1 is the canonical trust/finality root for universal-chain signing and authorization. Registry identifiers, protocol modules, and capability-evidence rows are distinct inventories. The [hardware driver refresh](docs/architecture/HARDWARE_DRIVER_QUALIFICATION_2026_10_14.md) and provider matrix record qualification limits; no count or provider label grants production signing authority.

This repository owns non-custodial signer and device-trust contracts. Keys must be generated and used inside the selected secure provider and must never cross the provider boundary. The SDK does not broadcast transactions, custody funds, operate cloud infrastructure, or decide business policy.

The public `conxian.org` surface consists of reusable request, evidence, replay, signing, and verification contracts. Conxian-Labs may sell integration, provider qualification, deployment support, and independent security review through `conxian-labs.com`; those services do not change the public cryptographic rules.

Android support currently provides bounded KeyMint/StrongBox authorization request and evidence types. It does not yet verify Google roots, certificate revocation, KeyMint authorization lists, or Play Integrity server-side, and it has no production hardware signer adapter. `CoreEnclaveManager` is a software development fixture and cannot authorize value-bearing production use.

Conxian has no native token, staking asset, or speculative tokenomics. This SDK signs caller-supplied digests only after the relevant provider, attestation, replay, and policy gates succeed.

