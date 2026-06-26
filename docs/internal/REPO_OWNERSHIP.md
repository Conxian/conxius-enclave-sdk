# Repo ownership

## Purpose

`lib-conclave-sdk` is the secure signer and device trust layer for the Conxian builder platform.

## This repo owns

- enclave-backed signing abstractions
- secure execution and hardware trust integrations
- signer policy enforcement where tied to secure execution
- device trust and attestation support where relevant

## This repo does not own

- network adapters
- application orchestration
- wallet UX
- general platform runtime concerns

## Boundary rule

If the concern is about secure signing, device trust, or controlled key use, it belongs here. If it is about layer-specific broadcast, observation, or application behavior, it belongs elsewhere.

## Strategic role

Primary strategic repo.