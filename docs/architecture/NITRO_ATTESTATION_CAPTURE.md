# Nitro attestation capture path

Scope: the "request + capture" half of the AWS Nitro attestation pipeline
(SDK #242). Verification is the separate, offline `examples/nitro_attest_verify`
step. This note records why the original capture path could not produce valid
evidence, and the corrected design.

## Why the original path could not work

Three independent defects, each verified against AWS documentation:

1. **`nitro-cli run-enclave` does not print the enclave's stdout.** The script
   captured `nitro-cli run-enclave ... | tail -n 1` as if it were the base64
   attestation document. It is not: the command's stdout is the launch JSON
   (`EnclaveID`, `EnclaveCID`, `ProcessID`, …). The document never appeared on
   that stream.

2. **The enclave console requires `--debug-mode`.** AWS states the console is
   readable only for an enclave launched with `--debug-mode`, and that enclaves
   launched that way "generate attestation documents with PCRs that are made up
   entirely of zeroes … cannot be used for cryptographic attestation." So even
   reading the console would yield all-zero PCRs — rejected by the verifier's
   policy and unusable as production evidence.

3. **The probe's inputs and reply channel were disconnected.** The probe read
   `user_data` / `nonce` / `public_key` from environment variables, but
   `nitro-cli run-enclave` provides no way to inject environment variables into
   the enclave process, so those inputs could never be set. The probe also wrote
   to a vsock port (5005) with **no listener** anywhere in the pipeline.

## Corrected design — vsock request/response

The enclave and parent exchange over a single vsock connection. This is the
AWS-standard pattern (the enclave connects out to the parent).

- **Enclave** (`scripts/nitro/enclave/src/main.rs`): connects to
  `VMADDR_CID_PARENT` (CID 3) on port 5005, reads three length-prefixed input
  fields, requests the NSM attestation document bound to them, and writes the
  base64 document back on the same socket.
- **Parent** (`scripts/nitro/vsock-capture.py`): listens on `VMADDR_CID_ANY`
  port 5005, accepts the enclave connection, sends the framed inputs, reads the
  document, and writes it to a file. It fails non-zero on timeout or empty
  capture, so a failed capture fails the pipeline.
- **Orchestration** (`scripts/nitro/run-attestation.sh`): launches the enclave
  **without** `--debug-mode` so the PCRs are real; starts the listener before
  the enclave; retrieves the document; then writes the verification request.
- **`user_data`** (`scripts/nitro/encode-release-binding.py`): encodes a
  `NitroReleaseBinding` with the exact byte layout of
  `src/enclave/nitro.rs`. A Rust test (`release_binding_matches_the_parent_encoder_vector`)
  pins the layout so the Python encoder and the Rust decoder cannot drift.

## AWS account id

The repo is public and its own convention (`docs/ORG_WIDE_PHASED_PLAN.md`)
redacts the AWS account id. The OIDC role ARN is therefore built from the
`AWS_ACCOUNT_ID` repository variable, and the CloudFormation `AwsAccountId`
parameter has no committed default — pass it at deploy time.

## Evidence boundary

This change is source and local checks only. It does **not** constitute a Nitro
or KMS attestation result. Real evidence requires running the pipeline on a real
Nitro instance with the pinned PCR policy, and remains tracked under #242 / #240
/ #202. The verifier already rejects debug/all-zero PCRs; this fix is what lets
the capture path produce a document that can pass that gate.

## Sources

- Nitro Enclaves user guide: cryptographic attestation, `nitro-cli run-enclave`,
  `nitro-cli console`, getting-started (all-zero debug PCRs).
- AWS KMS Developer Guide: `kms:RecipientAttestation:PCR<PCR_ID>` condition keys.
