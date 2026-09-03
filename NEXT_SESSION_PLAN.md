# Next Session Plan

> **For**: OpenHands AI Agent  
> **Context**: Continuing Conxius Enclave SDK v2.0.17 development
> **Priority Order**: Remaining P0 gates â†’ P1 â†’ P2
> **Knowledge Base**: v0.7.0 (Session 62, Aug 2026)
> **Last Session**: Session 65 — doc-vs-code audit (module count + MSRV) remediation


## Session 66 Completed (2026-09-03) — Fedimint DLEQ proof integration (PROTO-001)

### ✅ Fedimint DLEQ proof wiring
- Wired `DleqProof::verify`, `FedimintAdapter::create_dleq_proof`, and `FedimintAdapter::create_blind_signature_request` in `src/protocol/nexus/fedimint.rs` to the real BLS12-381 `fedimint_crypto` backend under `#[cfg(feature = "fedimint-crypto")]`.
- Enforced fail-closed `ProtocolUnsupported` behavior when `fedimint-crypto` is disabled.
- Unit tests added for genuine proof verification, tampered proof rejection, and feature-gated fallback.

---

## Session 65 Completed (2026-09-01) — doc-vs-code audit (module count + MSRV) remediation

### ✅ Protocol module recount (SDK + core)
- Recounted `src/protocol/mod.rs` (43 non-test `pub mod` declarations): **43 protocol modules = 25 blockchain + 18 infrastructure**.
- Corrected `AGENTS.md` header (was "50 Modules (25 + 25)"; infrastructure list actually has 18, not 25), `Directory Map` ("50" → "43"), and removed the `enclave-poc/` references (Nitro POC lives in `lib-conxian-core`, not this repo).
- Corrected `lib-conxian-core/AGENTS.md` cross-reference ("52 (24 + 28)" → "43 (25 + 18)").

### ✅ MSRV regression fixed (core)
- `lib-conxian-core/Cargo.toml` `rust-version` was `1.94.0`, contradicting the v0.3.0 CHANGELOG ("Raised the package MSRV to Rust 1.97.1"), all docs (README/COMPATIBILITY/RELEASE_PROCESS/COVERAGE), and every sub-crate (tests + addons at `1.97.1`). Restored to `1.97.1`.

---

## Session 64 Completed (2026-08-31) — KB audit + live verification + crates.io cleanup

### ✅ KB → code → CI audit
- Read all KBs; aligned with verified repo/cross-repo state (module count 50, `re_exports.rs`→`lib.rs`, `SystemState`→`EnclaveManager`, v2.0.17, 42 chains, MSRV 1.97.1).

### ✅ Live verification (first full toolchain run)
- Rust 1.97.1: `cargo test --locked` 629 passed; `--all-features` 645 passed; `fmt` + `clippy -D warnings` clean.

### ✅ Dependency security scan
- `cargo audit` 0 vulns; `cargo deny` ok. Added `RUSTSEC-2023-0089` to `.cargo/audit.toml`; removed orphaned root `audit.toml`; reconciled DEP-002.

### ✅ crates.io cleanup
- Yanked `lib-conclave-sdk@2.0.8` (DEP-003 resolved) + `anya-core@1.2.0`.

### PRs
- #329 merged (this work).

---

## Session 63 Completed (2026-08-30) — Dependency spine + release remediation

### ✅ Yanked-crate purge (org-wide, P0 #320)
- `bitcoin 0.33.0-beta` → `0.32.102`, `secp256k1 0.32.0-beta.2` → `0.33.1` across SDK, `lib-conxian-core`, and `conxian-nexus`. Yanked crate = 0 occurrences in all three Rust lockfiles. PRs #321, #281, #280 (lib-core), #255 (nexus) merged.

### ✅ v2.0.17 release + CI remediation
- v2.0.17 released to crates.io (first tag free of the yanked crate). PRs #325 (bump), #326 (User-Agent 403 fix) merged.
- **Root-caused** the missing GitHub Releases: `verify-registry-artifact.sh` curl lacked `User-Agent` → crates.io 403 since v2.0.16.
- Backfilled GitHub Releases v2.0.16 + v2.0.17 manually; #327 (recovery tag-gate fix) **merged** (approved by `admin-conxian-labs`) and #328 (KB audit session 63) **merged** — release recovery can now run without a tag ref.

### ✅ Cross-repo hygiene
- Closed broken dependabot PRs: gateway #350 (Rust group break), Conxian #700 (npm lock drift).

---


## Session 60 Completed (2026-08-08)

### âś… Comprehensive System Audit & Candidate 75-Point Scoring
- Audited remaining open issues and open PRs; updated 75-point candidate scoring matrix and selected `#271` (LDK Lightning Payment Execution Engine) as top candidate (71/75).

### âś… LDK Lightning Payment Execution Engine (#271)
- Implemented `parse_and_validate_invoice` and `verify_settlement_preimage` in `src/protocol/lightning.rs`; `sign_htlc_transaction` in `src/signing/lightning_signing.rs`; unit tests.

## Session 61 Completed (2026-08-29)

### âś… Full cycle re-sync
- `git fetch --all`, `scripts/sync_issues.sh` (39 issues / 279 PRs), org-wide audit (Conxian, 14 repos), gap scan (0 TODO/FIXME; 3 placeholders in ucs/statechain/dlc).

### âś… Real Groth16 BLS12-381 pairing verification (#267) â€” P0
- Added `groth16 = ["dep:bls12_381"]` feature and `bls12_381 = "0.8"` (alloc/groups/pairings, optional).
- Rewrote `BitVm2Groth16Verifier::verify` to run the actual pairing equation and fail closed on malformed/off-curve/identity/arity-mismatch inputs; removed the prior fail-open path that returned `Valid` for arbitrary bytes.
- Tests: `groth16_verifier_verifies_genuine_proof`, `groth16_verifier_rejects_arity_mismatch`, `groth16_verifier_rejects_arbitrary_bytes_fail_closed`; clippy `-D warnings` clean; 564 (default) / 566 (groth16) tests pass.

---

## Session 62 Completed (2026-08-29)

### âś… #271 â€” channel state machine (code-actionable scope complete)
- `src/protocol/lightning_channel.rs`: fail-closed metadata `LightningChannel` (funding/open/HTLC-settle/fail/cooperative-close/force-close), conserved capacity invariant, monotonic `commitment_number`, SHA-256 preimage settlement.
- Remaining `#271` items are live LND/LDK commitment/revocation coordination + gossip-based pathfinding â€” provider integration (external to this crate).

### âś… #240 â€” durable ReplayStore provider (code-actionable scope complete)
- `src/enclave/replay_store_file.rs`: `DurableFileReplayStore` (`ReplayStoreDurability::DurableProvider`), passes the full backend-neutral consume-once conformance suite.
- Acceptance items 1,2,3,4,5,7 are code-complete; item 6 (artifact/SBOM/provenance/independent review) is external-blocked on #202.

---

## Session 63 â€” Planned

### P0: Unblock yanked `secp256k1` (#320)
- Bump `secp256k1` 0.32.0-beta.2 â†’ 0.33.0 (non-yanked) in this SDK; re-verify FROST (`frost-secp256k1-tr` v3.0.0) compatibility.
- `cargo generate-lockfile` succeeds; `cargo test --locked` + clippy clean; `frost` feature tests pass.
- Publish a patch release and bump the `conxius-enclave-sdk` pin in `lib-conxian-core` â†’ `conxian-nexus`, so nexus PR #250 can merge.
- **Research correction (Session 63):** bumping the direct `secp256k1` alone is **insufficient** â€” `bitcoin 0.33.0-beta` transitively depends on `secp256k1 ^0.32.0-beta.2` (yanked) and there is no stable `bitcoin 0.33.x` yet. A complete unblock also requires downgrading the direct `bitcoin` `0.33.0-beta` â†’ `0.32.102` (converging on the `bdk_wallet` line) or waiting for stable `bitcoin 0.33.0`. Also drop the removed `rand` feature when bumping `secp256k1` â†’ `0.33.x` (`features = ["recovery", "std"]`). Full analysis in `RESEARCH_LOG.md` (Session 63).

### P0: Finish the cross-repo replay/idempotency backend (conxian-nexus)
- ✅ `IdempotencyStore` PR #250 merged (2026-08-29). Remaining: wire to Neon `Conxian Nexus` (`DATABASE_URL` + run migration).
- Add the live-DB conformance suite (single/batch/restart/anti-rollback/retention/32-thread contention) mirroring `tests/durable_replay_conformance.rs` (nexus #251).

### P1: #271 â€” expand research + mainnet proofing (kept open)
- Research: BOLT12 offers, BIP-353, trampoline routing, splicing, async payments, MPP/AMP, blinded paths.
- Mainnet proofing: test vectors, signet/mainnet dry-runs vs LND/LDK, commitment/revocation interop.

### P0: Remaining provider/runtime evidence gates (external-blocked)
- `#242` AWS Nitro live attestation + KMS (AWS deployment); `#241` Android KeyMint/StrongBox (device); `#200` WASM runtime (headless browser/Node); `#240` item 6 / `#202` independent review (external).

### P1: Fedimint real threshold BLS blinding (DEBT PROTO-001)
- Replace Fedimint structural-only path with real BLS12-381 threshold blinding/DLEQ validation (now that `bls12_381` is a dependency).

---


## Session 67 Completed (2026-09-03) — BOLT12 Offers & BIP-353 Payment Domain Resolution (#271)

### ✅ BOLT12 Offer Parsing & BIP-353 Payment Address Support
- Implemented  and  structs with  methods in .
- Added unit tests for BOLT12 offer validation ( prefix, SHA-256 offer ID) and BIP-353 DNS payment domain addresses ().
- Verified zero clippy warnings and 586 passing unit/integration tests under
running 586 tests
test enclave::android_authorization::tests::empty_and_oversized_fields_are_rejected ... ok
test enclave::android_authorization::tests::debug_redacts_raw_provider_evidence ... ok
test enclave::android_authorization::tests::android_tee_policy_accepts_tee_and_strongbox_but_not_software ... ok
test enclave::android_authorization::tests::mismatched_request_fields_are_rejected_without_fallback ... ok
test enclave::android_authorization::tests::every_public_binding_method_rejects_stale_expired_and_future_evidence ... ok
test enclave::android_authorization::tests::missing_play_integrity_evidence_is_rejected ... ok
test enclave::android_authorization::tests::binding_changes_when_security_context_or_evidence_changes ... ok
test enclave::android_authorization::tests::positive_structural_boundary_is_canonical_and_deterministic ... ok
test enclave::android_authorization::tests::phone_route_is_explicit_android_keymint_but_production_unavailable ... ok
test enclave::android_authorization::tests::strongbox_required_rejects_android_tee_downgrade ... ok
test enclave::android_authorization::tests::serde_rejects_unknown_and_private_key_fields ... ok
test enclave::android_strongbox::tests::software_strongbox_schnorr_matches_bip340_known_answer ... ok
test enclave::android_authorization::tests::serde_bounds_nested_der_and_play_evidence ... ok
test enclave::android_strongbox::tests::software_strongbox_ed25519_fails_closed_as_unsupported ... ok
test enclave::android_strongbox::tests::software_strongbox_taproot_schnorr_normalizes_odd_internal_secret ... ok
test enclave::android_strongbox::tests::software_strongbox_taproot_schnorr_preserves_even_internal_secret_behavior ... ok
test enclave::android_strongbox::tests::software_strongbox_taproot_schnorr_rejects_invalid_tweak_and_result_keys ... ok
test enclave::attestation::tests::attacker_key_with_trusted_label_is_rejected ... ok
test enclave::attestation::tests::changing_signed_security_fields_invalidates_report ... ok
test enclave::attestation::tests::changing_signed_value_bearing_binding_invalidates_report ... ok
test enclave::android_strongbox::tests::software_strongbox_ecdsa_signature_is_verifiable_and_nonzero ... ok
test enclave::attestation::tests::extension_matching_is_exact_not_substring_based ... ok
test enclave::attestation::tests::nitro_offline_policy_does_not_promote_production_provider_status ... ok
test enclave::attestation::tests::malformed_certificate_chain_is_rejected ... ok
test enclave::attestation::tests::report_type_and_version_are_signed ... ok
test enclave::attestation::tests::production_policy_rejects_generic_tee_and_is_unavailable ... ok
test enclave::attestation::tests::verify_accepts_report_within_freshness_window ... ok
test enclave::attestation::tests::typed_policy_rejects_wrong_purpose_and_algorithm ... ok
test enclave::attestation::tests::verify_rejects_clock_failure_before_provider_evidence ... ok
test enclave::attestation::tests::verify_accepts_strongbox_report ... ok
test enclave::attestation::tests::verify_rejects_stale_report ... ok
test enclave::attestation::tests::verify_rejects_invalid_signature ... ok
test enclave::cloud::tests::cloud_ecdsa_signature_is_verifiable_and_nonzero ... ok
test enclave::attestation::tests::verify_rejects_untrusted_root ... ok
test enclave::cloud::tests::cloud_schnorr_signing_is_explicitly_unsupported ... ok
test enclave::cloud::tests::cloud_ed25519_signature_is_verifiable_and_nonzero ... ok
test enclave::cloud::tests::cloud_test_fixture_attestation_is_not_production_evidence ... ok
test enclave::android_strongbox::tests::software_strongbox_schnorr_matches_bip340_reference_vector ... ok
test enclave::android_strongbox::tests::software_strongbox_schnorr_signature_is_verifiable_and_nonzero ... ok
test enclave::durable_replay::tests::fake_store_is_consumed_idempotent_conflicting_and_atomic ... ok
test enclave::durable_replay::tests::file_backed_store_fails_closed_on_expiry_and_rollback ... ok
test enclave::durable_replay::tests::file_backed_store_is_durable_across_restart ... ok
test enclave::durable_replay::tests::file_backed_store_is_idempotent_and_conflict_safe ... ok
test enclave::durable_replay::tests::file_backed_store_unavailable_when_dir_creation_fails ... ok
test enclave::durable_replay::tests::expiry_and_clock_rollback_fail_closed ... ok
test enclave::durable_replay::tests::idempotency_key_is_bounded_and_distinct_from_identity ... ok
test enclave::durable_replay::tests::identity_canonical_encoding_binds_every_field ... ok
test enclave::durable_replay::tests::file_backed_store_authorizer_end_to_end ... ok
test enclave::durable_replay::tests::forward_time_recovers_after_rejected_rollback ... ok
test enclave::durable_replay::tests::test_durable_replay_conditional_write_conformance ... ok
test enclave::durable_replay::tests::authorizer_rejects_expiry_and_rollback_before_store_invocation ... ok
test enclave::durable_replay::tests::mock_backend_conditional_write_semantics ... ok
test enclave::enclave_tests::attestation_leaf_operation_key_mismatch_is_rejected_after_report_verification ... ok
test enclave::durable_replay::tests::no_raw_evidence_enters_identity_or_audit ... ok
test enclave::enclave_tests::changing_requested_operation_purpose_is_rejected ... ok
test enclave::enclave_tests::current_managers_are_software_unverified ... ok
test enclave::enclave_tests::current_managers_reject_value_bearing_unlock_and_signing ... ok
test enclave::enclave_tests::default_manager_cannot_pass_value_bearing_boundary ... ok
test enclave::durable_replay::tests::wrapper_authorizes_only_consumed_or_confirmed_idempotent ... ok
test enclave::enclave_tests::ecdsa_recovery_id_mismatch_with_bound_key_is_rejected ... ok
test enclave::enclave_tests::ecdsa_recovery_id_for_bound_key_is_accepted ... ok
test enclave::durable_replay::tests::unavailable_store_status_and_non_good_result_fail_closed ... ok
test enclave::enclave_tests::malformed_provider_response_is_rejected_before_signature_use ... ok
test enclave::enclave_tests::migrated_primary_signers_never_call_legacy_raw_sign_when_typed_signing_rejects ... ok
test enclave::enclave_tests::complete_attestation_policy_rejects_wrong_root_purpose_algorithm_nonce_and_stale_report ... ok
test enclave::enclave_tests::public_value_bearing_signing_requires_durable_replay_before_provider ... ok
test enclave::enclave_tests::production_value_signing_rejects_simulated_provider ... ok
test enclave::enclave_tests::invalid_provider_evidence_does_not_consume_replay_state_and_valid_replay_is_rejected ... ok
test enclave::enclave_tests::signed_binding_rejects_algorithm_tampering ... ok
test enclave::enclave_tests::signed_binding_rejects_derivation_path_tampering ... ok
test enclave::enclave_tests::invalid_key_binding_does_not_consume_replay_state ... ok
test enclave::enclave_tests::signed_binding_rejects_expected_public_key_tampering ... ok
test enclave::enclave_tests::signed_binding_rejects_key_id_tampering ... ok
test enclave::enclave_tests::signed_binding_rejects_operation_digest_tampering ... ok
test enclave::enclave_tests::software_attestation_cannot_be_promoted_to_value_bearing ... ok
test enclave::enclave_tests::software_capability_cannot_create_value_bearing_session ... ok
test enclave::enclave_tests::signed_binding_rejects_operation_purpose_tampering ... ok
test enclave::enclave_tests::signed_binding_rejects_purpose_tampering ... ok
test enclave::enclave_tests::trusted_security_clock_rejects_pre_epoch_without_defaulting_to_zero ... ok
test enclave::enclave_tests::software_manager_cannot_satisfy_migrated_primary_signers ... ok
test enclave::enclave_tests::valid_report_and_signature_from_different_operation_key_are_rejected ... ok
test enclave::enclave_tests::signed_binding_rejects_returned_public_key_tampering ... ok
test enclave::enclave_tests::value_bearing_provider_response_requires_attestation ... ok
test enclave::enclave_tests::test_cloud_enclave_ed25519_signing_remains_non_production ... ok
test enclave::enclave_tests::value_bearing_request_is_domain_separated_and_key_bound ... ok
test enclave::hardware_attestation_tests::crypto_verification_tests::test_cloud_tee_requires_hardware_hardening ... ok
test enclave::enclave_tests::typed_provider_response_requires_attestation_leaf_operation_key_binding ... ok
test enclave::hardware_attestation_tests::crypto_verification_tests::test_rejects_invalid_signature ... ok
test enclave::hardware_attestation_tests::crypto_verification_tests::test_rejects_untrusted_root_ca ... ok
test enclave::hardware_attestation_tests::edge_case_tests::test_empty_certificate_chain_rejected ... ok
test enclave::hardware_attestation_tests::edge_case_tests::test_empty_signature_rejected ... ok
test enclave::hardware_attestation_tests::edge_case_tests::test_replay_guard_concurrent_access ... ok
test enclave::hardware_attestation_tests::edge_case_tests::test_single_certificate_rejected ... ok
test enclave::hardware_attestation_tests::edge_case_tests::test_verify_with_policy_result_fails_closed ... ok
test enclave::hardware_attestation_tests::fingerprint_tests::test_different_certs_produce_different_fingerprints ... ok
test enclave::hardware_attestation_tests::fingerprint_tests::test_fingerprint_deterministic ... ok
test enclave::hardware_attestation_tests::crypto_verification_tests::test_strongbox_requires_hardware_hardening ... ok
test enclave::hardware_attestation_tests::freshness_tests::test_rejects_future_timestamp ... ok
test enclave::hardware_attestation_tests::freshness_tests::test_rejects_stale_attestation ... ok
test enclave::hardware_attestation_tests::freshness_tests::test_rejects_wrong_nonce ... ok
test enclave::hardware_attestation_tests::freshness_tests::test_replay_guard_allows_after_ttl ... ok
test enclave::hardware_attestation_tests::freshness_tests::test_replay_guard_blocks_duplicate_attestation ... ok
test enclave::hardware_attestation_tests::trust_enforcement_tests::test_cloud_tee_is_production_trust ... ok
test enclave::hardware_attestation_tests::freshness_tests::test_accepts_fresh_attestation ... ok
test enclave::hardware_attestation_tests::trust_enforcement_tests::test_software_is_development_only ... ok
test enclave::hardware_attestation_tests::trust_enforcement_tests::test_strongbox_is_production_trust ... ok
test enclave::hardware_attestation_tests::trust_enforcement_tests::test_tee_is_development_trust ... ok
test enclave::enclave_tests::value_bearing_clock_failure_precedes_provider_and_replay_recording ... ok
test enclave::hardware_attestation_tests::trust_enforcement_tests::test_production_signing_requires_hardware_attestation ... ok
test enclave::hardware_attestation_tests::trust_tier_tests::test_cloud_tee_attestation_valid ... ok
test enclave::hardware_attestation_tests::trust_tier_tests::test_software_attestation_blocked_for_production ... ok
test enclave::hardware_attestation_tests::trust_tier_tests::test_strongbox_attestation_valid ... ok
test enclave::hardware_attestation_tests::trust_tier_tests::test_tee_attestation_valid ... ok
test enclave::enclave_tests::value_bearing_replay_saturation_fails_closed_without_live_eviction ... ok
test enclave::nitro::tests::rejects_deeply_nested_bounded_cbor ... ok
test enclave::nitro::tests::rejects_malformed_weak_and_unsupported_rsa_recipient_keys ... ok
test enclave::nitro::tests::parses_tagged_and_untagged_cose_with_real_p384_signature ... ok
test enclave::nitro::tests::rejects_malformed_cose_bounds_and_payload_types ... ok
test enclave::nitro::tests::rejects_recipient_plaintext_and_wrong_algorithm ... ok
test enclave::nitro::tests::rejects_reserved_indefinite_and_truncated_cbor_before_materialization ... ok
test enclave::nitro::tests::invalid_cose_signature_cannot_be_compensated_by_matching_bindings_or_trust ... ok
test enclave::nitro::tests::rejects_zero_kms_key_identifier_hash ... ok
test enclave::nitro::tests::rejects_zero_operation_digest ... ok
test enclave::nitro::tests::rejects_zero_policy_digest ... ok
test enclave::nitro::tests::rejects_zero_replay_identity ... ok
test enclave::nitro::tests::release_binding_is_deterministic_and_rejects_trailing_data ... ok
test enclave::nitro::tests::rejects_missing_payload_wrong_algorithm_duplicates_and_trailing_data ... ok
test enclave::nitro::tests::rejects_unknown_and_duplicate_payload_fields_and_invalid_pcrs ... ok
test enclave::proof::tests::all_six_proof_categories_verify_independently_and_compose ... ok
test enclave::proof::tests::canonical_context_and_proof_set_are_domain_separated_and_order_independent ... ok
test enclave::proof::tests::duplicate_conflicting_and_partial_sets_are_rejected ... ok
test enclave::proof::tests::independent_context_mismatches_are_typed_and_fail_closed ... ok
test enclave::proof::tests::mismatches_and_type_substitution_are_diagnosed_without_raw_evidence ... ok
test enclave::proof::tests::policy_digest_binds_exact_fields_and_requirement_order_is_canonical ... ok
test enclave::proof::tests::production_verifier_and_fixture_policy_boundaries_fail_closed ... ok
test enclave::proof::tests::raw_evidence_debug_does_not_expose_evidence_bytes ... ok
test enclave::proof::tests::stale_future_malformed_and_bound_errors_fail_closed ... ok
test enclave::proofs::tests::accepts_a_proof_within_the_configured_future_skew ... ok
test enclave::proofs::tests::bounded_deserialization_rejects_oversized_security_fields_and_sequences ... ok
test enclave::proofs::tests::bounded_transport_entry_point_rejects_oversized_input ... ok
test enclave::nitro::tests::trust_boundary_is_not_called_after_signature_or_policy_failure ... ok
test enclave::proofs::tests::bounded_transport_rejects_unknown_fields_before_provider_verification ... ok
test enclave::proofs::tests::capacity_failure_does_not_partially_insert_bundle_replay_keys ... ok
test enclave::proofs::tests::complete_replay_binding_store_path_is_atomic_and_ordered ... ok
test enclave::proofs::tests::durable_authorization_requires_exact_canonical_production_policy ... ok
test enclave::nitro::tests::rejects_missing_mismatched_and_all_zero_required_pcrs_or_expired_binding ... ok
test enclave::proofs::tests::durable_final_signing_fails_closed_before_provider_on_uncertain_store ... ok
test enclave::proofs::tests::durable_final_signing_consumes_operation_replay_once_across_managers ... ok
test enclave::proofs::tests::durable_final_signing_rejects_policy_digest_mutation ... ok
test enclave::proofs::tests::durable_final_signing_rejects_mismatched_request_policy_before_replay_and_provider ... ok
test enclave::proofs::tests::durable_final_signing_rejects_missing_request_policy_before_replay_and_provider ... ok
test enclave::proofs::tests::durable_store_gate_rejects_process_local_replay ... ok
test enclave::proofs::tests::effective_expiry_uses_the_first_proof_validity_boundary ... ok
test enclave::proofs::tests::empty_policy_and_bundle_cannot_create_value_bearing_authorization ... ok
test enclave::proofs::tests::exact_route_does_not_fallback_to_kind_only ... ok
test enclave::proofs::tests::indeterminate_replay_store_outcome_fails_closed ... ok
test enclave::proofs::tests::policy_digest_is_canonical_and_bound_to_verified_receipts ... ok
test enclave::proofs::tests::positive_test_only_all_six_composition_verifies_independently ... ok
test enclave::proofs::tests::production_registry_has_explicit_unavailable_routes ... ok
test enclave::proofs::tests::production_registry_rejects_a_well_shaped_all_six_bundle ... ok
test enclave::proofs::tests::process_local_replay_cannot_authorize_public_durable_value_path ... ok
test enclave::proofs::tests::proof_authorization_clock_failure_precedes_verification_and_replay_recording ... ok
test enclave::proofs::tests::proof_authorization_rechecks_expiry_before_hardware_signing_gate ... ok
test enclave::proofs::tests::proof_authorization_rejects_clock_rollback_after_expiry ... ok
test enclave::proofs::tests::proof_bundle_digest_is_order_independent ... ok
test enclave::proofs::tests::proof_policy_rejects_duplicate_required_kinds ... ok
test enclave::proofs::tests::proof_authorization_rejects_context_mismatch_before_signing ... ok
test enclave::proofs::tests::proof_signing_clock_failure_precedes_authorization_consumption ... ok
test enclave::proofs::tests::public_proof_authorization_ignores_caller_supplied_future_time ... ok
test enclave::proofs::tests::public_proof_signing_path_uses_trusted_clock_and_hardware_gate ... ok
test enclave::proofs::tests::public_settlement_authorization_ignores_caller_supplied_future_time ... ok
test enclave::proofs::tests::receipt_set_contains_only_digests_and_binding_metadata ... ok
test enclave::proofs::tests::rejects_duplicate_kind_and_duplicate_proof_id ... ok
test enclave::proofs::tests::rejects_invalid_evidence_and_cross_kind_substitution ... ok
test enclave::proofs::tests::reduced_policy_cannot_authorize_settlement_helper ... ok
test enclave::proofs::tests::rejects_missing_required_kind ... ok
test enclave::proofs::tests::rejects_unknown_serialized_fields ... ok
test enclave::proofs::tests::rejects_stale_future_and_expired_proofs ... ok
test enclave::proofs::tests::rejects_unsupported_version_and_malformed_bounds ... ok
test enclave::proofs::tests::rejects_unlisted_kinds_when_policy_is_explicitly_closed ... ok
test enclave::proofs::tests::rejects_wrong_digest_purpose_audience_and_nonce ... ok
test enclave::nitro::tests::verifies_policy_binding_nonce_public_key_and_injected_trust ... ok
test enclave::proofs::tests::replay_key_changes_for_each_security_relevant_component ... ok
test enclave::proofs::tests::replay_is_atomic_for_a_bundle ... ok
test enclave::proofs::tests::replay_is_rejected_after_legacy_ttl_before_proof_expiry ... ok
test enclave::proofs::tests::settlement_authorization_clock_failure_precedes_verification_and_replay_recording ... ok
test enclave::replay_guard::tests::accepts_new_key ... ok
test enclave::replay_guard::tests::allows_key_reuse_after_ttl_expiry ... ok
test enclave::proofs::tests::settlement_helper_binds_to_canonical_intent_and_domain ... ok
test enclave::replay_guard::tests::batch_outcome_count_is_derived_from_the_reservation_slice ... ok
test enclave::replay_guard::tests::batch_replay_is_atomic_on_capacity_saturation ... ok
test enclave::proofs::tests::weak_policy_cannot_authorize_value_bearing_operations ... ok
test enclave::replay_guard::tests::batch_replay_is_atomic_on_duplicate ... ok
test enclave::replay_guard::tests::bounded_batch_rejects_oversized_keys_before_recording ... ok
test enclave::replay_guard::tests::capacity_becomes_available_only_after_expiry ... ok
test enclave::replay_guard::tests::duplicate_failure_can_prune_expired_entries_without_inserting_new_keys ... ok
test enclave::proofs::tests::durable_final_signing_rejects_software_capability_before_replay_or_provider ... ok
test enclave::replay_guard::tests::horizon_aware_batch_retains_key_after_legacy_ttl ... ok
test enclave::replay_guard::tests::horizon_batch_failure_does_not_partially_insert_keys ... ok
test enclave::replay_guard::tests::rejects_clock_rollback_after_horizon_pruning_without_reinsertion ... ok
test enclave::replay_guard::tests::rejects_duplicate_key_within_window ... ok
test enclave::replay_guard::tests::rejects_new_keys_when_capacity_is_saturated ... ok
test enclave::replay_guard::tests::replay_binding_builder_debug_redacts_transient_inputs ... ok
test enclave::replay_guard::tests::canonical_binding_changes_for_every_security_dimension ... ok
test enclave::replay_guard::tests::replay_store_rejects_invalid_retention_and_clock_rollback ... ok
test enclave::replay_guard::tests::retention_horizon_is_exclusive_at_equality ... ok
test enclave::replay_guard::tests::replay_store_contract_is_atomic_and_secret_safe ... ok
test enclave::replay_guard::tests::zero_capacity_rejects_every_new_key ... ok
test enclave::replay_guard::tests::unavailable_backend_is_explicit ... ok
test enclave::replay_store_file::tests::file_store_fails_closed_on_validation ... ok
test enclave::trust::tests::anchor_duplicates_are_rejected_and_order_is_canonical ... ok
test enclave::replay_store_file::tests::file_store_survives_restart ... ok
test enclave::replay_store_file::tests::file_store_is_durable_provider_and_accept_then_duplicate ... ok
test enclave::replay_store_file::tests::file_store_batch_is_all_or_nothing ... ok
test enclave::trust::tests::monotonic_time_rejects_rollback_and_accepts_forward_observations ... ok
test enclave::trust::tests::mutations_to_payload_digest_signature_and_provider_fail_closed ... ok
test enclave::trust::tests::only_exact_policy_and_verifier_identity_can_authorize ... ok
test enclave::trust::tests::public_canonical_bytes_require_complete_validation ... ok
test enclave::trust::tests::canonical_result_changes_when_security_fields_change ... ok
test enclave::trust::tests::fixture_pipeline_produces_normalized_result_and_redacted_debug ... ok
test enclave::trust::tests::forged_context_freshness_time_is_replaced_before_provider_and_result ... ok
test enclave::trust::tests::unavailable_routes_and_clock_fail_closed ... ok
test enclave::trust::trust_bundle::tests::authenticated_digest_binds_route_source_and_receipt_identity ... ok
test enclave::trust::trust_bundle::tests::cache_caps_receipt_at_evidence_freshness_deadline ... ok
test enclave::trust::trust_bundle::tests::cache_requires_trusted_monotonic_time_and_rejects_expiry_equality ... ok
test enclave::trust::trust_bundle::tests::cache_rotates_and_rejects_sequence_rollback ... ok
test enclave::trust::trust_bundle::tests::canonical_digest_is_stable_across_set_order ... ok
test enclave::trust::trust_bundle::tests::debug_does_not_expose_signature_bytes ... ok
test enclave::trust::trust_bundle::tests::digest_and_signature_are_both_required ... ok
test enclave::trust::tests::signer_anchor_authorization_covers_rotation_status_validity_revision_and_constraints ... ok
test enclave::trust::tests::transport_rejects_unknown_fields_and_oversized_values ... ok
test enclave::trust::trust_bundle::tests::fixture_cannot_promote_to_production ... ok
test enclave::trust::trust_bundle::tests::malformed_and_oversized_content_is_rejected ... ok
test enclave::trust::trust_bundle::tests::production_registry_is_explicitly_unavailable ... ok
test enclave::trust::trust_bundle::tests::refresh_outage_and_recovery_are_explicit ... ok
test enclave::trust::trust_bundle::tests::refresh_unavailable_never_returns_expired_cached_trust ... ok
test enclave::trust_contracts::tests::authenticated_collateral_requires_an_unimplemented_authority_verifier ... ok
test enclave::trust_contracts::tests::collateral_expiry_is_strict_without_stale_grace ... ok
test enclave::trust_contracts::tests::collateral_future_and_revocation_states_fail_closed ... ok
test enclave::trust_contracts::tests::collateral_metadata_validates_without_raw_roots ... ok
test enclave::trust_contracts::tests::durable_backend_uncertainty_and_recovery_errors_are_typed ... ok
test enclave::trust_contracts::tests::every_replay_binding_field_changes_the_digest ... ok
test enclave::trust_contracts::tests::in_memory_store_rejects_expiry_ambiguity_and_clock_rollback ... ok
test enclave::trust_contracts::tests::in_memory_store_retains_consumed_identity_after_reservation_expiry ... ok
test enclave::trust_contracts::tests::provider_identity_only_maps_from_specific_existing_levels ... ok
test enclave::trust_contracts::tests::release_evidence_requires_exact_complete_consistent_scope ... ok
test enclave::trust_contracts::tests::release_evidence_schema_and_digest_mismatches_fail_closed ... ok
test enclave::trust_contracts::tests::replay_binding_debug_and_serialization_exclude_raw_sensitive_values ... ok
test enclave::trust_contracts::tests::replay_reservations_and_in_memory_store_are_atomic_and_non_production ... ok
test enclave::trust_contracts::tests::unknown_collateral_schema_and_root_mismatch_fail_closed ... ok
test enclave::verifiers::nitro_trust::tests::custom_root_ca_works ... ok
test enclave::verifiers::nitro_trust::tests::default_uses_embedded_root ... ok
test enclave::verifiers::nitro_trust::tests::root_ca_fingerprint_self_consistent ... ok
test enclave::verifiers::nitro_trust::tests::trust_boundary_constructs ... ok
test enclave::verifiers::nitro_verifier::tests::nitro_verifier_constructs ... ok
test enclave::verifiers::nitro_verifier::tests::root_ca_fingerprint_matches ... ok
test enclave::verifiers::oidc_verifier::tests::oidc_nonce_is_deterministic ... ok
test enclave::verifiers::oidc_verifier::tests::oidc_validate_claims_accepts_valid ... ok
test enclave::verifiers::oidc_verifier::tests::oidc_validate_claims_rejects_expired_token ... ok
test enclave::verifiers::oidc_verifier::tests::oidc_validate_claims_rejects_wrong_issuer ... ok
test enclave::verifiers::oidc_verifier::tests::oidc_verifier_constructs ... ok
test enclave::verifiers::pkcs11_verifier::tests::pkcs11_enumerate_slots_returns_ok ... ok
test enclave::verifiers::pkcs11_verifier::tests::pkcs11_key_type_classification ... ok
test enclave::verifiers::pkcs11_verifier::tests::pkcs11_verifier_constructs ... ok
test enclave::verifiers::webauthn_verifier::tests::attestation_formats_distinct ... ok
test enclave::verifiers::webauthn_verifier::tests::client_data_validation_accepts_valid ... ok
test enclave::verifiers::webauthn_verifier::tests::client_data_validation_rejects_wrong_type ... ok
test enclave::verifiers::webauthn_verifier::tests::webauthn_generate_challenge ... ok
test enclave::verifiers::webauthn_verifier::tests::webauthn_hardware_tier_classification ... ok
test enclave::verifiers::webauthn_verifier::tests::webauthn_verifier_constructs ... ok
test enclave::trust::trust_bundle::tests::evidence_freshness_enforces_bundle_interval_skew_and_age_boundaries ... ok
test protocol::account_abstraction::tests::canonical_action_shape_is_validated_without_execution_claim ... ok
test protocol::account_abstraction::tests::malformed_action_is_rejected_before_value_bearing_path ... ok
test protocol::account_abstraction::tests::module_network_context_cannot_be_zero ... ok
test protocol::account_abstraction::tests::module_setup_requires_provenance_after_local_validation ... ok
test protocol::ark::tests::all_value_bearing_ark_operations_are_exactly_unsupported_and_stateless ... ok
test protocol::ark::tests::backend_selection_accepts_only_the_safe_disabled_variant ... ok
test protocol::ark::tests::recovery_is_exactly_unsupported ... ok
test protocol::ark::tests::validates_typed_ids_versions_expiry_and_tree_shape ... ok
test protocol::ark::tests::vtxo_tree_empty_rejected ... ok
test protocol::ark::tests::vtxo_tree_power_of_two ... ok
test protocol::ark::tests::vtxo_tree_single_leaf ... ok
test protocol::ark::tests::with_backend_accepts_unconfigured_backend ... ok
test protocol::asset_tests::tests::canonical_eurc_is_active ... ok
test protocol::asset_tests::tests::canonical_mainnet_contract_asset_is_active ... ok
test protocol::asset_tests::tests::canonical_tron_usdt_passes_base58check_validation ... ok
test protocol::asset_tests::tests::canonical_usdc_address_checksum_is_valid ... ok
test protocol::asset_tests::tests::every_builtin_active_asset_has_canonical_metadata ... ok
test protocol::asset_tests::tests::malformed_checksum_cannot_be_registered_as_active ... ok
test protocol::asset_tests::tests::missing_contract_address_is_quarantined ... ok
test protocol::asset_tests::tests::placeholder_address_cannot_be_registered_as_active ... ok
test protocol::asset_tests::tests::test_expanded_bitcoin_network_registration ... ok
test protocol::asset_tests::tests::test_rsk_bob_registration ... ok
test protocol::asset_tests::tests::unregistered_asset_cannot_enter_value_bearing_paths ... ok
test protocol::asset_tests::tests::wrong_canonical_address_cannot_be_registered_as_active ... ok
test protocol::asset_tests::tests::wrong_network_is_rejected_before_asset_use ... ok
test protocol::babylon::tests::delegation_hash_is_deterministic ... ok
test protocol::babylon::tests::delegation_id_roundtrips ... ok
test protocol::babylon::tests::delegation_state_transitions ... ok
test protocol::bip110::tests::test_context_aware_witness_limits ... ok
test protocol::bip110::tests::test_core_transaction_shape_checks_all_measurements_and_boundaries ... ok
test protocol::bip110::tests::test_default_limits ... ok
test protocol::bip110::tests::test_message_chunking ... ok
test protocol::bip110::tests::test_message_chunking_long ... ok
test protocol::bip110::tests::test_ordered_commitment_segmentation ... ok
test protocol::bip110::tests::test_requires_chunking ... ok
test protocol::bip110::tests::test_validate_pushdata_boundaries ... ok
test protocol::bip110::tests::test_validate_script_pubkey_boundaries ... ok
test protocol::bip110::tests::test_validate_script_pushdata ... ok
test protocol::bip110::tests::test_with_limits_cannot_relax_consensus_maxima ... ok
test protocol::bip322::tests::test_bip322_canonical_to_spend_and_to_sign_vectors ... ok
test protocol::bip322::tests::test_bip322_explicit_network_policy_uses_bitcoin_address_semantics ... ok
test protocol::bip322::tests::test_bip322_full_and_proof_of_funds_reject_incomplete_material ... ok
test protocol::a2p::tests::test_prepare_otp_intent ... ok
test protocol::bip322::tests::test_bip322_malformed_inputs_do_not_panic ... ok
test protocol::bip322::tests::test_bip322_official_generated_p2tr_positive_vector ... ok
test protocol::bip322::tests::test_bip322_official_negative_vectors ... ok
test protocol::bip322::tests::test_bip322_messages_are_not_limited_by_legacy_payload_boundary ... ok
test protocol::bip322::tests::test_bip322_official_p2tr_positive_vector_without_prefix ... ok
test protocol::bip322::tests::test_bip322_p2a_and_future_witness_boundaries_are_typed ... ok
test protocol::bip322::tests::test_bip322_official_p2wpkh_positive_vector ... ok
test protocol::bip322::tests::test_bip322_taproot_annexes_are_explicitly_unsupported ... ok
test protocol::bip322::tests::test_bip322_p2wsh_and_taproot_script_path_are_unsupported ... ok
test protocol::bip322::tests::test_bip322_unprefixed_lowercase_base64_uses_simple_fallback ... ok
test protocol::bip322::tests::test_bip322_to_sign_rejects_message_mismatch_and_noncanonical_shape ... ok
test protocol::bip322::tests::test_bip322_unsupported_address_types_fail_closed ... ok
test protocol::bitcoin::tests::test_bip340_verification_rejects_malformed_lengths_and_keys ... ok
test protocol::bitcoin::tests::test_bip340_verification_matches_official_valid_vector ... ok
test protocol::bitcoin::tests::test_bip341_tap_tweak_matches_wallet_vector_with_merkle_root ... ok
test protocol::bitcoin::tests::test_bip340_verification_rejects_official_invalid_vectors ... ok
test protocol::bitcoin::tests::test_bip86_tap_tweak_matches_reference_vector ... ok
test protocol::bitcoin::tests::test_sighash_external_generation ... ok
test protocol::bitcoin::tests::test_op_cat_covenant_script_generation ... ok
test protocol::bitcoin::tests::test_taproot_rejects_noncanonical_paths_and_keys ... ok
test protocol::bitcoin_tests::tests::test_bitcoin_manager_descriptors ... ok
test protocol::bitvm2::tests::duplicate_chain_observations_are_idempotent_and_conflicts_fail_closed ... ok
test protocol::bitcoin_tests::tests::test_bitcoin_transaction_intent_lifecycle ... ok
test protocol::bitvm2::tests::groth16_proof_rejects_zero_bytes ... ok
test protocol::bitvm2::tests::groth16_proof_accepts_valid_elements ... ok
test protocol::bitvm2::tests::groth16_public_inputs_rejects_zero_digests ... ok
test protocol::bitvm2::tests::groth16_verifier_rejects_arbitrary_bytes_fail_closed ... ok
test protocol::bitvm2::tests::groth16_vk_accepts_valid_keys ... ok
test protocol::bitvm2::tests::groth16_vk_rejects_zero_key_elements ... ok
test protocol::bitvm2::tests::unsupported_operations_do_not_mutate_or_synthesize_state ... ok
test protocol::bitvm2::tests::observed_events_are_the_only_modeled_state_transition ... ok
test protocol::bitvm2::tests::validates_challenge_window_boundaries_and_identifiers ... ok
test protocol::bitvm::tests::snark_validator_default_constructs ... ok
test protocol::bitvm::tests::bitvm_manager_validate_snark_proof_bridges_to_verifier ... ok
test protocol::bitvm::tests::snark_validator_fails_closed_for_non_curve_bytes ... ok
test protocol::bitvm::tests::snark_validator_rejects_zero_input_digests ... ok
test protocol::bitvm::tests::snark_validator_rejects_zero_proof_elements ... ok
test protocol::bitvm::tests::snark_validator_rejects_zero_vk_elements ... ok
test protocol::bitvm::tests::test_bitvm_challenge_bounds ... ok
test protocol::cctp::tests::attestation_message_hash_is_deterministic ... ok
test protocol::cctp::tests::attestation_mismatched_hash_rejected ... ok
test protocol::cctp::tests::attestation_rejects_empty_signature ... ok
test protocol::cctp::tests::attestation_rejects_invalid_der_signature ... ok
test protocol::cctp::tests::canonical_intent_shape_passes_local_validation ... ok
test protocol::cctp::tests::malformed_network_or_recipient_data_is_rejected ... ok
test protocol::chain_abstraction::tests::test_resolve_intent_logic ... ok
test enclave::trust::trust_bundle::tests::validator_exposes_each_fail_closed_state ... ok
test protocol::chain_abstraction::tests::test_sign_for_chain_bitcoin_fails_closed_without_provider ... ok
test protocol::chain_abstraction::tests::test_sign_for_chain_near_fails_closed_without_provider ... ok
test protocol::bitvm::tests::test_bitvm_multi_party_aggregation ... ok
test protocol::control_model_adapter::tests::bip110_defaults_and_shape_use_exact_core_wire_contract ... ok
test protocol::control_model_adapter::tests::bip110_provenance_fixture_matches_core_wire_contract ... ok
test protocol::control_model_adapter::tests::core_chain_and_family_use_exact_reviewed_names ... ok
test protocol::control_model_adapter::tests::core_trust_tier_uses_exact_snake_case_values ... ok
test protocol::control_model_adapter::tests::core_verification_class_uses_exact_snake_case_values ... ok
test protocol::control_model_adapter::tests::production_projection_enforces_core_strict_light_client_invariant ... ok
test protocol::control_model_adapter::tests::production_projection_rejects_testnet_and_devnet ... ok
test protocol::control_model_adapter::tests::sdk_trust_tier_mapping_is_explicit_and_production_rejects_t4 ... ok
test protocol::control_model_adapter::tests::signed_envelope_identity_and_serialization_are_deterministic ... ok
test protocol::control_model_adapter::tests::supported_chains_map_without_family_collapsing ... ok
test protocol::control_model_adapter::tests::unknown_values_and_fields_fail_closed ... ok
test protocol::chain_abstraction::tests::test_sign_for_chain_stellar_fails_closed_without_provider ... ok
test protocol::covenant::tests::test_all_patterns_roundtrip ... ok
test protocol::covenant::tests::test_generate_apo_script ... ok
test protocol::covenant::tests::test_build_tapscript_leaf ... ok
test protocol::covenant::tests::test_generate_cat_vault_script ... ok
test protocol::chain_abstraction::tests::test_sign_for_chain_xrp_fails_closed_without_provider ... ok
test protocol::covenant::tests::test_verify_recursive_invariant_harden ... ok
test protocol::covenant::tests::test_generate_ctv_vault_script ... ok
test protocol::dlc::tests::cet_template_payout_is_proportional ... ok
test protocol::dlc::tests::cet_template_rejects_non_signed_contract ... ok
test protocol::dlc::tests::oracle_attestation_invalid_sig_rejected ... ok
test protocol::dlc::tests::test_dlc_contract_id_generation ... ok
test protocol::dlc::tests::test_dlc_lifecycle ... ok
test protocol::economy_tests::tests::test_gas_sponsored_tx_generation_fails_closed_without_provider ... ok
test protocol::economy_tests::tests::test_dual_stack_generation_fails_closed_without_provider ... ok
test protocol::ethereum::tests::test_eip155_chain_id_decoder_is_context_bound ... ok
test protocol::ethereum::tests::test_eip191_hash_and_signature_verification ... ok
test protocol::ethereum::tests::test_compact_and_recoverable_signature_canonicality ... ok
test protocol::ethereum::tests::test_eip2098_official_and_negative_vectors ... ok
test protocol::ethereum::tests::test_eip55_address_vectors_and_strict_input ... ok
test protocol::ethereum::tests::test_ethereum_address_uses_canonical_keccak ... ok
test protocol::ethereum::tests::test_keccak_and_eip191_binary_safe_vectors ... ok
test protocol::ethereum::tests::test_ethereum_rejects_malformed_addresses_and_signatures ... ok
test protocol::frost::tests::all_value_bearing_operations_remain_exactly_unsupported ... ok
test protocol::frost::tests::envelopes_and_errors_do_not_expose_secret_material ... ok
test protocol::frost::tests::rejects_invalid_thresholds_identifiers_versions_and_duplicates ... ok
test protocol::frost::tests::signing_session_enforces_ownership_and_duplicate_replay ... ok
test protocol::identity::tests::software_and_development_managers_cannot_create_hardware_identity ... ok
test protocol::intent::tests::canonical_hash_changes_for_rail_and_dispatch_context_mutations ... ok
test protocol::intent::tests::canonical_hash_is_independent_of_map_insertion_order ... ok
test protocol::intent::tests::legacy_request_only_hash_is_not_the_complete_intent_hash ... ok
test protocol::intent::tests::test_fdc3_context_creation ... ok
test protocol::job_card::tests::test_amount_validation_rejects_invalid_formats ... ok
test protocol::job_card::tests::test_amount_validation_rejects_zero_amounts ... ok
test protocol::job_card::tests::test_benchmark_pacs008_latency ... ok
test protocol::job_card::tests::test_job_card_validation ... ok
test protocol::job_card::tests::test_pacs008_generation ... ok
test protocol::lightning::tests::bip353_address_parsing_and_validation ... ok
test protocol::lightning::tests::bolt12_offer_parsing_and_validation ... ok
test protocol::lightning::tests::route_finder_enforces_budgets_and_disabled_edges ... ok
test protocol::lightning::tests::route_finder_fails_closed_without_feasible_path ... ok
test protocol::lightning::tests::route_finder_selects_minimum_fee_path ... ok
test protocol::lightning::tests::route_finder_validates_graph_and_amount ... ok
test protocol::lightning::tests::test_failure_and_retry ... ok
test protocol::lightning::tests::test_max_retries ... ok
test protocol::lightning::tests::test_payment_lifecycle_events ... ok
test protocol::lightning::tests::test_permanent_failure_blocks_retry ... ok
test protocol::lightning::tests::test_preimage_settlement_verification ... ok
test protocol::lightning_channel::tests::channel_fails_closed_on_invalid_operations ... ok
test protocol::lightning_channel::tests::channel_lifecycle_progresses_through_phases ... ok
test protocol::lightning_channel::tests::cooperative_close_requires_resolved_htlcs ... ok
test protocol::lightning_channel::tests::force_close_can_occur_with_pending_htlcs ... ok
test protocol::lightning_channel::tests::offered_htlc_settle_and_fail_preserve_capacity_invariant ... ok
test protocol::lightning_channel::tests::received_htlc_settle_and_fail_preserve_capacity_invariant ... ok
test protocol::lightning_channel::tests::settle_requires_correct_preimage ... ok
test protocol::credit::tests::test_prepare_vouch_determinism ... ok
test protocol::nexus::fedimint::tests::note_serialization_and_debug_do_not_expose_a_secret ... ok
test protocol::nexus::fedimint::tests::operation_ledger_is_idempotent_and_rejects_conflicting_replay ... ok
test protocol::nexus::fedimint::tests::unsupported_operations_do_not_mutate_adapter_state ... ok
test protocol::nexus::fedimint::tests::validates_thresholds_identifiers_and_versions ... ok
test protocol::nexus::fedimint::tests::verify_note_and_threshold_signatures ... ok
test protocol::nexus::roast::tests::coordinator_rejects_session_when_too_many_excluded ... ok
test protocol::nexus::roast::tests::exclusion_list_works ... ok
test protocol::nexus::roast::tests::round_with_insufficient_shares_returns_failed_with_blame ... ok
test protocol::nexus::roast::tests::session_collects_commitments_and_shares ... ok
test protocol::nexus::roast::tests::session_rejects_non_member_signer ... ok
test protocol::nexus::roast::tests::session_rejects_wrong_round_commitment ... ok
test protocol::nexus::roast::tests::value_bearing_operations_are_unsupported_without_frost_crypto ... ok
test enclave::trust::tests::rollback_floor_validity_and_statuses_are_explicit ... ok
test protocol::fiat::tests::test_prepare_fiat_session_sovereign ... ok
test protocol::mmr::tests::test_mmr_local_proof ... ok
test protocol::opportunity::tests::test_opportunity_dispatcher_dynamic_rail ... ok
test protocol::rails::fdc3_integration_tests::test_resolve_fdc3_instrument_to_intent ... ok
test protocol::rails::ntt::tests::test_ntt_rail_name ... ok
test protocol::rails::rail_proxy_tests::default_rail_policy_and_ordering_remain_unchanged ... ok
test protocol::rails::rail_proxy_tests::missing_durable_replay_fails_before_rail_side_effect ... ok
test protocol::rails::rail_proxy_tests::public_rail_integrity_requires_durable_replay_before_attestation_work ... ok
test protocol::rails::rail_proxy_tests::rail_proxy_rejects_process_local_replay_store_at_configuration ... ok
test protocol::rails::rail_proxy_tests::test_attestation_is_always_required ... ok
test protocol::rails::rail_proxy_tests::built_in_adapter_dispatch_is_quarantined_before_network ... ok
test protocol::rails::rail_proxy_tests::shared_durable_rail_store_accepts_once_and_rejects_cross_proxy_duplicate ... ok
test protocol::rails::rail_proxy_tests::test_clock_failure_precedes_attestation_verification_and_replay_recording ... ok
test protocol::rails::rail_proxy_tests::test_configured_attestation_policy_is_enforced ... ok
test protocol::rails::rail_proxy_tests::test_discover_best_rail ... ok
test protocol::rails::rail_proxy_tests::test_forged_report_is_rejected_without_consuming_replay_state ... ok
test protocol::rails::rail_proxy_tests::test_legacy_policy_flag_cannot_disable_attestation ... ok
test protocol::rails::rail_proxy_tests::test_legacy_request_only_hash_is_rejected ... ok
test protocol::rails::rail_proxy_tests::test_malformed_attestation_is_rejected_without_consuming_replay_state ... ok
test protocol::rails::rail_proxy_tests::test_prepare_intent_with_fdc3 ... ok
test protocol::rails::rail_proxy_tests::test_quarantined_asset_cannot_enter_routing ... ok
test protocol::rails::rail_proxy_tests::test_trust_tier_enforcement ... ok
test protocol::rails::rail_proxy_tests::test_rail_proxy_with_telemetry ... ok
test protocol::rails::rail_proxy_tests::test_untrusted_root_is_rejected_without_consuming_replay_state ... ok
test protocol::rails::rail_proxy_tests::test_verify_hardware_integrity_rejects_replay ... ok
test protocol::rails::rail_proxy_tests::test_wrong_nonce_is_rejected_before_replay_recording ... ok
test protocol::rails::rail_proxy_tests::test_stale_and_future_reports_are_rejected ... ok
test protocol::rails::rail_proxy_tests::typed_dispatch_preflight_is_validation_only ... ok
test protocol::rails::rail_proxy_tests::test_wrong_purpose_is_rejected_without_consuming_replay_state ... ok
test protocol::rails::rail_proxy_tests::typed_settlement_authorization_rejects_same_id_weaker_policy_digest ... ok
test protocol::rails::rail_proxy_tests::typed_settlement_authorization_replay_is_rejected ... ok
test protocol::rails::rail_proxy_tests::typed_settlement_clock_failure_does_not_consume_replay_state ... ok
test protocol::rails::rail_proxy_tests::typed_settlement_dispatch_rechecks_expected_and_verified_policy_digest ... ok
test protocol::rails::rail_proxy_tests::typed_settlement_proof_attachment_rejects_same_id_policy_variants_before_dispatch ... ok
test protocol::rails::rail_proxy_tests::typed_settlement_envelope_rejects_missing_attestation_and_replay_authorization ... ok
test protocol::rails::rail_proxy_tests::typed_settlement_envelope_rejects_intent_digest_key_and_policy_mismatch ... ok
test protocol::rails::tests::test_swap_request_hash_determinism ... ok
test protocol::rails::rail_proxy_tests::typed_settlement_replay_is_consumed_before_downstream_failure ... ok
test protocol::rgb::tests::contract_id_roundtrips ... ok
test protocol::rgb::tests::seal_construction ... ok
test protocol::rgb::tests::transition_hash_is_deterministic ... ok
test protocol::settlement::settlement_expanded_tests::test_create_proposal_expanded_chains ... ok
test protocol::settlement::tests::test_settlement_flow ... ok
test protocol::settlement_service::tests::test_settlement_service_trigger_to_proposal ... ok
test protocol::settlement_service::tests::test_trust_tier_resolution ... ok
test protocol::settlement_service::tests::test_verify_reconciliation ... ok
test protocol::rails::x402::tests::test_x402_rail_validation ... ok
test protocol::sidl::tests::test_sidl_vote_serialization ... ok
test protocol::solver::tests::test_solver_ranking_prioritizes_yield ... ok
test protocol::statechain::tests::encoding_version_current_is_valid ... ok
test protocol::statechain::tests::encoding_version_zero_rejected ... ok
test protocol::statechain::tests::forfeit_sign_is_gated ... ok
test protocol::statechain::tests::leaf_accepts_valid ... ok
test protocol::statechain::tests::leaf_rejects_excessive_depth ... ok
test protocol::statechain::tests::leaf_rejects_zero_amount ... ok
test protocol::statechain::tests::operator_set_rejects_duplicate_ids ... ok
test protocol::statechain::tests::operator_set_rejects_threshold_gt_operators ... ok
test protocol::statechain::tests::operator_set_rejects_zero_threshold ... ok
test protocol::statechain::tests::session_initiate_dkg_is_gated ... ok
test protocol::statechain::tests::transfer_execute_is_gated ... ok
test protocol::statechain::tests::transfer_rejects_empty_leaf_ids ... ok
test protocol::statechain::tests::transfer_rejects_same_sender_recipient ... ok
test protocol::statechain::tests::vutxo_tree_computes_total ... ok
test protocol::statechain::tests::vutxo_tree_rejects_empty_leaves ... ok
test protocol::rails::rail_proxy_tests::unavailable_and_indeterminate_rail_replay_fail_closed ... ok
test protocol::universal_tests::tests::test_chain_abstraction_signature_fails_closed_without_provider ... ok
test protocol::universal_tests::tests::test_ethereum_address_derivation ... ok
test protocol::universal_tests::tests::test_ethereum_erc20_preparation ... ok
test protocol::universal_tests::tests::test_solana_address_retrieval ... ok
test protocol::universal_tests::tests::test_universal_asset_registry ... ok
test protocol::zkml::tests::test_zkml_request_construction ... ok
test protocol::sidl::tests::test_sidl_service_new ... ok
test signing::bip110_signing::tests::bip110_enforcer_constructs ... ok
test signing::bip110_signing::tests::bip110_enforcer_is_send_sync ... ok
test signing::bip110_signing::tests::bip110_requires_chunking_short_message ... ok
test signing::bip110_signing::tests::bip110_validate_script_pubkey_accepts_standard ... ok
test signing::bip110_signing::tests::bip110_validate_witness_item_accepts_small_data ... ok
test signing::bip322_signing::tests::bip322_signer_constructs ... ok
test signing::bip322_signing::tests::bip322_signer_is_send_sync ... ok
test signing::bip322_signing::tests::bip322_verify_invalid_signature_returns_false ... ok
test signing::bitvm2_signing::tests::bitvm2_ids_construct ... ok
test signing::bitvm2_signing::tests::bitvm2_signer_constructs ... ok
test signing::covenant_signing::tests::covenant_signer_constructs ... ok
test signing::dlc_signing::tests::dlc_signer_constructs ... ok
test signing::dlc_signing::tests::oracle_hash_differs_by_outcome ... ok
test signing::dlc_signing::tests::oracle_hash_is_deterministic ... ok
test signing::lightning_signing::tests::lightning_signer_constructs ... ok
test signing::musig2_signing::tests::musig2_signer_constructs ... ok
test signing::musig2_signing::tests::musig2_signer_is_send_sync ... ok
test signing::statechain_signing::tests::statechain_signer_constructs ... ok
test signing::statechain_signing::tests::statechain_transfer_types_align ... ok
test signing::taproot::tests::classify_bip44_path ... ok
test signing::taproot::tests::classify_bip84_path ... ok
test signing::taproot::tests::classify_bip86_path ... ok
test signing::taproot::tests::classify_unknown_path ... ok
test signing::taproot::tests::compute_taproot_tweak_default_merkle_root ... ok
test signing::taproot::tests::tapleaf_hash_of_empty_script ... ok
test signing::taproot::tests::taproot_output_key_no_script_path ... ok
test protocol::swap_router::tests::test_swap_router_instantiation ... ok
test signing::threshold::tests::frost_dkg_rounds_type_check ... ok
test signing::threshold::tests::frost_signer_default_constructs ... ok
test signing::threshold::tests::frost_signer_is_send_sync ... ok
test signing::ucs::tests::ucs_can_be_constructed ... ok
test signing::threshold::tests::frost_signing_rounds_type_check ... ok
test signing::ucs::tests::ucs_is_send_and_sync ... ok
test signing::ucs::tests::ucs_methods_fail_closed_on_unsupported_enclave ... ok
test signing::wasm_runtime::tests::wasm_decode_hex_32_invalid_length ... ok
test signing::ucs::tests::ucs_sign_methods_type_check ... ok
test signing::wasm_runtime::tests::wasm_decode_hex_32_valid ... ok
test signing::wasm_runtime::tests::wasm_public_key_request_roundtrips ... ok
test signing::wasm_runtime::tests::wasm_request_serialization_roundtrips ... ok
test signing::wasm_runtime::tests::wasm_sign_rejects_unknown_chain ... ok
test state::tests::test_mmr_height_calculation ... ok
test signing::zkml_signing::tests::zkml_signer_constructs ... ok
test state::tests::test_mmr_integrity ... ok
test state::tests::test_mmr_proof_generation ... ok
test telemetry::tests::delivery_policy_rejects_unbounded_values ... ok
test telemetry::tests::delayed_transport_exercises_request_timeout ... ok
test telemetry::tests::documented_default_policy_values_are_explicit ... ok
test telemetry::tests::empty_api_key_omits_auth_header ... ok
test telemetry::tests::every_documented_retryable_http_status_retries ... ok
test protocol::zkml::tests::test_zkml_service_new ... ok
test telemetry::tests::disabled_mode_is_explicit_and_side_effect_free ... ok
test telemetry::tests::non_retryable_http_status_does_not_retry ... ok
test telemetry::tests::payload_serialization_excludes_credentials_and_identifiers ... ok
test telemetry::tests::production_endpoints_require_https_and_reject_ambiguous_urls ... ok
test telemetry::tests::retryable_http_failure_can_recover_without_blocking ... ok
test telemetry::tests::scheduling_without_a_runtime_is_observable_and_does_not_panic ... ok
test telemetry::tests::timeout_retries_are_bounded_and_observable ... ok
test telemetry::tests::transport_keeps_credentials_in_headers_only ... ok
test wasm_support::tests::bolt11_case_normalization_accepts_uniform_case_only ... ok
test wasm_support::tests::direct_ark_and_legacy_bitvm_clients_are_stateless_and_quarantined ... ok
test wasm_support::tests::every_known_runtime_fails_closed_without_evidence ... ok
test wasm_support::tests::legacy_wasm_bitvm_surface_is_exactly_bitvm2_unsupported ... ok
test wasm_support::tests::stable_error_codes_preserve_input_protocol_and_secret_semantics ... ok
test wasm_support::tests::unapproved_provider_is_typed_as_unsupported ... ok
test wasm_support::tests::unknown_runtime_is_typed_as_unsupported ... ok
test wasm_support::tests::wasm_surface_does_not_serialize_fedimint_blinding_factors ... ok
test wasm_support::tests::wasm_surface_has_no_private_key_export_or_cloud_default ... ok
test telemetry::tests::invalid_compatibility_configuration_fails_closed_without_panic ... ok
test telemetry::tests::native_client_does_not_follow_redirects_or_forward_api_key ... ok
test protocol::rails::rail_proxy_tests::proof_authorized_settlements_use_separate_replay_capacity_domains ... ok

test result: ok. 586 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 28.17s


running 10 tests
test batch_after_commit_response_loss_restores_as_all_or_nothing_duplicate ... ok
test clock_rollback_is_detected_before_pruning_or_admission ... ok
test batch_before_commit_unavailable_has_no_mutation_and_retry_succeeds_atomically ... ok
test forward_duplicate_advances_and_persists_high_water ... ok
test forward_failed_batch_persists_high_water_without_fresh_member ... ok
test invalid_reservations_precede_fault_consumption_and_high_water_mutation ... ok
test single_after_commit_response_loss_restores_as_duplicate ... ok
test single_before_commit_unavailable_has_no_mutation_and_retry_succeeds ... ok
test reference_model_passes_complete_backend_neutral_suite ... ok
test file_backed_store_passes_complete_backend_neutral_suite ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.14s


running 4 tests
test valid_looking_erc7579_inputs_cannot_execute_or_claim_module_provenance ... ok
test valid_looking_cctp_inputs_cannot_produce_calldata_or_validate_iris_attestation ... ok
test conflicting_metadata_cannot_replace_canonical_state_or_change_rail_selection ... ok
test quarantined_unknown_metadata_cannot_enter_rail_selection ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s


running 10 tests
test harness::tests::assert_unsupported_accepts_unsupported_error ... ok
test harness::tests::derivation_paths_are_valid ... ok
test harness::tests::assert_unsupported_panics_on_ok - should panic ... ok
test harness::tests::digests_are_32_bytes ... ok
test harness::tests::harness_enclave_constructs ... ok
test harness::tests::harness_enclave_ucs_constructs ... ok
test harness_derivation_paths ... ok
test harness_digests_are_distinct ... ok
test harness_enclave_returns_public_key ... ok
test harness_exercises_ucs ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 4 tests
test all_non_good_statuses_are_fail_closed ... ok
test single_mechanism_scope_is_explicit_and_not_a_complete_authorization ... ok
test trust_transport_denies_unknown_fields_and_unbounded_identifiers ... ok
test unavailable_durable_store_never_authorizes ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 6 tests
test every_builtin_adapter_is_gated_before_http_dispatch ... ok
test production_explicit_proof_path_stops_at_unavailable_verifier ... ok
test production_default_policy_is_hardware_only_and_provider_unavailable ... ok
test production_opportunity_dispatch_reaches_provider_boundary ... ok
test prepare_intent_commits_to_the_complete_security_context ... ok
test production_verification_rejects_legacy_request_only_hashes ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.13s


running 6 tests
test duplicate_kind_and_proof_id_are_rejected_before_verification ... ok
test production_registry_exposes_only_unavailable_exact_routes ... ok
test replay_batch_capacity_failure_does_not_partially_insert_keys ... ok
test exact_context_binding_rejects_wrong_digest_without_fallback ... ok
test serialized_unknown_fields_are_rejected_and_debug_redacts_evidence ... ok
test well_shaped_production_bundle_is_not_structural_success ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 4 tests
test production_attestation_policy_and_provider_status_remain_unavailable ... ok
test public_release_manifest_rejects_missing_independent_review ... ok
test public_collateral_contract_fails_closed_on_expiry_and_root_mismatch ... ok
test public_replay_binding_serializes_only_digests ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 2 tests
test src/protocol/zkml.rs - protocol::zkml::ZkmlService (line 121) ... ignored
test src/protocol/rails/mod.rs - protocol::rails::RailProxy (line 405) - compile fail ... ok

test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.15s.
