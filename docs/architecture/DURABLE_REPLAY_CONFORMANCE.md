# Durable Replay Conformance for `ReplayStore`

> **Status:** Backend-neutral contract and test-model evidence only. This
> document does not select a datastore, establish distributed durability,
> promote a capability, or make a production-readiness claim.

## Scope and requirement trace

This document defines conformance expectations for the active
`src/enclave/replay_guard.rs::ReplayStore` contract used by proof
authorization, final value-bearing signing, and typed rail dispatch. It records
the durable-replay slice requested by
[#191](https://github.com/Conxian/conxius-enclave-sdk/issues/191) and the
distributed replay gate tracked by
[#240](https://github.com/Conxian/conxius-enclave-sdk/issues/240).

The repository currently contains **three distinct replay contracts**:

1. `enclave::replay_guard::ReplayStore` is the active production-facing
   consume-once contract and the only contract in scope here.
2. `enclave::durable_replay::DurableReplayStore` supports the separate
   single-mechanism replay authorizer foundation.
3. `enclave::trust_contracts::DurableReplayStore` is a separate typed trust
   contract foundation.

They use different request, outcome, and error types. Implementations and test
fixtures are not interchangeable, and conformance evidence for one must not be
presented as evidence for another.

## Required semantics

### Complete replay identity

The storage key must represent the complete `ReplayBinding`, including its
domain, provider, proof subject and mechanism, nonce digest, operation digest,
purpose, policy digest, key-identity digest, evidence digest, and optional proof
and audience identifiers. An adapter must persist or conditionally compare the
complete binding digest supplied by `ReplayReservation`; it must not truncate,
normalize across domains, or substitute a weaker provider/request identifier.

Each security-relevant dimension is isolated. Two requests that differ in any
binding dimension are different replay identities. Reusing one identity for a
different payload is not idempotency; it is a conflicting request and must fail
closed at the layer that validates the binding.

### Atomic consume-once

`consume_once` has one linearized result:

- `Accepted`: the reservation was committed exactly once;
- `Duplicate`: the same binding is still retained; or
- a typed error that must not be interpreted as acceptance.

`consume_once_batch` is all-or-nothing. It may return
`ReplayBatchOutcome::accepted_for(reservations)` only after every reservation
in that slice commits in one atomic transaction. Returning `Ok` is the
adapter's assertion that the atomic commit reached its required durability
point. The derived count is descriptive and cannot independently prove that
assertion. A pre-existing duplicate, a duplicate inside the request, invalid
input, capacity rejection, rollback, outage, or uncertain result must not leave
a subset of new reservations committed. Maintenance effects allowed by the
active contract—persisting a forward high-water observation and pruning expired
entries—do not permit partial insertion of requested keys.

### Error mapping and uncertain commits

Adapters must distinguish failures observed before commit from failures where
the commit result cannot be proven:

| Backend observation | `ReplayStore` result | Retry interpretation |
| --- | --- | --- |
| Request definitely did not commit | `BackendUnavailable` | Retry may be attempted with the same complete binding. |
| Commit definitely succeeded | `Accepted` or atomic batch success | Continue once. |
| Existing live reservation | `Duplicate` / atomic duplicate | Do not emit the protected external side effect. |
| Response lost or commit outcome otherwise uncertain | `TransactionIndeterminate` | Fail closed; never assume the key is free. Reconcile or retry only through the same complete binding. |
| Trusted time below persisted high-water | `ClockRollback` | Stop; recover trusted time/state before retry. |

A timeout, canceled client request, leader change, or broken response channel is
not evidence that a transaction failed. If the adapter cannot prove
non-commit, it must return `TransactionIndeterminate`.

### Restart, failover, and recovery

The replay ledger and trusted-time high-water mark are one durable security
state. A restart or failover must restore both from a committed snapshot or
transactionally consistent log. Recovery must not:

- restore a ledger without its corresponding high-water mark;
- restore an older ledger generation over a newer accepted generation;
- accept traffic while the latest committed state is uncertain;
- split one replay domain across replicas that cannot provide one consume-once
  decision; or
- convert indeterminate writes into absent writes without reconciliation.

Backups, replicas, point-in-time recovery, and regional failover require tests
that prove accepted keys and the high-water clock survive the exact recovery
procedure. An adapter must fail closed while recovery ownership or state
freshness is ambiguous.

### Retention horizon

`retain_until` is an **exclusive** horizon:

- a reservation is admissible only while `now_secs < retain_until`;
- `now_secs >= retain_until` returns `InvalidRetention` for that reservation;
- a stored key remains duplicate only while `now_secs < stored_retain_until`;
  and
- at or after the stored horizon, pruning may make the same complete binding a
  fresh reservation only when the caller supplies a new future horizon.

Backend TTL deletion is an optimization, not the security decision. Delayed TTL
cleanup must not extend authorization unexpectedly, and early/asynchronous TTL
cleanup must not allow reuse before the exclusive horizon. The transaction
must compare trusted time and the stored horizon directly.

### Rollback resistance

Every non-rollback observation advances a persisted high-water clock according
to the active contract. A lower subsequent observation returns
`ClockRollback` before key admission or expiry pruning. The high-water mark must
survive key eviction, duplicate outcomes, restart, backup restore, leader
change, and failover. Recovery to a snapshot older than an externally accepted
transaction must be detected or treated as unavailable/indeterminate.

## What `DurableProvider` proves

`ReplayStoreDurability::DurableProvider` is an adapter assertion used by API
gates. By itself it proves only that the implementation claims the durable
contract. It does **not** prove:

- atomic conditional writes or serializable transactions;
- restart, replica, or regional failover behavior;
- backup/restore freshness or rollback detection;
- trusted-clock quality;
- retention/TTL correctness;
- operational monitoring or recovery procedures;
- independent security review; or
- support for any production deployment.

The `FaultInjectingReplayStore` in `tests/durable_replay_conformance.rs` and
other fixtures that return `DurableProvider` are unmistakably test-only. Their
labels exercise the API boundary and are not durability evidence.

## Generic adapter conformance and model-only evidence

`tests/support/mod.rs::run_replay_store_conformance_suite` accepts a factory
that returns a fresh `Arc<dyn ReplayStore>`. It runs the complete
backend-neutral suite: single success/duplicate, atomic batch success and
conflicts, intra-batch duplicates, deterministic 32-thread same-key contention,
overlapping-batch contention with no partial loser write, forward high-water
behavior on duplicate and failed batch outcomes, exclusive retention and
post-horizon reuse, generic validation precedence, and every complete-binding
dimension. `tests/durable_replay_conformance.rs` invokes that complete suite
against the reference model; a future adapter target can invoke the same entry
point without copying cases.

Snapshot/restore and injected pre/post-commit fault transitions are explicitly
model-specific because `ReplayStore` has no lifecycle or fault-control hooks.
The reference model separately tests single and batch faults, all-or-nothing
recovery after response loss, persisted duplicate/failed-batch high-water
observations, validation before fault consumption, and rollback before pruning
or admission. A real adapter must supply equivalent backend-specific hooks and
recovery evidence rather than treating model simulation as datastore evidence.

Existing focused tests already establish downstream containment and are not
duplicated in the integration target:

- `durable_final_signing_fails_closed_before_provider_on_uncertain_store` in
  `src/enclave/proofs.rs` asserts that `TransactionIndeterminate` leaves the
  provider call count at zero.
- `unavailable_and_indeterminate_rail_replay_fail_closed` and
  `missing_durable_replay_fails_before_rail_side_effect` in
  `src/protocol/rails/mod.rs` establish fail-closed rail admission and zero rail
  calls when replay admission is unavailable.

These tests plus the restored-after-commit duplicate scenario define expected
control flow. They do not demonstrate a real backend's recovery behavior.

## Evidence gate before promotion

Before any adapter or capability can be promoted, attach a traceable
requirement -> adapter code -> conformance/integration test -> exact CI run ->
deployment artifact chain containing at least:

1. the datastore product, version, topology, consistency mode, schema, key
   shape, transaction/conditional-write expression, and retention mechanism;
2. a reviewed mapping for every `ReplayStoreError`, especially timeout,
   cancellation, conflict, aborted transaction, and unknown commit status;
3. deterministic tests against the real adapter for all conformance cases;
4. crash tests at pre-commit, commit, and post-commit response boundaries;
5. restart, leader/replica failover, backup restore, and regional recovery
   evidence with accepted keys and high-water state retained;
6. concurrency/load evidence for single-key and overlapping batch contention;
7. trusted-clock source, rollback behavior, skew bounds, and recovery procedure;
8. retention-boundary tests independent of asynchronous TTL deletion;
9. observability that does not expose raw nonces, evidence, keys, credentials,
   or private operational endpoints;
10. independent security review and the exact artifact digest/provenance for the
    deployment under review.

Do not update `capability-evidence.json` or a production-support decision until
all applicable evidence is reviewed and linked.

## Backend adapter checklist

- [ ] Uses `ReplayStore`, not either distinct `DurableReplayStore` trait.
- [ ] Preserves the complete domain-separated binding digest without
      truncation or cross-domain normalization.
- [ ] Implements conditional single-key admission atomically.
- [ ] Implements all-or-nothing batches, including duplicate detection inside
      one request.
- [ ] Returns success only after the required durability point.
- [ ] Maps uncertain commits to `TransactionIndeterminate`.
- [ ] Persists ledger and high-water clock consistently.
- [ ] Rejects clock rollback before pruning or insertion.
- [ ] Enforces the exclusive retention horizon in the transaction itself.
- [ ] Proves behavior under contention, restart, failover, and restore.
- [ ] Bounds capacity and request size without partial writes.
- [ ] Keeps diagnostics secret-free and ZSE-safe.
- [ ] Ships exact CI, artifact, provenance, and independent-review evidence.

## Research-informed options, not selections

Official database documentation describes useful implementation primitives:
conditional writes, all-or-nothing transactions, serializable isolation, and
commit timestamps. Those are candidate patterns only. No DynamoDB, Spanner,
PostgreSQL, or other backend is selected or supported by this document.
