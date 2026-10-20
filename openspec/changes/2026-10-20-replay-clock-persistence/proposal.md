# Fail closed on replay clock persistence errors

Owner: SDK #240; portfolio: Conxian/conxian-business#1390. Priority P0.

Both lower-level file replay consume paths currently discard errors returned by `write_high_water`. A request can consequently be accepted without a successfully persisted anti-rollback observation. Propagate the existing backend-unavailable/transaction-indeterminate error before reading, deleting or creating any claim. Keep the in-process high-water observation advanced even on failure, preventing a retry with an older clock. A retry at the same or later time must successfully persist the clock before consuming anything.

Validate single and batch failures using an obstructed clock path, no claim changes on failure, rejection of an older retry, recovery at the same time, and duplicate/clock-rollback protection after reopening. Exercise actual write errors on Unix using a synthetic `/dev/full` clock target. Retain existing conformance and feature-disabled tests, strict Clippy, format, support inventories and public proof checks.

This corrects only ignored persistence failures in the local reference adapter. It does not qualify crash-atomic batches, filesystem directory-entry durability, independent store instances, multi-replica/region coordination, provider/hardware evidence, or production acceptance. No replay records, policies, trust roots, dependencies or release authority are migrated. Rollback is a source revert through normal review; never erase replay history to recover availability.

Research: Rust File documentation explicitly requires handling write/synchronization errors; dropping a file ignores close errors: https://doc.rust-lang.org/std/fs/struct.File.html . SDK production backends remain service-owned.
