# Persist every durable-request clock observation before consuming

P0 owner: SDK #240; portfolio: Conxian/conxian-business#1390. Continues the lower-level replay correction in #599 against fresh dev af8e2844dd6c8936aad16e391a70ec202a383cf2.

The distinct higher-level `FileBackedDurableReplayStore` still saves the anti-rollback clock best-effort after a new record has been committed. Duplicate/conflicting requests never advance it. Require successful clock persistence before creating, reclaiming or inspecting any claim, including same-request retries and conflicts. Retain the in-process observation on failure; do not remove existing replay history. Propagate StoreUnavailable/UncertainCommit instead of granting a consume result.

Regression evidence must reproduce failures on unchanged source, then verify new-request denial without a claim, denied retries without altering existing records, older-clock denial, recovery at the same timestamp, and restart rollback denial after duplicate/conflicting requests. Exercise real clock-path obstruction and Linux write failure, then run locked default/all-feature native suites, strict Clippy, format, inventory/public-proof validators and hosted WASM checks.

No change to identity encoding, expiry convention, record format, policy digest, provider identity or release authority. Local file-store behavior is not distributed, multi-instance, crash-atomic or power-loss directory-entry durability qualification. Service-owned transactional backends and provider/independent release evidence remain open under #240/#202. Roll back source only via normal review and never erase replay history for availability.
