#!/usr/bin/env python3
"""Fail closed when published SDK support counts drift from their sources."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs/architecture/support-inventory.json"
ASSET_SOURCE = ROOT / "src/protocol/asset.rs"
PROTOCOL_SOURCE = ROOT / "src/protocol/mod.rs"
ADAPTER_SOURCE = ROOT / "src/protocol/control_model_adapter.rs"
CAPABILITY_SOURCE = ROOT / "docs/architecture/capability-evidence.json"


def fail(message: str) -> None:
    print(f"support inventory validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def extract_usize_constant(source: str, name: str) -> int:
    match = re.search(rf"pub const {name}: usize = (\d+);", source)
    if not match:
        fail(f"missing usize constant {name}")
    return int(match.group(1))


def count_all_chains(source: str) -> int:
    match = re.search(r"pub const ALL_CHAINS: &\[Chain\] = &\[(.*?)\n\];", source, re.S)
    if not match:
        fail("missing ALL_CHAINS inventory")
    return len(re.findall(r"\bChain::[A-Za-z0-9_]+\b", match.group(1)))


def count_protocol_modules(source: str) -> int:
    modules = re.findall(r"^pub mod ([A-Za-z0-9_]+);$", source, re.M)
    return len([name for name in modules if not name.endswith("_tests") and name != "universal_tests"])


def count_exact_core_projections(source: str) -> int:
    match = re.search(
        r"pub fn sdk_chain_to_core\(.*?let mapped = match value \{(.*?)\n\s*\};",
        source,
        re.S,
    )
    if not match:
        fail("missing sdk_chain_to_core match")
    return len(re.findall(r"^\s*Chain::[A-Za-z0-9_]+\s*=>\s*CoreChain::", match.group(1), re.M))


def main() -> None:
    inventory = json.loads(INVENTORY.read_text())
    asset_source = ASSET_SOURCE.read_text()
    measures = inventory["measures"]

    actual = {
        "sdkChainIdentifiers": count_all_chains(asset_source),
        "builtinAssetRecords": extract_usize_constant(asset_source, "BUILTIN_ASSET_RECORD_COUNT"),
        "activeAssetRecords": extract_usize_constant(
            asset_source, "BUILTIN_ACTIVE_ASSET_RECORD_COUNT"
        ),
        "protocolModules": count_protocol_modules(PROTOCOL_SOURCE.read_text()),
        "exactCoreChainProjections": count_exact_core_projections(ADAPTER_SOURCE.read_text()),
    }
    capabilities = json.loads(CAPABILITY_SOURCE.read_text())["capabilities"]
    actual["capabilityEvidenceRecords"] = len(capabilities)
    actual["productionSupportedRecords"] = sum(
        row["productionSupport"] == "production-supported" for row in capabilities
    )

    expected = {
        "sdkChainIdentifiers": measures["sdkChainIdentifiers"]["count"],
        "builtinAssetRecords": measures["builtinAssetRecords"]["count"],
        "activeAssetRecords": measures["builtinAssetRecords"]["activeCount"],
        "protocolModules": measures["protocolModules"]["count"],
        "exactCoreChainProjections": measures["exactCoreChainProjections"]["count"],
        "capabilityEvidenceRecords": measures["capabilityEvidenceRecords"]["count"],
        "productionSupportedRecords": measures["capabilityEvidenceRecords"]["productionSupportedCount"],
    }
    if actual != expected:
        fail(f"published counts drifted: expected {expected}, derived {actual}")

    if inventory["trustModel"] != {
        "root": "bitcoin-l1",
        "scope": "universal-chain",
        "nativeConxianToken": False,
        "note": "Bitcoin L1 is the canonical trust/finality root. External chains, networks, layers, assets, and staking adapters remain valid when independently evidenced.",
    }:
        fail("trust model must remain Bitcoin-rooted, universal-chain, and zero-native-token")

    print(f"support inventory valid: {actual}")


if __name__ == "__main__":
    main()
