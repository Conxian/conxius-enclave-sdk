#!/usr/bin/env python3
"""Validate decentralized-signing claims and their local evidence references."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs/architecture/decentralized-signing-inventory.json"
CAPABILITIES = ROOT / "docs/architecture/capability-evidence.json"
ALLOWED_PRODUCTION = {"unsupported", "production-supported"}
REQUIRED_IDS = {
    "aws-kms-release-set",
    "frost-secp256k1",
    "roast-frost-coordinator",
    "musig2-secp256k1",
    "fedimint-guardian",
    "spark-statechain",
    "bitcoin-multisig-and-hardware",
}


def main() -> None:
    inventory = json.loads(INVENTORY.read_text())
    capability = json.loads(CAPABILITIES.read_text())
    systems = inventory["systems"]
    by_id = {item["id"]: item for item in systems}

    if len(by_id) != len(systems):
        raise SystemExit("duplicate decentralized-signing inventory id")
    if set(by_id) != REQUIRED_IDS:
        raise SystemExit(f"inventory id drift: {sorted(set(by_id) ^ REQUIRED_IDS)}")

    for item in systems:
        if item["productionSupport"] not in ALLOWED_PRODUCTION:
            raise SystemExit(f"invalid productionSupport for {item['id']}")
        if item["decentralizedCustody"] == "yes" and item["productionSupport"] != "production-supported":
            raise SystemExit(f"unqualified decentralized-custody claim for {item['id']}")
        if not item.get("reason"):
            raise SystemExit(f"missing reason for {item['id']}")
        for ref in item["evidence"]:
            if ref.startswith(("http://", "https://")):
                continue
            if not (ROOT / ref).exists():
                raise SystemExit(f"missing evidence for {item['id']}: {ref}")

    capability_by_id = {item["id"]: item for item in capability["capabilities"]}
    expected = {
        "frost": ("yes", "yes", "unsupported"),
        "musig2": ("partial", "no", "unsupported"),
        "fedimint-nexus": ("partial", "no", "unsupported"),
        "android-strongbox": ("partial", "no", "unsupported"),
        "aws-nitro": ("partial", "no", "unsupported"),
    }
    for capability_id, statuses in expected.items():
        item = capability_by_id[capability_id]
        actual = (item["implementation"], item["integration"], item["productionSupport"])
        if actual != statuses:
            raise SystemExit(f"capability drift for {capability_id}: {actual} != {statuses}")

    print(f"decentralized signing inventory valid: {len(systems)} systems; 0 production-qualified")


if __name__ == "__main__":
    main()
