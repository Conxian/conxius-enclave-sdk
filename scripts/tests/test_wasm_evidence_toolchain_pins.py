#!/usr/bin/env python3

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_SCRIPT = REPO_ROOT / "scripts" / "wasm_runtime_evidence.sh"
TOOLCHAIN_FILE = REPO_ROOT / "rust-toolchain.toml"


def _toolchain_channel() -> str:
    text = TOOLCHAIN_FILE.read_text(encoding="utf-8")
    match = re.search(r'^\s*channel\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise AssertionError(f"no channel in {TOOLCHAIN_FILE}")
    return match.group(1)


def _script_default(env_var: str) -> str:
    text = EVIDENCE_SCRIPT.read_text(encoding="utf-8")
    pattern = re.compile(
        r'%s="\$\{%s:-([^}]+)\}"' % (re.escape(env_var.replace("WASM_EXPECTED", "EXPECTED")), re.escape(env_var))
    )
    match = pattern.search(text)
    if not match:
        raise AssertionError(f"{env_var} default not found in {EVIDENCE_SCRIPT}")
    return match.group(1)


class WasmEvidenceToolchainPinTests(unittest.TestCase):
    """The evidence script falls back to a hardcoded Rust version when the
    workflow does not export WASM_EXPECTED_RUST_VERSION. That fallback must
    track the repository's real pin, or a path that runs the script without the
    override fails under STRICT_TOOLCHAIN with a version it never shipped."""

    def test_rust_default_matches_the_toolchain_channel(self):
        self.assertEqual(_script_default("WASM_EXPECTED_RUST_VERSION"), _toolchain_channel())

    def test_rust_default_is_not_the_previous_pin(self):
        self.assertNotEqual(_script_default("WASM_EXPECTED_RUST_VERSION"), "1.99.1")


if __name__ == "__main__":
    unittest.main()
