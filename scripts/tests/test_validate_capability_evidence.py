#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import validate_capability_evidence as validator  # noqa: E402


class CapabilityEvidenceValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        data_path = REPO_ROOT / validator.DATA_RELATIVE_PATH
        with data_path.open(encoding="utf-8") as handle:
            cls.document = json.load(handle)

    def valid_document(self) -> dict:
        return copy.deepcopy(self.document)

    def errors_for(self, document: dict) -> list[str]:
        return validator.validate_document(document, REPO_ROOT)

    def find(self, document: dict, capability_id: str) -> dict:
        return next(
            capability
            for capability in document["capabilities"]
            if capability["id"] == capability_id
        )

    def test_duplicate_ids_are_rejected(self) -> None:
        document = self.valid_document()
        document["capabilities"].append(copy.deepcopy(document["capabilities"][0]))
        errors = self.errors_for(document)
        self.assertTrue(any("duplicate capability id" in error for error in errors))

    def test_invalid_enum_is_rejected(self) -> None:
        document = self.valid_document()
        document["capabilities"][0]["api"] = "maybe"
        errors = self.errors_for(document)
        self.assertTrue(any("invalid enum value" in error for error in errors))

    def test_missing_repository_path_is_rejected(self) -> None:
        document = self.valid_document()
        document["capabilities"][0]["evidenceRefs"][0] = "src/missing.rs:1-2"
        errors = self.errors_for(document)
        self.assertTrue(any("missing repository path" in error for error in errors))

    def test_required_wasm_row_is_rejected_when_absent(self) -> None:
        document = self.valid_document()
        document["capabilities"] = [
            capability
            for capability in document["capabilities"]
            if capability["id"] != "wasm-a2p"
        ]
        errors = self.errors_for(document)
        self.assertTrue(any("missing required WASM capability id" in error for error in errors))

    def test_incomplete_row_requires_blocker_or_exclusion(self) -> None:
        document = self.valid_document()
        capability = self.find(document, "wasm-lightning")
        capability["blockers"] = []
        capability["exclusion"] = None
        errors = self.errors_for(document)
        self.assertTrue(any("requires a blocker URL or explicit exclusion" in error for error in errors))

    def test_production_claim_requires_prerequisite_evidence(self) -> None:
        document = self.valid_document()
        capability = self.find(document, "enclave-signing")
        for axis in ("api", "implementation", "integration", "independentReview"):
            capability[axis] = "yes"
        capability["productionSupport"] = "production-supported"
        capability["evidenceChain"][-1]["refs"] = []
        errors = self.errors_for(document)
        self.assertTrue(
            any("production-supported requires refs for every evidence stage" in error for error in errors)
        )

    def test_generated_matrix_drift_is_rejected(self) -> None:
        matrix_path = REPO_ROOT / validator.MATRIX_RELATIVE_PATH
        matrix_text = matrix_path.read_text(encoding="utf-8")
        matrix_text = matrix_text.replace(
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            "| drift | --- | --- | --- | --- | --- | --- | --- | --- |",
            1,
        )
        errors = validator.check_generated_matrix(self.document, matrix_text)
        self.assertTrue(any("matrix drift" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
