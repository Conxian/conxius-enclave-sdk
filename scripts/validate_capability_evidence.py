#!/usr/bin/env python3
"""Validate and render the repository's machine-readable capability evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
EXPECTED_REPOSITORY = "Conxian/conxius-enclave-sdk"
EXPECTED_MATURITY = "beta-conditional"
EXPECTED_AXIS_ORDER = [
    "api",
    "implementation",
    "integration",
    "independentReview",
    "productionSupport",
]
EXPECTED_STAGE_ORDER = ["requirement", "code", "test", "ci", "artifact"]
EVIDENCE_STATUSES = {"yes", "partial", "no", "not-evidenced"}
PRODUCTION_SUPPORT_STATUSES = {"unsupported", "conditional", "production-supported"}
REQUIRED_WASM_IDS = [
    "wasm-lightning",
    "wasm-settlement-service",
    "wasm-solver",
    "wasm-swap-router",
    "wasm-zkml",
    "wasm-dlc",
    "wasm-stablecoin",
    "wasm-job-card-iso20022",
    "wasm-mmr",
    "wasm-opportunity",
    "wasm-business",
    "wasm-a2p",
]

MATRIX_START = "<!-- capability-evidence:generated:start -->"
MATRIX_END = "<!-- capability-evidence:generated:end -->"
MATRIX_RELATIVE_PATH = Path("docs/architecture/CAPABILITY_MATRIX.md")
DATA_RELATIVE_PATH = Path("docs/architecture/capability-evidence.json")

_LINE_SUFFIX_RE = re.compile(r"^(.*?)(?::\d+(?:-\d+)?|#L\d+(?:-L?\d+)?)?$")
_CAPABILITY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]+$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_GITHUB_BLOCKER_RE = re.compile(
    r"^https://github\.com/Conxian/conxius-enclave-sdk/issues/[1-9][0-9]*$"
)


def _is_url(value: str) -> bool:
    return value.startswith(("https://", "http://"))


def _repo_path_from_ref(ref: str) -> str | None:
    if _is_url(ref):
        return None
    match = _LINE_SUFFIX_RE.match(ref)
    if not match:
        return ref
    return match.group(1)


def _validate_ref(ref: Any, root: Path, location: str, errors: list[str]) -> None:
    if not isinstance(ref, str) or not ref.strip():
        errors.append(f"{location} must contain a non-empty string")
        return
    if _is_url(ref):
        return
    repo_path = _repo_path_from_ref(ref)
    if repo_path is None or not repo_path or repo_path.startswith("/"):
        errors.append(f"{location} has an invalid repository path: {ref!r}")
        return
    candidate = (root / repo_path).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        errors.append(f"{location} escapes the repository: {ref!r}")
        return
    if not candidate.exists():
        errors.append(f"{location} references a missing repository path: {ref!r}")


def _validate_ref_list(
    refs: Any, root: Path, location: str, errors: list[str]
) -> None:
    if not isinstance(refs, list):
        errors.append(f"{location} must be a list")
        return
    for index, ref in enumerate(refs):
        _validate_ref(ref, root, f"{location}[{index}]", errors)


def validate_document(document: Any, root: Path) -> list[str]:
    """Return deterministic validation errors for a decoded evidence document."""

    errors: list[str] = []
    if not isinstance(document, dict):
        return ["document must be a JSON object"]

    required_top_level = {
        "$schema",
        "schemaVersion",
        "repository",
        "reviewedRef",
        "lastVerified",
        "maturity",
        "statusVocabulary",
        "axisOrder",
        "evidenceStageOrder",
        "requiredWasmIds",
        "capabilities",
    }
    missing = sorted(required_top_level - document.keys())
    errors.extend(f"missing top-level field: {field}" for field in missing)

    if document.get("schemaVersion") != SCHEMA_VERSION:
        errors.append(
            f"schemaVersion must be {SCHEMA_VERSION}, got {document.get('schemaVersion')!r}"
        )
    if document.get("repository") != EXPECTED_REPOSITORY:
        errors.append(
            f"repository must be {EXPECTED_REPOSITORY!r}, got {document.get('repository')!r}"
        )
    if not isinstance(document.get("reviewedRef"), str) or not _SHA_RE.fullmatch(
        document.get("reviewedRef", "")
    ):
        errors.append("reviewedRef must be a full 40-character lowercase Git SHA")
    if not isinstance(document.get("lastVerified"), str) or not _DATE_RE.fullmatch(
        document.get("lastVerified", "")
    ):
        errors.append("lastVerified must be an ISO date")
    if document.get("maturity") != EXPECTED_MATURITY:
        errors.append(
            f"maturity must be {EXPECTED_MATURITY!r}, got {document.get('maturity')!r}"
        )

    vocabulary = document.get("statusVocabulary")
    expected_vocabulary = {
        "evidence": ["yes", "partial", "no", "not-evidenced"],
        "productionSupport": [
            "unsupported",
            "conditional",
            "production-supported",
        ],
    }
    if vocabulary != expected_vocabulary:
        errors.append("statusVocabulary does not match the controlled vocabulary")
    if document.get("axisOrder") != EXPECTED_AXIS_ORDER:
        errors.append("axisOrder must list the five evidence axes in canonical order")
    if document.get("evidenceStageOrder") != EXPECTED_STAGE_ORDER:
        errors.append(
            "evidenceStageOrder must be requirement, code, test, ci, artifact"
        )
    if document.get("requiredWasmIds") != REQUIRED_WASM_IDS:
        errors.append("requiredWasmIds does not match the required explicit WASM inventory")

    capabilities = document.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        errors.append("capabilities must be a non-empty list")
        return errors

    seen_ids: set[str] = set()
    for index, capability in enumerate(capabilities):
        location = f"capabilities[{index}]"
        if not isinstance(capability, dict):
            errors.append(f"{location} must be an object")
            continue

        capability_id = capability.get("id")
        if not isinstance(capability_id, str) or not _CAPABILITY_ID_RE.fullmatch(
            capability_id
        ):
            errors.append(f"{location}.id must be a lowercase kebab-case identifier")
        elif capability_id in seen_ids:
            errors.append(f"duplicate capability id: {capability_id}")
        else:
            seen_ids.add(capability_id)

        required_fields = {
            "id",
            "name",
            "family",
            "api",
            "implementation",
            "integration",
            "independentReview",
            "productionSupport",
            "evidenceRefs",
            "evidenceChain",
            "blockers",
            "exclusion",
            "notes",
        }
        missing_fields = sorted(required_fields - capability.keys())
        errors.extend(
            f"{location} missing field: {field}" for field in missing_fields
        )

        for axis in EXPECTED_AXIS_ORDER:
            value = capability.get(axis)
            allowed = (
                PRODUCTION_SUPPORT_STATUSES
                if axis == "productionSupport"
                else EVIDENCE_STATUSES
            )
            if value not in allowed:
                errors.append(f"{location}.{axis} has invalid enum value: {value!r}")

        _validate_ref_list(
            capability.get("evidenceRefs"), root, f"{location}.evidenceRefs", errors
        )

        evidence_chain = capability.get("evidenceChain")
        if not isinstance(evidence_chain, list):
            errors.append(f"{location}.evidenceChain must be a list")
        else:
            if [
                item.get("stage")
                for item in evidence_chain
                if isinstance(item, dict)
            ] != EXPECTED_STAGE_ORDER:
                errors.append(
                    f"{location}.evidenceChain must use the canonical evidence ordering"
                )
            if len(evidence_chain) != len(EXPECTED_STAGE_ORDER):
                errors.append(
                    f"{location}.evidenceChain must contain exactly five stages"
                )
            for stage_index, stage in enumerate(evidence_chain):
                stage_location = f"{location}.evidenceChain[{stage_index}]"
                if not isinstance(stage, dict):
                    errors.append(f"{stage_location} must be an object")
                    continue
                if set(stage) != {"stage", "refs"}:
                    errors.append(
                        f"{stage_location} must contain only stage and refs fields"
                    )
                _validate_ref_list(
                    stage.get("refs"), root, f"{stage_location}.refs", errors
                )

        blockers = capability.get("blockers")
        if not isinstance(blockers, list):
            errors.append(f"{location}.blockers must be a list")
            blockers = []
        for blocker_index, blocker in enumerate(blockers):
            if not isinstance(blocker, str) or not _GITHUB_BLOCKER_RE.fullmatch(
                blocker
            ):
                errors.append(
                    f"{location}.blockers[{blocker_index}] must be a canonical GitHub issue URL"
                )

        exclusion = capability.get("exclusion")
        if exclusion is not None and (
            not isinstance(exclusion, str) or not exclusion.strip()
        ):
            errors.append(f"{location}.exclusion must be null or a non-empty string")

        support = capability.get("productionSupport")
        has_gap = any(
            capability.get(axis) != "yes"
            for axis in ("api", "implementation", "integration", "independentReview")
        )
        if (support != "production-supported" or has_gap) and not blockers and not exclusion:
            errors.append(
                f"{location} requires a blocker URL or explicit exclusion while evidence is incomplete"
            )

        if support == "production-supported":
            if has_gap:
                errors.append(
                    f"{location} cannot be production-supported without yes on all prerequisite axes"
                )
            if isinstance(evidence_chain, list):
                for stage in evidence_chain:
                    if isinstance(stage, dict) and not stage.get("refs"):
                        errors.append(
                            f"{location} production-supported requires refs for every evidence stage"
                        )

    missing_wasm = sorted(set(REQUIRED_WASM_IDS) - seen_ids)
    errors.extend(f"missing required WASM capability id: {wasm_id}" for wasm_id in missing_wasm)
    return errors


def _status_label(value: str) -> str:
    labels = {
        "yes": "Yes",
        "partial": "Partial",
        "no": "No",
        "not-evidenced": "Not evidenced",
        "unsupported": "No",
        "conditional": "Conditional",
        "production-supported": "Yes",
    }
    return labels[value]


def _markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def _blocker_cell(capability: dict[str, Any]) -> str:
    blockers = capability.get("blockers", [])
    if blockers:
        rendered = []
        for blocker in blockers:
            number = blocker.rsplit("/", 1)[-1]
            rendered.append(f"[#{number}]({blocker})")
        return ", ".join(rendered)
    exclusion = capability.get("exclusion")
    return exclusion if exclusion else "—"


def render_generated_section(document: dict[str, Any]) -> str:
    rows = [
        MATRIX_START,
        "## Generated capability evidence",
        "",
        "| ID | Capability | Family | API | Implementation | Integration | Independent review | Production support | Blocker / exclusion |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    capabilities = sorted(
        document["capabilities"],
        key=lambda item: (item["family"], item["name"], item["id"]),
    )
    for capability in capabilities:
        rows.append(
            "| "
            + " | ".join(
                [
                    _markdown_cell(capability["id"]),
                    _markdown_cell(capability["name"]),
                    _markdown_cell(capability["family"]),
                    _status_label(capability["api"]),
                    _status_label(capability["implementation"]),
                    _status_label(capability["integration"]),
                    _status_label(capability["independentReview"]),
                    _status_label(capability["productionSupport"]),
                    _markdown_cell(_blocker_cell(capability)),
                ]
            )
            + " |"
        )
    rows.extend(["", MATRIX_END])
    return "\n".join(rows)


def check_generated_matrix(document: dict[str, Any], matrix_text: str) -> list[str]:
    expected = render_generated_section(document)
    marker_pattern = re.compile(
        re.escape(MATRIX_START) + r".*?" + re.escape(MATRIX_END), re.DOTALL
    )
    matches = marker_pattern.findall(matrix_text)
    if len(matches) != 1:
        return [
            "CAPABILITY_MATRIX.md must contain exactly one generated capability section"
        ]
    if matches[0] != expected:
        return [
            "generated capability matrix drift detected; run "
            "python3 scripts/validate_capability_evidence.py --write"
        ]
    return []


def write_generated_matrix(document: dict[str, Any], matrix_path: Path) -> None:
    matrix_text = matrix_path.read_text(encoding="utf-8")
    rendered = render_generated_section(document)
    marker_pattern = re.compile(
        re.escape(MATRIX_START) + r".*?" + re.escape(MATRIX_END), re.DOTALL
    )
    updated, count = marker_pattern.subn(rendered, matrix_text, count=1)
    if count != 1:
        raise ValueError(
            "CAPABILITY_MATRIX.md must contain exactly one generated capability section"
        )
    matrix_path.write_text(updated, encoding="utf-8")


def _load_document(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise ValueError("evidence JSON root must be an object")
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to this script's repository)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="validate JSON and check generated Markdown (default)",
    )
    mode.add_argument(
        "--write",
        action="store_true",
        help="validate JSON and update only the generated Markdown section",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    data_path = root / DATA_RELATIVE_PATH
    matrix_path = root / MATRIX_RELATIVE_PATH
    try:
        document = _load_document(data_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: unable to load {data_path}: {error}", file=sys.stderr)
        return 1

    errors = validate_document(document, root)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1

    if args.write:
        try:
            write_generated_matrix(document, matrix_path)
        except (OSError, ValueError) as error:
            print(f"error: unable to write {matrix_path}: {error}", file=sys.stderr)
            return 1
        print(f"wrote generated capability matrix: {matrix_path}")
        return 0

    try:
        matrix_text = matrix_path.read_text(encoding="utf-8")
    except OSError as error:
        print(f"error: unable to read {matrix_path}: {error}", file=sys.stderr)
        return 1
    errors = check_generated_matrix(document, matrix_text)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(
        f"capability evidence valid: {len(document['capabilities'])} capabilities; "
        "generated matrix is current"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
