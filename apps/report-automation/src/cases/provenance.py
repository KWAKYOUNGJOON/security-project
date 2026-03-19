"""Helpers for file hashing and provenance ledger generation."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.cases.case_loader import CaseInputs


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest for a local file."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_provenance_ledger(case_inputs: CaseInputs, output_paths: list[Path]) -> dict[str, Any]:
    """Build a case-level provenance ledger for inputs and generated outputs."""

    return {
        "case_id": case_inputs.case_dir.name,
        "generated_at": _generated_at(),
        "inputs": _input_records(case_inputs),
        "outputs": _output_records(case_inputs, output_paths),
    }


def _generated_at() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _input_records(case_inputs: CaseInputs) -> list[dict[str, str]]:
    records: list[dict[str, str]] = [
        _file_record(case_inputs, role="engagement", path=case_inputs.engagement_file),
    ]
    if case_inputs.document_control_file is not None:
        records.append(_file_record(case_inputs, role="document-control", path=case_inputs.document_control_file))
    if case_inputs.tool_inventory_file is not None:
        records.append(_file_record(case_inputs, role="tool-inventory", path=case_inputs.tool_inventory_file))
    for role, path in case_inputs.review.input_files:
        records.append(_file_record(case_inputs, role=role, path=path))

    for finding in case_inputs.findings:
        if finding.target_file is not None:
            records.append(_file_record(case_inputs, role="target", path=finding.target_file, finding_key=finding.finding_key))
        records.append(
            _file_record(case_inputs, role="manual-finding", path=finding.manual_finding_file, finding_key=finding.finding_key)
        )
        records.append(_file_record(case_inputs, role="raw", path=finding.raw_scan_file, finding_key=finding.finding_key))
        records.append(_file_record(case_inputs, role="http", path=finding.request_file, finding_key=finding.finding_key))
        records.append(_file_record(case_inputs, role="http", path=finding.response_file, finding_key=finding.finding_key))
        for screenshot_file in finding.screenshot_files:
            records.append(_file_record(case_inputs, role="evidence", path=screenshot_file, finding_key=finding.finding_key))

    return sorted(records, key=lambda item: (item["role"], item.get("finding_key", ""), item["path"]))


def _output_records(case_inputs: CaseInputs, output_paths: list[Path]) -> list[dict[str, str]]:
    records = [
        {
            "path": case_inputs.repo_relative(path),
            "sha256": sha256_file(path),
        }
        for path in sorted({item.resolve() for item in output_paths if item.exists()})
    ]
    return records


def _file_record(
    case_inputs: CaseInputs,
    *,
    role: str,
    path: Path,
    finding_key: str | None = None,
) -> dict[str, str]:
    record = {
        "role": role,
        "path": case_inputs.repo_relative(path),
        "sha256": sha256_file(path),
    }
    if finding_key:
        record["finding_key"] = finding_key
    return record
