"""Helpers for file hashing and provenance ledger generation."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.cases.case_loader import CaseInputs

InputFileRef = tuple[str, Path, str | None]


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest for a local file."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_provenance_ledger(case_inputs: CaseInputs, output_paths: list[Path]) -> dict[str, Any]:
    """Build a case-level provenance ledger for inputs and generated outputs."""

    input_records = _input_refs(case_inputs)
    return build_file_provenance_ledger(
        record_id=case_inputs.case_dir.name,
        repo_root=case_inputs.repo_root,
        input_files=input_records,
        output_paths=output_paths,
    )


def build_file_provenance_ledger(
    *,
    record_id: str,
    repo_root: Path,
    input_files: list[InputFileRef],
    output_paths: list[Path],
    subject_type: str | None = None,
) -> dict[str, Any]:
    """Build a generic file-based provenance ledger."""

    ledger = {
        "case_id": record_id,
        "generated_at": _generated_at(),
        "inputs": _input_records(repo_root, input_files),
        "outputs": _output_records(repo_root, output_paths),
    }
    if subject_type:
        ledger["subject_type"] = subject_type
    return ledger


def _generated_at() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _input_refs(case_inputs: CaseInputs) -> list[InputFileRef]:
    records: list[InputFileRef] = [
        ("engagement", case_inputs.engagement_file, None),
    ]
    if case_inputs.document_control_file is not None:
        records.append(("document-control", case_inputs.document_control_file, None))
    if case_inputs.tool_inventory_file is not None:
        records.append(("tool-inventory", case_inputs.tool_inventory_file, None))
    for role, path in case_inputs.review.input_files:
        records.append((role, path, None))

    for finding in case_inputs.findings:
        if finding.target_file is not None:
            records.append(("target", finding.target_file, finding.finding_key))
        records.append(("manual-finding", finding.manual_finding_file, finding.finding_key))
        records.append(("raw", finding.raw_scan_file, finding.finding_key))
        records.append(("http", finding.request_file, finding.finding_key))
        records.append(("http", finding.response_file, finding.finding_key))
        for screenshot_file in finding.screenshot_files:
            records.append(("evidence", screenshot_file, finding.finding_key))

    return records


def _repo_relative(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError as exc:  # pragma: no cover - defensive boundary
        raise ValueError(f"Path is outside the repository root: {path}") from exc


def _input_records(repo_root: Path, input_files: list[InputFileRef]) -> list[dict[str, str]]:
    records = [
        _file_record(repo_root, role=role, path=path, finding_key=finding_key)
        for role, path, finding_key in input_files
    ]
    return sorted(records, key=lambda item: (item["role"], item.get("finding_key", ""), item["path"]))


def _output_records(repo_root: Path, output_paths: list[Path]) -> list[dict[str, str]]:
    records = [
        {
            "path": _repo_relative(repo_root, path),
            "sha256": sha256_file(path),
        }
        for path in sorted({item.resolve() for item in output_paths if item.exists()})
    ]
    return records


def _file_record(
    repo_root: Path,
    *,
    role: str,
    path: Path,
    finding_key: str | None = None,
) -> dict[str, str]:
    record = {
        "role": role,
        "path": _repo_relative(repo_root, path),
        "sha256": sha256_file(path),
    }
    if finding_key:
        record["finding_key"] = finding_key
    return record
