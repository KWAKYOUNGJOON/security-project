"""File-based HexStrike intake validation for pre-target mode."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from src.cases.provenance import build_file_provenance_ledger
from src.intake.hexstrike_intake import HexStrikeIntakeRun, load_hexstrike_intake_run, resolve_intake_directory
from src.parsers import build_hexstrike_format_observation
from src.validators import validate_schema_file


def validate_live_hexstrike_run(run_arg: str | Path, repo_root: Path, schema_dir: Path) -> dict[str, Any]:
    """Validate one file-based intake run and write observation artifacts."""

    run_dir = resolve_intake_directory(run_arg, repo_root)
    intake_run = load_hexstrike_intake_run(run_dir, repo_root)
    observation = build_hexstrike_format_observation(intake_run)
    validate_schema_file(observation, schema_dir / "format-observation.schema.json")

    observation_path = run_dir / "derived" / "format-observation.json"
    _write_json(observation_path, observation)

    provenance = _build_intake_provenance_ledger(intake_run, repo_root=repo_root, output_paths=[observation_path])
    validate_schema_file(provenance, schema_dir / "provenance.schema.json")
    provenance_path = run_dir / "derived" / "provenance.json"
    _write_json(provenance_path, provenance)

    return {
        "format_observation_path": str(observation_path),
        "provenance_path": str(provenance_path),
        "finding_count_detected": int(observation["finding_count_detected"]),
        "warning_count": len(observation["parser_warnings"]),
    }


def _build_intake_provenance_ledger(
    intake_run: HexStrikeIntakeRun,
    *,
    repo_root: Path,
    output_paths: list[Path],
) -> dict[str, Any]:
    input_files = [
        ("manifest", intake_run.manifest_path, None),
        ("notes", intake_run.notes_path, None),
    ]
    input_files.extend(("runtime-baseline", path, None) for path in intake_run.baseline_files)
    input_files.extend(("intake-raw", raw_payload.file_path, None) for raw_payload in intake_run.raw_payloads)
    return build_file_provenance_ledger(
        record_id=intake_run.run_id,
        repo_root=repo_root.resolve(),
        input_files=input_files,
        output_paths=output_paths,
        subject_type="intake-run",
    )


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
